// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/jay94ks/seafield/internal/engineimage"
	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// fill sets an envelope id whatever its wire type is.
func fill(p any) {
	switch v := p.(type) {
	case *[16]byte:
		v[0] = 1
	case *[8]byte:
		v[0] = 1
	case *string:
		*v = "1"
	}
}

func TestEngineImageAnswersATicketedBlobFromAnOffset(t *testing.T) {
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := img.RawManifest()
	md, _ := img.Digest()
	mt, _ := img.MediaType()
	cfg, _ := img.RawConfigFile()
	cd, _ := img.ConfigName()
	layers, _ := img.Layers()
	lr, _ := layers[0].Compressed()
	layer, _ := io.ReadAll(lr)
	ld, _ := layers[0].Digest()
	blobs := map[string][]byte{cd.String(): cfg, ld.String(): layer}
	open := func(ctx context.Context, q registryclient.GraphContentQuery, offset int64) (registryclient.ContentInfo, io.ReadCloser, error) {
		info, body, err := registryclient.SelectGraphContent(q, func(digest string) (string, []byte, error) {
			if digest != md.String() {
				return "", nil, &registryclient.Error{Code: "NOT_FOUND"}
			}
			return string(mt), raw, nil
		})
		if err != nil {
			return info, nil, err
		}
		if q.Kind != "manifest" {
			body = blobs[info.Digest]
		}
		return info, io.NopCloser(bytes.NewReader(body[offset:])), nil
	}
	r := &Runtime{engineImages: engineimage.New()}
	table, err := r.newEngineOps()
	if err != nil {
		t.Fatal(err)
	}
	release, err := r.engineImages.Issue(context.Background(), "registry.example/team/app@"+md.String(), open)
	if err != nil {
		t.Fatal(err)
	}
	ask := func(op, repo, digest string, offset uint64) (engineImageReply, []byte) {
		q := engineImageRequest{Repository: repo, Digest: digest, Offset: offset}
		q.Schema, q.Op = 1, op
		fill(&q.OpID)
		fill(&q.BootID)
		body, _ := json.Marshal(q)
		a := table.Serve(context.Background(), engineops.Image, body)
		var reply engineImageReply
		if err := json.Unmarshal(a.Body, &reply); err != nil {
			t.Fatal(err)
		}
		var got []byte
		if a.Stream != nil {
			got, _ = io.ReadAll(a.Stream)
			_ = a.Stream.Close()
		}
		return reply, got
	}
	reply, got := ask("blob", "registry.example/team/app", ld.String(), 10)
	if reply.Result != engineops.Applied || reply.Size != int64(len(layer)) || !bytes.Equal(got, layer[10:]) {
		t.Fatalf("blob = %+v, %d bytes", reply, len(got))
	}
	if reply, got = ask("manifest", "registry.example/team/app", md.String(), 0); reply.Result != engineops.Applied || !bytes.Equal(got, raw) || reply.ContentType != string(mt) {
		t.Fatalf("manifest = %+v", reply)
	}
	for _, c := range []struct{ op, repo, digest, reason string }{
		{"blob", "registry.example/other", ld.String(), engineops.Refused},
		{"manifest", "registry.example/team/app", ld.String(), engineops.NotFound},
		{"blob", "registry.example/team/app", "sha256:" + string(bytes.Repeat([]byte("0"), 64)), engineops.NotFound},
	} {
		if reply, got := ask(c.op, c.repo, c.digest, 0); reply.Result != engineops.NotApplied || reply.Reason != c.reason || got != nil {
			t.Fatalf("%+v = %+v", c, reply)
		}
	}
	if reply, _ := ask("blob", "registry.example/team/app", ld.String(), uint64(len(layer))+1); reply.Reason != engineops.Invalid {
		t.Fatalf("past end = %+v", reply)
	}
	release()
	if reply, _ := ask("blob", "registry.example/team/app", ld.String(), 0); reply.Reason != engineops.Refused {
		t.Fatalf("after release = %+v", reply)
	}
}
