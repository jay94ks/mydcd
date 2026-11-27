// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/registryclient"
)

func TestNativeContentUsesOriginalStoreAndReaderBlocksGCJoin(t *testing.T) {
	s, _, _, _, _, _, image, digest := nativeImageFixture(t)
	q := registryclient.ContentQuery{Ref: "registry.example/team/app@" + digest, Kind: "layer", Digest: image.Layers[0].Digest.String()}
	info, body, err := s.OpenContent(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(body)
	if err != nil || int64(len(raw)) != info.Bytes || fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != info.Digest {
		t.Fatal(info, err)
	}
	// The request's actual Close, not reading EOF, releases the native gate.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = s.GarbageCollect(ctx, GCRequest{Operation: "read-overlap", Authority: "registry.example"}, func(context.Context, []string) error { return nil })
	cancel()
	if err == nil {
		t.Fatal("GC crossed an unjoined original content reader")
	}
	if err = body.Close(); err != nil {
		t.Fatal(err)
	}
	if err = body.Close(); err != nil {
		t.Fatal(err)
	}
	q.Kind = "manifest"
	q.Digest = ""
	info, body, err = s.OpenContent(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = io.ReadAll(body)
	closeErr := body.Close()
	if err != nil || closeErr != nil || !info.Valid(q) || !bytes.Contains(raw, []byte(image.Layers[0].Digest.String())) {
		t.Fatal("actual retained manifest", info, err, closeErr)
	}
	q.Kind = "layer"
	q.Digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, body, err = s.OpenContent(context.Background(), q); err == nil || body != nil {
		t.Fatal("unwitnessed native blob opened", body, err)
	}
}

func TestNativeContentResumesFromOffset(t *testing.T) {
	s, _, _, _, _, _, image, digest := nativeImageFixture(t)
	root := "registry.example/team/app@" + digest
	for _, q := range []registryclient.GraphContentQuery{
		{Root: root, Kind: "layer", Digest: image.Layers[0].Digest.String()},
		{Root: root, Kind: "manifest"},
	} {
		info, body, err := s.OpenGraphContentAt(context.Background(), q, 0)
		if err != nil {
			t.Fatal(err)
		}
		whole, _ := io.ReadAll(body)
		body.Close()
		cut := int64(len(whole) / 3)
		info2, body, err := s.OpenGraphContentAt(context.Background(), q, cut)
		if err != nil {
			t.Fatal(err)
		}
		rest, _ := io.ReadAll(body)
		body.Close()
		joined := append(whole[:cut:cut], rest...)
		if info2 != info || info.Bytes != int64(len(whole)) || fmt.Sprintf("sha256:%x", sha256.Sum256(joined)) != info.Digest {
			t.Fatal("resumed read differs", q.Kind, info, info2)
		}
		_, body, err = s.OpenGraphContentAt(context.Background(), q, info.Bytes)
		if err != nil {
			t.Fatal("offset at the end", err)
		}
		if tail, _ := io.ReadAll(body); len(tail) != 0 {
			t.Fatal("read past the end")
		}
		body.Close()
		for _, bad := range []int64{-1, info.Bytes + 1} {
			if _, body, err = s.OpenGraphContentAt(context.Background(), q, bad); err == nil || body != nil {
				t.Fatal("offset outside the item accepted", bad)
			}
		}
	}
}
