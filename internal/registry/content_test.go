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

	"github.com/jay94ks/mydcd/internal/registryclient"
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
