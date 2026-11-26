// SPDX-License-Identifier: Apache-2.0

package nodeapp

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

func TestEveryNodeAppImageHasAControlPolicy(t *testing.T) {
	for _, i := range Images() {
		if i.Name == "" || i.Control == 0 {
			t.Fatalf("node app image without a control policy: %+v", i)
		}
	}
	if w, ok := Lookup(Web); !ok || w.Control != NodeConfigOnly {
		t.Fatal("web must be node.yaml-only", w)
	}
	if _, ok := Lookup("other"); ok {
		t.Fatal("unknown node app found")
	}
}

func TestOpenReturnsOnlyThePinnedImageFromItsBundle(t *testing.T) {
	dir := t.TempDir()
	web, _ := Lookup(Web)
	if _, err := Open(dir, web); !errors.Is(err, ErrImageNotFound) {
		t.Fatal("unpinned build opened an image", err)
	}
	pinned, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	other, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	p, err := layout.Write(filepath.Join(dir, web.Layout), empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.AppendImage(other); err != nil {
		t.Fatal(err)
	}
	h, _ := pinned.Digest()
	old := webDigest
	webDigest = h.String()
	t.Cleanup(func() { webDigest = old })
	web, _ = Lookup(Web)
	if _, err := Open(t.TempDir(), web); !errors.Is(err, ErrImageNotFound) || err.Error() != "node app image not found" {
		t.Fatal("node without the image package", err)
	}
	if _, err := Open(dir, web); !errors.Is(err, ErrImageNotFound) {
		t.Fatal("bundle without the pinned image accepted", err)
	}
	if err = p.AppendImage(pinned); err != nil {
		t.Fatal(err)
	}
	got, err := Open(dir, web)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := got.Digest(); d != h {
		t.Fatal("wrong image", d)
	}
	if err = os.Remove(filepath.Join(dir, web.Layout, "blobs", h.Algorithm, h.Hex)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, web); !errors.Is(err, ErrImage) {
		t.Fatal("damaged bundle accepted", err)
	}
}
