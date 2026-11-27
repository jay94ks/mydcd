// SPDX-License-Identifier: Apache-2.0

package clusterapp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

func TestEveryClusterAppImageHasAControlPolicy(t *testing.T) {
	for _, i := range Images() {
		if i.Name == "" || i.Control == 0 {
			t.Fatalf("cluster app image without a control policy: %+v", i)
		}
	}
	if w, ok := Lookup(Web); !ok || w.Control != NodeConfigOnly {
		t.Fatal("web must be node.yaml-only", w)
	}
	if _, ok := Lookup("other"); ok {
		t.Fatal("unknown cluster app found")
	}
}

func TestOpenReturnsOnlyTheImageASignedReleaseNames(t *testing.T) {
	dir := t.TempDir()
	web, _ := Lookup(Web)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	trust := TrustKeys(pub)
	if _, err := Open(dir, web, trust); !errors.Is(err, ErrImageNotFound) || err.Error() != "cluster app image not found" {
		t.Fatal("node without the image package", err)
	}
	named, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	other, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, web.Layout)
	p, err := layout.Write(bundle, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.AppendImage(other); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, web, trust); !errors.Is(err, ErrRelease) {
		t.Fatal("bundle without a release manifest accepted", err)
	}
	h, _ := named.Digest()
	r := Release{Schema: 1, App: Web, Repository: web.Repository, Version: "0.9.1", Digest: h.String()}
	if err = SignRelease(bundle, r, otherKey); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, web, trust); !errors.Is(err, ErrRelease) {
		t.Fatal("manifest signed by an untrusted key accepted", err)
	}
	if _, err := Open(dir, web, Trust{}); !errors.Is(err, ErrRelease) {
		t.Fatal("empty trust accepted a manifest", err)
	}
	if err = SignRelease(bundle, r, key); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, web, trust); !errors.Is(err, ErrImage) {
		t.Fatal("bundle without the named image accepted", err)
	}
	if err = p.AppendImage(named); err != nil {
		t.Fatal(err)
	}
	got, err := Open(dir, web, trust)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := got.Image.Digest(); d != h || got.Release != r {
		t.Fatal("wrong image", d, got.Release)
	}
	// A second trusted key (e.g. one root added to KeyDir) also verifies.
	if _, err := Open(dir, web, TrustKeys(otherPub, pub)); err != nil {
		t.Fatal(err)
	}
	// Changing the manifest after signing breaks the signature.
	b, _ := os.ReadFile(filepath.Join(bundle, ReleaseFile))
	if err = os.WriteFile(filepath.Join(bundle, ReleaseFile), bytes.Replace(b, []byte("0.9.1"), []byte("0.9.2"), 1), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, web, trust); !errors.Is(err, ErrRelease) {
		t.Fatal("edited manifest accepted", err)
	}
	// A signed manifest for another image is refused.
	for _, bad := range []Release{
		{Schema: 1, App: "other", Repository: web.Repository, Version: "1", Digest: h.String()},
		{Schema: 1, App: Web, Repository: "evil/web", Version: "1", Digest: h.String()},
		{Schema: 2, App: Web, Repository: web.Repository, Version: "1", Digest: h.String()},
		{Schema: 1, App: Web, Repository: web.Repository, Digest: h.String()},
		{Schema: 1, App: Web, Repository: web.Repository, Version: "1", Digest: "sha512:" + h.Hex},
	} {
		if err = SignRelease(bundle, bad, key); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, web, trust); !errors.Is(err, ErrRelease) {
			t.Fatal("manifest for another image accepted", bad, err)
		}
	}
	if err = SignRelease(bundle, r, key); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(bundle, "blobs", h.Algorithm, h.Hex)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, web, trust); !errors.Is(err, ErrImage) {
		t.Fatal("damaged bundle accepted", err)
	}
}

func TestLoadTrustReadsKeyFiles(t *testing.T) {
	dir := t.TempDir()
	if tr, err := LoadTrust(filepath.Join(dir, "missing")); err != nil || len(tr.keys) != len(releaseKeys) {
		t.Fatal("missing key directory", err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := os.WriteFile(filepath.Join(dir, "lab.pub"), []byte(hex.EncodeToString(pub)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a key"), 0644); err != nil {
		t.Fatal(err)
	}
	tr, err := LoadTrust(dir)
	if err != nil || len(tr.keys) != len(releaseKeys)+1 || !tr.keys[len(tr.keys)-1].Equal(pub) {
		t.Fatal("key file not trusted", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.pub"), []byte("zz"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrust(dir); err == nil {
		t.Fatal("malformed key file ignored")
	}
}

func TestBuiltinTrustReadsNoDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := os.WriteFile("stray.pub", []byte(hex.EncodeToString(pub)), 0644); err != nil {
		t.Fatal(err)
	}
	if tr, err := BuiltinTrust(); err != nil || len(tr.keys) != len(releaseKeys) {
		t.Fatal("built-in trust read a key file", err)
	}
}

func TestBuiltInReleaseKeysParse(t *testing.T) {
	for _, k := range releaseKeys {
		if _, err := ParseKey([]byte(k)); err != nil {
			t.Fatal(k, err)
		}
	}
}
