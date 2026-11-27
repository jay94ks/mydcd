// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

func TestKeygenSignVerify(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "release.key")
	if err := keygen([]string{"-out", key}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(key); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("private key mode", err)
	}
	if err := keygen([]string{"-out", key}); err == nil {
		t.Fatal("keygen overwrote a key")
	}
	bundle := filepath.Join(dir, "images", "anything")
	p, err := layout.Write(bundle, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	img, _ := random.Image(128, 1)
	if err = p.AppendImage(img); err != nil {
		t.Fatal(err)
	}
	if err = sign([]string{"-key", key, "-app", "web", "-version", "0.9.1", "-bundle", bundle}); err != nil {
		t.Fatal(err)
	}
	if err = verify([]string{"-pub", filepath.Join(dir, "release.pub"), "-app", "web", "-bundle", bundle}); err != nil {
		t.Fatal(err)
	}
	seed, _ := os.ReadFile(key)
	t.Setenv("TEST_RELEASE_KEY", string(seed))
	if err = sign([]string{"-key-env", "TEST_RELEASE_KEY", "-app", "web", "-version", "0.9.2", "-bundle", bundle}); err != nil {
		t.Fatal("sign from the environment", err)
	}
	if err = verify([]string{"-builtin", "-app", "web", "-bundle", bundle}); err == nil {
		t.Fatal("a key sfcd does not build in verified")
	}
	if err = p.AppendImage(img); err != nil {
		t.Fatal(err)
	}
	if err = sign([]string{"-key", key, "-app", "web", "-version", "0.9.1", "-bundle", bundle}); err == nil {
		t.Fatal("signed a bundle with two manifests")
	}
}
