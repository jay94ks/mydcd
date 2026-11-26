// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFileProfilePreservesReadsAndRejectsProviderWrites(t *testing.T) {
	f := writable(t)
	old, _ := f.t.WriteProfile("vault")
	raw, _ := json.Marshal(old)
	if bytes.Contains(raw, []byte("Mode")) {
		t.Fatal("legacy original receipt encoding changed")
	}
	request := valueRequest(f, "file-write", "runtime")
	p := old
	p.Mode, p.Revision = "local-file", 0
	n, err := f.t.SetWriteProfile(f.c, "admin", f.t.Revision(), p)
	f.t = mustTree(t, n, err)
	if _, err := f.t.PlanWrite(f.c, "admin", "new-file-write", "runtime", "vault", ValueWrite, nil); err == nil {
		t.Fatal("read-only file source planned a provider write")
	}
	if _, err := f.t.PrepareWrite(f.c, "admin", f.t.Revision(), request); err == nil {
		t.Fatal("direct provider dispatch bypassed read-only file profile")
	}
	for _, mode := range []string{"invalid", "local-file"} {
		bad := p
		bad.ID, bad.Mode, bad.Verifiers = "bad", mode, true
		if _, err := f.t.SetWriteProfile(f.c, "admin", f.t.Revision(), bad); err == nil {
			t.Fatal("invalid/verifier file profile accepted")
		}
	}
	encoded, err := f.t.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeTree(encoded)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := restored.WriteProfile("vault")
	if !ok || profile.Mode != "local-file" || !profile.Values || profile.Verifiers {
		t.Fatal("file read authority lost across checkpoint")
	}
}

func TestRealInstalledSecretFilesFixedVersionAndRefusals(t *testing.T) {
	root := filepath.Join(t.TempDir(), "installed")
	ref := Reference{Profile: "files", Object: "tenant/data", Revision: 1, Keys: []string{"PASSWORD"}}
	install := func(version, value string, revision int) string {
		t.Helper()
		dir := filepath.Join(root, "tenant/data", version)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		manifest, _ := json.Marshal(map[string]any{"schema": 1, "profile": "files", "object": "tenant/data", "revision": revision, "keys": ref.Keys})
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "key-PASSWORD"), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	dir := install("1", "private-original", 1)
	install("2", "private-successor", 2)
	p, err := OpenFiles("files", root, "tenant", 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	check := func(ctx context.Context, ref Reference, want bool) {
		t.Helper()
		value, err := p.Fetch(ctx, "data", ref)
		defer func() {
			for _, b := range value.Values {
				clear(b)
			}
		}()
		if want {
			if err != nil || string(value.Values["PASSWORD"]) != "private-original" || value.Reference.Revision != 1 {
				t.Fatal("original version read", err)
			}
		} else if err == nil || len(value.Values) != 0 {
			t.Fatal("invalid installed source accepted")
		}
	}
	ctx := context.Background()
	check(ctx, ref, true)
	for _, bad := range []Reference{{Profile: "other", Object: ref.Object, Revision: 1, Keys: ref.Keys}, {Profile: ref.Profile, Object: "../tenant/data", Revision: 1, Keys: ref.Keys}, {Profile: ref.Profile, Object: "other/data", Revision: 1, Keys: ref.Keys}, {Profile: ref.Profile, Object: ref.Object, Revision: 3, Keys: ref.Keys}, {Profile: ref.Profile, Object: ref.Object, Revision: 1, Keys: []string{"OTHER"}}} {
		check(ctx, bad, false)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	check(cancelled, ref, false)
	key := filepath.Join(dir, "key-PASSWORD")
	if err := os.Rename(key, key+"-held"); err != nil {
		t.Fatal(err)
	}
	check(ctx, ref, false) // No fallback to the installed successor.
	if err := os.Symlink("key-PASSWORD-held", key); err != nil {
		t.Fatal(err)
	}
	check(ctx, ref, false)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(key+"-held", key); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0644); err != nil {
		t.Fatal(err)
	}
	check(ctx, ref, false)
	if err := os.Chmod(key, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	check(ctx, ref, false)
	if err := os.Remove(filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra"), []byte("extra"), 0600); err != nil {
		t.Fatal(err)
	}
	check(ctx, ref, false)
	if err := os.Remove(filepath.Join(dir, "extra")); err != nil {
		t.Fatal(err)
	}
	install("1", "private-original", 2)
	check(ctx, ref, false)
	install("1", "private-original", 1)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(key, 0600); err != nil {
		t.Fatal(err)
	}
	check(ctx, ref, false)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	install("1", "private-original", 1)
	small, err := OpenFiles("files", root, "tenant", 1)
	if err != nil {
		t.Fatal(err)
	}
	v, err := small.Fetch(ctx, "data", ref)
	small.Close()
	if err == nil || len(v.Values) != 0 {
		t.Fatal("byte limit not enforced")
	}
	if err := os.Rename(dir, dir+"-held"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("1-held", dir); err != nil {
		t.Fatal(err)
	}
	check(ctx, ref, false)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir+"-held", dir); err != nil {
		t.Fatal(err)
	}
	check(ctx, ref, true)
	if _, err := json.Marshal(p); !errors.Is(err, ErrPrivateMaterial) {
		t.Fatal("provider not redacted")
	}
	t.Log("actual private files: exact original version after successor; no latest/fallback; wrong profile/prefix/keys/version, cancellation, symlink directory/file, hardlink, public mode, FIFO, extra/missing keys, rebound manifest and byte overflow denied")
}
