// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/web/seal"
)

func TestSealStatus(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	// no box configured
	if code, out := f.do("GET", "/api/v1/system/seal", nil); code != 200 || out["state"] != "no-key" || out["ready"] != false {
		t.Fatalf("no box: %d %v", code, out)
	}
	box, err := seal.Open(t.TempDir(), bytes.Repeat([]byte{1}, seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.opt.Seal = box
	if code, out := f.do("GET", "/api/v1/system/seal", nil); code != 200 || out["state"] != "ready" || out["ready"] != true {
		t.Fatalf("ready: %d %v", code, out)
	}
}

func TestSealBrokenReasonOnlyForAdmin(t *testing.T) {
	f, _ := newFakeFixture(t)
	// a file where the folder should be makes the box broken
	file := filepath.Join(t.TempDir(), "secrets")
	os.WriteFile(file, nil, 0o600)
	box, err := seal.Open(file, bytes.Repeat([]byte{1}, seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := box.Status(); st != seal.StateBroken {
		t.Fatalf("state %v", st)
	}
	f.srv.opt.Seal = box
	fakeLogin(t, f, "alice")
	_, out := f.do("GET", "/api/v1/system/seal", nil)
	if out["state"] != "broken" || strings.Contains(out["reason"].(string), file) {
		t.Fatalf("non-admin: %v", out)
	}
	f.do("POST", "/api/v1/auth/logout", nil)
	fakeLogin(t, f, "admin")
	_, out = f.do("GET", "/api/v1/system/seal", nil)
	if !strings.Contains(out["reason"].(string), file) {
		t.Fatalf("admin should see the OS error: %v", out)
	}
}
