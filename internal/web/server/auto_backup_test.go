// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/web/seal"
)

func TestAutoBackup(t *testing.T) {
	f, _ := newFakeFixture(t)
	f.srv.opt.DataDir = t.TempDir()
	var clock atomic.Int64
	clock.Store(time.Date(2026, 11, 22, 1, 0, 0, 0, time.Local).Unix())
	f.srv.now = func() time.Time { return time.Unix(clock.Load(), 0) }

	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/system/auto-backup", nil); code != 403 {
		t.Fatalf("non-admin: %d", code)
	}
	fakeLogin(t, f, "admin")
	key := make([]byte, seal.KeySize)
	key[0] = 9
	box, err := seal.Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	if code, out := f.do("GET", "/api/v1/system/auto-backup", nil); code != 200 || out["prefix"] != "mydc-web-backups/" || out["enabled"] != false || out["account"] != nil {
		t.Fatalf("default: %d %v", code, out)
	}
	put := func(tenant, volume string) (int, map[string]any) {
		return f.do("PUT", "/api/v1/system/auto-backup", map[string]any{"enabled": true, "at": "03:00", "keep": 2, "tenant": tenant, "volume": volume})
	}
	if code, _ := put("shop", "uploads"); code != 422 {
		t.Fatalf("shared volume: %d", code)
	}
	if code, _ := put("shop", "mysql-data"); code != 422 {
		t.Fatalf("app volume: %d", code)
	}
	if code, out := f.do("PUT", "/api/v1/system/auto-backup", map[string]any{"enabled": true, "at": "25:00", "keep": 2, "tenant": "payments", "volume": "ledger-data"}); code != 422 {
		t.Fatalf("bad at: %d %v", code, out)
	}
	code, out := put("payments", "ledger-data")
	if code != 200 || out["next"] == nil {
		t.Fatalf("put: %d %v", code, out)
	}

	if code, out := f.do("POST", "/api/v1/system/auto-backup/run", map[string]any{}); code != 503 || errCode(out) != "seal-unavailable" {
		t.Fatalf("run without seal: %d %v", code, out)
	}
	f.srv.opt.Seal = box

	// three runs a minute apart; keep 2 removes the first
	var last map[string]any
	for i := 0; i < 3; i++ {
		clock.Add(60)
		if code, out := f.do("POST", "/api/v1/system/auto-backup/run", map[string]any{}); code != 202 {
			t.Fatalf("run: %d %v", code, out)
		}
		for deadline := time.Now().Add(10 * time.Second); ; {
			_, last = f.do("GET", "/api/v1/system/auto-backup", nil)
			if last["running"] == false && last["last"] != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("run did not end: %v", last)
			}
			time.Sleep(20 * time.Millisecond)
		}
		if l := last["last"].(map[string]any); l["ok"] != true {
			t.Fatalf("run %d: %v", i, l)
		}
	}
	_, files := f.do("GET", "/api/v1/t/payments/volumes/ledger-data/files?prefix=mydc-web-backups/", nil)
	items := files["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["path"] != "mydc-web-backups/web-"+time.Unix(clock.Load()-60, 0).UTC().Format("2006-01-02T1504")+"Z.db.gz.sealed" {
		t.Fatalf("files: %v", items)
	}
	path := last["last"].(map[string]any)["path"].(string)
	// the copy in the volume is ciphertext, not the web DB or its gzip
	req, _ := http.NewRequest("GET", f.http.URL+"/api/v1/t/payments/volumes/ledger-data/file?path="+path, nil)
	resp, err := f.hc.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("download: %v %v", resp, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.HasPrefix(raw, []byte{0x1f, 0x8b}) || bytes.Contains(raw, []byte("u-alice")) {
		t.Fatal("the backup in the volume is readable")
	}
	if !bytes.HasPrefix(raw, []byte("mydc-web-seal\x00")) {
		t.Fatal("the backup has no seal header")
	}
	gz, err := box.OpenBlob("web-backup", raw)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	db, _ := io.ReadAll(zr)
	if !bytes.Contains(db, []byte("u-alice")) {
		t.Fatal("the opened backup is not the web DB")
	}
	// no 32-byte run of the DB or of its gzip shows through
	for _, plain := range [][]byte{db, gz} {
		for i := 0; i+32 <= len(plain); i += 32 {
			if chunk := plain[i : i+32]; bytes.Count(chunk, chunk[:1]) < 32 && bytes.Contains(raw, chunk) {
				t.Fatalf("plaintext at %d shows in the sealed file", i)
			}
		}
	}

	// another seal key cannot restore it
	other, _ := seal.Open(t.TempDir(), make([]byte, seal.KeySize))
	f.srv.opt.Seal = other
	if code, out := f.do("POST", "/api/v1/system/restore-from", map[string]any{"tenant": "payments", "volume": "ledger-data", "path": path}); code != 422 || errCode(out) != "seal-key" {
		t.Fatalf("other key: %d %v", code, out)
	}
	f.srv.opt.Seal = box

	// restore straight from the newest copy
	if code, _ := f.do("POST", "/api/v1/system/restore-from", map[string]any{"tenant": "payments", "volume": "ledger-data", "path": "../web.db"}); code != 422 {
		t.Fatalf("bad path: %d", code)
	}
	if code, out := f.do("POST", "/api/v1/system/restore-from", map[string]any{"tenant": "payments", "volume": "ledger-data", "path": path}); code != 202 || out["restorePending"] != true {
		t.Fatalf("restore-from: %d %v", code, out)
	}
	if _, err := os.Stat(filepath.Join(f.srv.opt.DataDir, RestoreFile)); err != nil {
		t.Fatal(err)
	}

	// a due slot without the automation account
	clock.Store(time.Date(2026, 11, 22, 3, 0, 5, 0, time.Local).Unix())
	f.srv.autoBackupTick()
	_, cur := f.do("GET", "/api/v1/system/auto-backup", nil)
	if l := cur["last"].(map[string]any); l["ok"] != false || l["error"] != "automation-account-missing" {
		t.Fatalf("tick: %v", cur)
	}
	_, n := f.do("GET", "/api/v1/notifications", nil)
	if raw, _ := json.Marshal(n); !strings.Contains(string(raw), "web-backup") {
		t.Fatalf("no notification: %v", n)
	}
	f.srv.autoBackupTick() // same slot: once
}
