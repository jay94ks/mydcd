// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/seal"
)

func TestAutomationAccount(t *testing.T) {
	f, fake := newFakeFixture(t)
	var clock atomic.Int64
	clock.Store(time.Date(2026, 11, 22, 1, 0, 0, 0, time.Local).Unix())
	f.srv.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/system/automation", nil); code != 403 {
		t.Fatalf("non-admin: %d", code)
	}
	fakeLogin(t, f, "admin")
	if code, out := f.do("PUT", "/api/v1/system/automation", map[string]any{"username": "mydc-autofix"}); code != 503 || errCode(out) != "seal-unavailable" {
		t.Fatalf("without seal: %d %v", code, out)
	}
	box, err := seal.Open(t.TempDir(), make([]byte, seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.opt.Seal = box
	if code, out := f.do("GET", "/api/v1/system/automation", nil); code != 200 || out["configured"] != false || out["sealReady"] != true {
		t.Fatalf("empty: %d %v", code, out)
	}
	if code, _ := f.do("PUT", "/api/v1/system/automation", map[string]any{"username": "Bad Name"}); code != 422 {
		t.Fatalf("bad name: %d", code)
	}
	code, out := f.do("PUT", "/api/v1/system/automation", map[string]any{"username": "mydc-autofix"})
	pub, _ := out["publicKey"].(string)
	if code != 200 || len(pub) != 64 || out["username"] != "mydc-autofix" || out["createdBy"] != "admin" {
		t.Fatalf("make key: %d %v", code, out)
	}
	if _, out := f.do("PUT", "/api/v1/system/automation", map[string]any{"username": "mydc-autofix"}); out["publicKey"] != pub {
		t.Fatal("the same name made a new key")
	}
	_, out = f.do("PUT", "/api/v1/system/automation", map[string]any{"username": "mydc-autofix", "rotate": true})
	if out["publicKey"] == pub {
		t.Fatal("rotate kept the key")
	}
	pub = out["publicKey"].(string)
	// the private key is sealed, not in bbolt or the answer
	if names, _ := box.List(); len(names) == 0 {
		t.Fatal("no sealed key")
	}
	// not registered yet: login is denied
	if code, out := f.do("POST", "/api/v1/system/automation/check", map[string]any{}); code != 200 || out["ok"] != false || out["error"] != "denied" {
		t.Fatalf("check unregistered: %d %v", code, out)
	}

	// the administrator registers the key on a new account (put-user)
	raw, _ := hex.DecodeString(pub)
	var key [32]byte
	copy(key[:], raw)
	code, out = f.do("POST", "/api/v1/ops", map[string]any{"opId": "a1b2c3d4-0000-4000-8000-0000000000a1", "action": mydc.ActionPutUser, "principal": "u-admin", "expected": 0,
		"payload": map[string]any{"ID": "u-autofix", "Username": "mydc-autofix", "Enabled": true,
			"Credentials": []any{map[string]any{"ID": "web-1", "Method": string(mydc.MethodPrivateKey), "PublicKey": key, "Enabled": true}}}})
	if opState(t, code, out) != "applied" {
		t.Fatalf("put-user: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/system/automation/check", map[string]any{})
	if code != 200 || out["ok"] != true || out["user"] != "u-autofix" || out["username"] != "mydc-autofix" {
		t.Fatalf("check: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/system/automation", nil); out["lastCheck"].(map[string]any)["ok"] != true || out["userId"] != "u-autofix" {
		t.Fatalf("lastCheck: %v", out)
	}

	// a scheduled backup signs as the automation account
	if code, out := f.do("PUT", "/api/v1/system/auto-backup", map[string]any{"enabled": true, "at": "03:00", "keep": 2, "tenant": "payments", "volume": "ledger-data"}); code != 200 || out["account"] != "mydc-autofix" || out["accountId"] != "u-autofix" {
		t.Fatalf("auto-backup: %d %v", code, out)
	}
	clock.Add(3 * 3600)
	f.srv.autoBackupTick()
	var last map[string]any
	for deadline := time.Now().Add(10 * time.Second); ; {
		_, st := f.do("GET", "/api/v1/system/auto-backup", nil)
		if st["running"] == false && st["last"] != nil {
			last = st["last"].(map[string]any)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("scheduled run did not end: %v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// mydcd decides: the account has no membership in payments, so the
	// write is denied (the web does not lend it the admin's authority)
	if last["by"] != "mydc-autofix" || last["ok"] != false || !strings.Contains(last["error"].(string), "denied") {
		t.Fatalf("scheduled run: %v", last)
	}

	if _, st := f.do("GET", "/api/v1/system/auto-backup", nil); st["granted"] != false {
		t.Fatalf("granted before the grant: %v", st)
	}
	// the workspace manager grants the folder; the next scheduled run writes.
	// mydcd grants files only to a member of the workspace (viewer here).
	if err := withAdminConn(t, fake, func(c mydc.Conn) error {
		p, err := c.TenantMembers(context.Background(), "payments", "")
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(access.Membership{Tenant: "payments", User: "u-autofix", Role: mydc.RoleViewer, Enabled: true})
		who, err := c.Whoami(context.Background())
		if err != nil {
			return err
		}
		op, err := c.Prepare(context.Background(), mydc.Change{Schema: 1, Action: mydc.ActionSetMembership, Principal: "u-admin", Expected: p.Revision, Payload: raw}, who.RootFor(mydc.ActionSetMembership))
		if err != nil {
			return err
		}
		res, err := c.Submit(context.Background(), op)
		if err == nil && res.Code != mydc.ResultApplied {
			err = fmt.Errorf("membership: %+v", res)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code, out := f.do("POST", "/api/v1/t/payments/volumes/ledger-data/file-grants", map[string]any{"opId": "a1b2c3d4-0000-4000-8000-0000000000a2", "prefix": "mydc-web-backups/", "user": "u-autofix"}); opState(t, code, out) != "applied" {
		t.Fatalf("grant: %d %v", code, out)
	}
	if _, st := f.do("GET", "/api/v1/system/auto-backup", nil); st["granted"] != true {
		t.Fatalf("granted: %v", st)
	}
	clock.Add(24 * 3600)
	f.srv.autoBackupTick()
	for deadline := time.Now().Add(10 * time.Second); ; {
		_, st := f.do("GET", "/api/v1/system/auto-backup", nil)
		if l, _ := st["last"].(map[string]any); st["running"] == false && l["at"] != last["at"] {
			last = l
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("second scheduled run did not end: %v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if last["ok"] != true || last["by"] != "mydc-autofix" {
		t.Fatalf("granted scheduled run: %v", last)
	}

	seed, err := box.Get(automationKey)
	if err != nil || len(seed) != 32 {
		t.Fatalf("sealed seed: %v", err)
	}
	assertKeyNowhere(t, f, seed, "u-admin", "u-autofix")

	// forgetting the account removes the sealed key
	if code, _ := f.do("DELETE", "/api/v1/system/automation", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if _, err := box.Get(automationKey); err == nil {
		t.Fatal("sealed key left behind")
	}
	if code, out := f.do("POST", "/api/v1/system/automation/check", map[string]any{}); code != 409 || errCode(out) != "not-configured" {
		t.Fatalf("check after delete: %d %v", code, out)
	}
	clock.Add(24 * 3600)
	f.srv.autoBackupTick()
	if _, st := f.do("GET", "/api/v1/system/auto-backup", nil); st["last"].(map[string]any)["error"] != ErrAutomationMissing {
		t.Fatalf("missing account: %v", st["last"])
	}
}

// makeAutomation makes the web's automation key for username and, when
// register, puts the account with that key (the admin's own put-user).
func makeAutomation(t *testing.T, f *fixture, username, opID string, register, systemAdmin bool) {
	t.Helper()
	code, out := f.do("PUT", "/api/v1/system/automation", map[string]any{"username": username})
	if code != 200 {
		t.Fatalf("automation key: %d %v", code, out)
	}
	if !register {
		return
	}
	raw, _ := hex.DecodeString(out["publicKey"].(string))
	var key [32]byte
	copy(key[:], raw)
	code, out = f.do("POST", "/api/v1/ops", map[string]any{"opId": opID, "action": mydc.ActionPutUser, "principal": "u-admin", "expected": 0,
		"payload": map[string]any{"ID": "u-" + username, "Username": username, "Enabled": true, "SystemAdmin": systemAdmin,
			"Credentials": []any{map[string]any{"ID": "web-1", "Method": string(mydc.MethodPrivateKey), "PublicKey": key, "Enabled": true}}}})
	if opState(t, code, out) != "applied" {
		t.Fatalf("put-user: %d %v", code, out)
	}
}

func TestACMERenewAsAutomation(t *testing.T) {
	f, _, ca, fake := acmeFixture(t)
	acct := newAccount(t, f)
	if code, out := f.do("POST", "/api/v1/acme/certs", map[string]any{"name": "shop", "names": []string{"shop.example.com"}, "account": acct}); code != 201 {
		t.Fatalf("add cert: %d %v", code, out)
	}
	f.do("POST", "/api/v1/acme/certs/shop/issue", map[string]any{"opId": "a1b2c3d4-0000-4000-8000-0000000000b1"})
	if o := lastOrder(waitCert(t, f, "shop")); o["state"] != "done" {
		t.Fatalf("issue: %v", o)
	}
	due := func() {
		c, _ := f.store.GetACMECert("shop")
		c.NextRenew, c.NextTry = time.Now().Add(-time.Hour), time.Time{}
		f.store.PutACMECert(c)
		f.srv.acmeTick()
	}

	// a key mydcd does not know: the order stops before the CA and retries later
	makeAutomation(t, f, "mydc-web", "", false, false)
	due()
	out := waitCert(t, f, "shop")
	if o := lastOrder(out); o["state"] != "failed" || o["errorCode"] != "renew-account" || o["auto"] != true || ca.Issued() != 1 {
		t.Fatalf("unregistered renewal: %v issued=%d", o, ca.Issued())
	}
	if c := out["certificate"].(map[string]any); c["failures"] != float64(1) || c["nextTry"] == nil {
		t.Fatalf("retry schedule: %v", c)
	}

	// registered (put-certificate here needs a system administrator): the
	// renewal is signed by the automation account
	makeAutomation(t, f, "mydc-web", "a1b2c3d4-0000-4000-8000-0000000000b2", true, true)
	due()
	out = waitCert(t, f, "shop")
	o := lastOrder(out)
	if o["state"] != "done" || ca.Issued() != 2 || journalCount(fake, mydc.ActionPutCertificate) != 2 {
		t.Fatalf("renewal: %v issued=%d", o, ca.Issued())
	}
	if op, _ := f.store.GetOp("u-mydc-web", o["storeOp"].(string)); op == nil || op.User != "u-mydc-web" || op.Username != "mydc-web" {
		t.Fatalf("store op signer: %+v", op)
	}
}

// assertKeyNowhere: the automation seed (raw, hex or base64) is in no web
// data: the whole bbolt file, the ops of users, and the automation answers.
func assertKeyNowhere(t *testing.T, f *fixture, seed []byte, users ...string) {
	t.Helper()
	forms := [][]byte{seed, []byte(hex.EncodeToString(seed)), []byte(base64.StdEncoding.EncodeToString(seed)), []byte(base64.RawURLEncoding.EncodeToString(seed))}
	var db bytes.Buffer
	if _, err := f.store.Backup(func(int64) io.Writer { return &db }); err != nil {
		t.Fatal(err)
	}
	var blobs [][]byte
	blobs = append(blobs, db.Bytes())
	for _, u := range users {
		ops, _ := f.store.ListOps(u, "", 1000)
		for _, o := range ops {
			raw, _ := json.Marshal(o)
			blobs = append(blobs, raw, o.Signed)
		}
	}
	for _, p := range []string{"/api/v1/system/automation", "/api/v1/system/auto-backup", "/api/v1/system/settings"} {
		_, out := f.do("GET", p, nil)
		raw, _ := json.Marshal(out)
		blobs = append(blobs, raw)
	}
	for i, b := range blobs {
		for _, k := range forms {
			if bytes.Contains(b, k) {
				t.Fatalf("automation key found in web data %d", i)
			}
		}
	}
}
