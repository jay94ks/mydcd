// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/seal"
	"github.com/jay94ks/mydcd/internal/web/store"
)

func TestWebSettingsAdminOnlyAndAudited(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/system/settings", nil); code != 403 {
		t.Fatalf("non-admin settings: %d", code)
	}
	f.do("POST", "/api/v1/auth/logout", nil)
	fakeLogin(t, f, "admin")
	code, out := f.do("GET", "/api/v1/system/settings", nil)
	if code != 200 || out["settings"].(map[string]any)["auditRetentionDays"] != float64(365) || out["info"].(map[string]any)["schema"] != float64(1) {
		t.Fatalf("settings: %d %v", code, out)
	}
	bad := map[string]any{"settings": map[string]any{"opRetentionDays": 0, "auditRetentionDays": 365, "notificationRetentionDays": 90}}
	if code, _ := f.do("PUT", "/api/v1/system/settings", bad); code != 422 {
		t.Fatalf("out of range accepted: %d", code)
	}
	good := map[string]any{"settings": map[string]any{"sessionMaxHours": 8, "sessionIdleMinutes": 30, "opRetentionDays": 60, "auditRetentionDays": 400, "notificationRetentionDays": 30}}
	if code, out := f.do("PUT", "/api/v1/system/settings", good); code != 200 || out["settings"].(map[string]any)["opRetentionDays"] != float64(60) {
		t.Fatalf("put: %d %v", code, out)
	}
	if max, idle := f.srv.sessionLimits(); max != 8*time.Hour || idle != 30*time.Minute {
		t.Fatalf("limits: %v %v", max, idle)
	}
	// survives a restart (loaded from bbolt)
	s2 := New(Options{Client: strictFake(), Store: f.store, Logger: discardLogger()})
	if s2.settings().AuditRetentionDays != 400 {
		t.Fatal("settings not reloaded")
	}
	code, out = f.do("GET", "/api/v1/audit", nil)
	items := out["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("audit: %d %v", code, out)
	}
	e := items[0].(map[string]any)
	if e["area"] != "web-settings" || e["username"] != "admin" || e["before"].(map[string]any)["opRetentionDays"] != float64(30) || e["after"].(map[string]any)["opRetentionDays"] != float64(60) {
		t.Fatalf("audit entry: %v", e)
	}
	// a non-admin does not see system-wide entries
	f.do("POST", "/api/v1/auth/logout", nil)
	fakeLogin(t, f, "alice")
	f.store.AppendAudit(&store.AuditEntry{ID: "x1", At: time.Now(), User: "u-admin", Tenant: "shop", Area: "archived", Action: "purge"})
	f.store.AppendAudit(&store.AuditEntry{ID: "x2", At: time.Now(), User: "u-admin", Tenant: "elsewhere", Area: "archived", Action: "purge"})
	_, out = f.do("GET", "/api/v1/audit", nil)
	items = out["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["tenant"] != "shop" {
		t.Fatalf("alice audit: %v", items)
	}
}

func TestSessionIdleAndCap(t *testing.T) {
	f, _ := newFakeFixture(t)
	f.srv.cur.Store(&store.Settings{SessionMaxHours: 1, SessionIdleMinutes: 10})
	fakeLogin(t, f, "alice")
	var ws *webSession
	for _, v := range f.srv.sessions.live {
		ws = v
	}
	if d := time.Until(ws.expiresAt); d > time.Hour+time.Minute {
		t.Fatalf("login not capped: %v", d)
	}
	if code, _ := f.do("GET", "/api/v1/auth/session", nil); code != 200 {
		t.Fatal("session lost early")
	}
	// automatic refreshes do not count as activity
	ws.seen.Store(time.Now().Add(-9 * time.Minute).UnixNano())
	req, _ := http.NewRequest("GET", f.http.URL+"/api/v1/auth/session", nil)
	req.Header.Set("X-MyDC-Background", "1")
	if resp, err := f.hc.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("background refresh: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
	if seen := time.Unix(0, ws.seen.Load()); time.Since(seen) < 8*time.Minute {
		t.Fatal("background refresh counted as activity")
	}
	ws.seen.Store(time.Now().Add(-11 * time.Minute).UnixNano())
	if code, _ := f.do("GET", "/api/v1/auth/session", nil); code != 401 {
		t.Fatalf("idle session still works: %d", code)
	}
}

func TestBackupAndStagedRestore(t *testing.T) {
	f, _ := newFakeFixture(t)
	dir := t.TempDir()
	f.srv.opt.DataDir = dir
	fakeLogin(t, f, "admin")
	f.store.PutPrefs("u-admin", []byte(`{"theme":"dark"}`))
	req, _ := http.NewRequest("GET", f.http.URL+"/api/v1/system/backup", nil)
	resp, err := f.hc.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("backup: %v %v", resp, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ContentLength != int64(len(raw)) {
		t.Fatalf("content-length %d, body %d", resp.ContentLength, len(raw))
	}
	bak := filepath.Join(t.TempDir(), "b.db")
	os.WriteFile(bak, raw, 0o600)
	if err := store.Check(bak); err != nil {
		t.Fatalf("backup is not a web DB: %v", err)
	}

	post := func(body []byte) int {
		req, _ := http.NewRequest("POST", f.http.URL+"/api/v1/system/restore", bytes.NewReader(body))
		req.Header.Set("X-MyDC-Web", "1")
		resp, err := f.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post([]byte("not a db")); code != 422 {
		t.Fatalf("garbage restore: %d", code)
	}
	if code := post(raw); code != 202 {
		t.Fatalf("restore: %d", code)
	}
	_, out := f.do("GET", "/api/v1/system/settings", nil)
	if out["info"].(map[string]any)["restorePending"] != true {
		t.Fatalf("restore not pending: %v", out["info"])
	}
	// the next start swaps it in
	db := filepath.Join(dir, "web.db")
	os.WriteFile(db, []byte("old"), 0o600)
	ok, err := store.ApplyRestore(db, filepath.Join(dir, RestoreFile), time.Now())
	if err != nil || !ok {
		t.Fatalf("apply: %v %v", ok, err)
	}
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if p, _ := st.GetPrefs("u-admin"); string(p) != `{"theme":"dark"}` {
		t.Fatalf("restored prefs: %s", p)
	}
}

func TestSealResetAudited(t *testing.T) {
	f, _ := newFakeFixture(t)
	dir := t.TempDir()
	good, _ := seal.Open(dir, bytes.Repeat([]byte{1}, seal.KeySize))
	good.Put("ai-claude", []byte("k"))
	lost, _ := seal.Open(dir, bytes.Repeat([]byte{2}, seal.KeySize))
	fakeLogin(t, f, "admin")
	// a working box is never reset
	f.srv.opt.Seal = good
	if code, out := f.do("POST", "/api/v1/system/seal/reset", map[string]any{"confirm": "reset"}); code != 409 || out["error"].(map[string]any)["code"] != "seal-ready" {
		t.Fatalf("reset of a working box: %d %v", code, out)
	}
	if v, err := good.Get("ai-claude"); err != nil || string(v) != "k" {
		t.Fatalf("refused reset changed data: %q %v", v, err)
	}
	f.srv.opt.Seal = lost
	if code, _ := f.do("POST", "/api/v1/system/seal/reset", map[string]any{"confirm": "yes"}); code != 400 {
		t.Fatalf("reset without confirm: %d", code)
	}
	code, out := f.do("POST", "/api/v1/system/seal/reset", map[string]any{"confirm": "reset"})
	if code != 200 || out["state"] != "ready" {
		t.Fatalf("reset: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/audit", nil)
	if e := out["items"].([]any)[0].(map[string]any); e["area"] != "seal" || e["before"].(map[string]any)["state"] != "wrong-key" {
		t.Fatalf("audit: %v", e)
	}
}

func TestNotificationsFromOps(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	_, out := f.do("GET", "/api/v1/auth/session", nil)
	uid := out["user"].(map[string]any)["id"].(string)
	fake.LoseNextReply("submit", true)
	body := map[string]any{"opId": opA, "action": mydc.ActionCreateTenant, "principal": uid, "expected": 0,
		"payload": map[string]any{"ID": "lab"}, "rootRevision": fake.RootRevision()}
	if code, _ := f.do("POST", "/api/v1/ops", body); code != 202 {
		t.Fatal("expected unknown")
	}
	code, out := f.do("GET", "/api/v1/notifications", nil)
	items := out["items"].([]any)
	if code != 200 || out["unread"] != float64(1) || len(items) != 1 {
		t.Fatalf("notifications: %d %v", code, out)
	}
	n := items[0].(map[string]any)
	if n["kind"] != NotifyOpUnknown || n["action"] != true || n["link"] != "/ops/"+opA {
		t.Fatalf("notification: %v", n)
	}
	if code, _ := f.do("POST", "/api/v1/notifications/"+n["id"].(string)+"/read", nil); code != 204 {
		t.Fatalf("read: %d", code)
	}
	if code, _ := f.do("POST", "/api/v1/notifications/nope/read", nil); code != 404 {
		t.Fatalf("read missing: %d", code)
	}
	_, out = f.do("GET", "/api/v1/notifications?unread=1", nil)
	if out["unread"] != float64(0) || len(out["items"].([]any)) != 0 {
		t.Fatalf("after read: %v", out)
	}

	// muted kinds are not stored
	if code, _ := f.do("PUT", "/api/v1/notify-prefs", map[string]any{"prefs": map[string]any{"mutedKinds": []string{"bogus"}}}); code != 422 {
		t.Fatalf("unknown kind accepted: %d", code)
	}
	f.do("PUT", "/api/v1/notify-prefs", map[string]any{"prefs": map[string]any{"mutedKinds": []string{NotifyOpUnknown}, "browser": true}})
	fake.LoseNextReply("submit", true)
	body["opId"] = opB
	body["payload"] = map[string]any{"ID": "lab2"}
	body["rootRevision"] = fake.RootRevision()
	f.do("POST", "/api/v1/ops", body)
	_, out = f.do("GET", "/api/v1/notifications", nil)
	if len(out["items"].([]any)) != 1 {
		t.Fatalf("muted kind stored: %v", out)
	}
	_, out = f.do("GET", "/api/v1/notify-prefs", nil)
	if out["prefs"].(map[string]any)["browser"] != true {
		t.Fatalf("prefs: %v", out)
	}
}

func TestWebSettingsLoginRules(t *testing.T) {
	f := newFixture(t)
	if code, out := f.do("GET", "/api/v1/auth/methods", nil); code != 200 || out["key"] != true {
		t.Fatalf("methods: %d %v", code, out)
	}
	no := false
	if err := f.store.PutSettings(&store.Settings{AllowKeyLogin: &no, MaxSessionsPerUser: 2}); err != nil {
		t.Fatal(err)
	}
	f.srv.loadSettings()
	if _, out := f.do("GET", "/api/v1/auth/methods", nil); out["key"] != false {
		t.Fatalf("methods off: %v", out)
	}
	code, out := f.do("POST", "/api/v1/auth/key/challenge", map[string]any{"username": "bob", "publicKey": strings.Repeat("11", 32)})
	if code != 403 || errCode(out) != "key-login-disabled" {
		t.Fatalf("key challenge while off: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/auth/key/login", map[string]any{"ticketId": "x", "signature": strings.Repeat("00", 64)}); code != 403 {
		t.Fatalf("key login while off: %d %v", code, out)
	}

	// three logins of alice: the first one ends
	var jars []*http.Client
	for i := 0; i < 3; i++ {
		jar, _ := cookiejar.New(nil)
		f.hc = &http.Client{Jar: jar}
		f.login()
		jars = append(jars, f.hc)
		time.Sleep(time.Millisecond)
	}
	for i, hc := range jars {
		f.hc = hc
		code, _ := f.do("GET", "/api/v1/auth/session", nil)
		if want := map[bool]int{true: 401, false: 200}[i == 0]; code != want {
			t.Fatalf("session %d: %d, want %d", i, code, want)
		}
	}
	// lowering the cap ends the older of the remaining two
	f.srv.sessions.capAll(1)
	f.hc = jars[1]
	if code, _ := f.do("GET", "/api/v1/auth/session", nil); code != 401 {
		t.Fatalf("capAll kept the older login: %d", code)
	}
	f.hc = jars[2]
	if code, _ := f.do("GET", "/api/v1/auth/session", nil); code != 200 {
		t.Fatalf("capAll ended the newest login: %d", code)
	}
}

func TestWebSettingsInfoAndSeal(t *testing.T) {
	f, _ := newFakeFixture(t)
	dir := t.TempDir()
	key := bytes.Repeat([]byte{3}, seal.KeySize)
	box, err := seal.OpenRekey(dir, key, bytes.Repeat([]byte{4}, seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.opt.Seal, f.srv.opt.SealKeySource, f.srv.opt.DBPath = box, "env", "/data/web.db"
	fakeLogin(t, f, "admin")
	code, out := f.do("GET", "/api/v1/system/settings", nil)
	if code != 200 {
		t.Fatalf("settings: %d %v", code, out)
	}
	st := out["settings"].(map[string]any)
	if st["allowKeyLogin"] != true || st["maxSessionsPerUser"] != float64(0) || st["webhookDeliveryRetentionDays"] != float64(30) || st["mcpCallRetentionDays"] != float64(90) {
		t.Fatalf("new defaults: %v", st)
	}
	info := out["info"].(map[string]any)
	mv, _ := info["mydcdVersion"].(map[string]any)
	if info["dbPath"] != "/data/web.db" || info["connected"] != true || mv == nil || mv["version"] != "1" || mv["protocol"] != "1" || mv["buildTime"] != "2026-11-15T08:00:00Z" {
		t.Fatalf("info: %v", info)
	}
	sl := out["seal"].(map[string]any)
	fp, _ := sl["fingerprint"].(string)
	next, _ := sl["next"].(map[string]any)
	if sl["keySource"] != "env" || sl["dir"] != dir || len([]rune(fp)) != 9 || next == nil || next["fingerprint"] == fp || sl["files"] == nil {
		t.Fatalf("seal: %v", sl)
	}
	raw, _ := json.Marshal(out)
	if bytes.Contains(raw, []byte(hex.EncodeToString(key))) {
		t.Fatal("the seal key shows in settings")
	}
	// out-of-range values
	bad := map[string]any{"settings": map[string]any{"opRetentionDays": 30, "auditRetentionDays": 365, "notificationRetentionDays": 90, "maxSessionsPerUser": 51}}
	if code, _ := f.do("PUT", "/api/v1/system/settings", bad); code != 422 {
		t.Fatalf("maxSessionsPerUser 51 accepted: %d", code)
	}
	good := map[string]any{"settings": map[string]any{"opRetentionDays": 30, "auditRetentionDays": 365, "notificationRetentionDays": 90, "allowKeyLogin": false, "maxSessionsPerUser": 3, "webhookDeliveryRetentionDays": 7, "mcpCallRetentionDays": 14}}
	if code, out := f.do("PUT", "/api/v1/system/settings", good); code != 200 || out["settings"].(map[string]any)["allowKeyLogin"] != false || out["settings"].(map[string]any)["mcpCallRetentionDays"] != float64(14) {
		t.Fatalf("put: %d %v", code, out)
	}
}
