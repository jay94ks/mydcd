// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

func inviteRow(t *testing.T, f *fixture, user string) map[string]any {
	t.Helper()
	code, out := f.do("GET", "/api/v1/users", nil)
	if code != 200 {
		t.Fatalf("users: %d %v", code, out)
	}
	for _, x := range out["items"].([]any) {
		row := x.(map[string]any)
		if row["username"] == user {
			inv, _ := row["invite"].(map[string]any)
			return inv
		}
	}
	t.Fatalf("no row for %s: %v", user, out)
	return nil
}

func TestFakeInviteLink(t *testing.T) {
	f, fake := newFakeFixture(t)
	n := 0
	op := func() string { n++; return fmt.Sprintf("1a2b3c4d-0000-4000-8000-%012d", n) }
	_, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "admin", "method": "password"})
	if code, out := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": "admin"}); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	// a new account awaiting its first method
	code, out := f.do("POST", "/api/v1/ops", map[string]any{"opId": op(), "action": sfc.ActionPutUser, "principal": "u-admin", "expected": 0,
		"payload": map[string]any{"ID": "u-carol", "Username": "carol", "Enabled": true}})
	if opState(t, code, out) != "applied" {
		t.Fatalf("put-user: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/users/carol/invites", map[string]any{"opId": op(), "expires": "2h"}); code != 400 {
		t.Fatalf("bad expiry: %d %v", code, out)
	}
	issue := op()
	code, out = f.do("POST", "/api/v1/users/carol/invites", map[string]any{"opId": issue, "expires": "24h"})
	link, _ := out["link"].(string)
	if opState(t, code, out) != "applied" || !strings.HasPrefix(link, "/login/invite?u=carol#") || out["expiresAt"] == nil {
		t.Fatalf("issue: %d %v", code, out)
	}
	secret := link[strings.Index(link, "#")+1:]
	// a replayed opId never shows the code again
	if code, out := f.do("POST", "/api/v1/users/carol/invites", map[string]any{"opId": issue, "expires": "24h"}); code != 200 || out["link"] != nil {
		t.Fatalf("replay: %d %v", code, out)
	}
	if inv := inviteRow(t, f, "carol"); inv == nil || inv["state"] != "active" {
		t.Fatalf("invite row: %v", inv)
	}
	// one enabled invitation at a time
	if code, out := f.do("POST", "/api/v1/users/carol/invites", map[string]any{"opId": op(), "expires": "1h"}); opState(t, code, out) == "applied" || out["link"] != nil {
		t.Fatalf("second invite: %d %v", code, out)
	}

	// the recipient: no web session
	anon, _ := cookiejar.New(nil)
	admin := f.hc.Jar
	f.hc.Jar = anon
	if code, out := f.do("POST", "/api/v1/login/invite/open", map[string]any{"username": "carol", "code": "wrong"}); code != 410 || errCode(out) != "invite-invalid" {
		t.Fatalf("wrong code: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/login/invite/open", map[string]any{"username": "alice", "code": secret}); code != 410 || errCode(out) != "invite-invalid" {
		t.Fatalf("no invitation: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/login/invite/open", map[string]any{"username": "carol", "code": secret})
	if code != 200 || out["userId"] != "u-carol" || out["username"] != "carol" || len(out["clusterId"].(string)) != 64 || out["accountRevision"] == nil {
		t.Fatalf("open: %d %v", code, out)
	}
	opened := out
	// the code was consumed
	if code, out := f.do("POST", "/api/v1/login/invite/open", map[string]any{"username": "carol", "code": secret}); code != 410 || errCode(out) != "invite-invalid" {
		t.Fatalf("second open: %d %v", code, out)
	}
	// the opened ticket is not a password/token login ticket
	if code, _ := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": opened["ticket"], "secret": secret}); code != 401 {
		t.Fatalf("credential login with an invite ticket: %d", code)
	}

	// the ticket above was spent by that attempt: the administrator revokes
	// the opened invitation and issues a new one
	f.hc.Jar = admin
	_, users := f.do("GET", "/api/v1/users/carol", nil)
	code, out = f.do("POST", "/api/v1/users/carol/invites/revoke", map[string]any{"opId": op(), "expected": users["accountRevision"]})
	if opState(t, code, out) != "applied" {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if inv := inviteRow(t, f, "carol"); inv != nil {
		t.Fatalf("revoked invite row: %v", inv)
	}
	if code, out := f.do("POST", "/api/v1/users/carol/invites/revoke", map[string]any{"opId": op(), "expected": users["accountRevision"]}); code != 409 || errCode(out) != "no-invite" {
		t.Fatalf("revoke twice: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/users/carol/invites", map[string]any{"opId": op(), "expires": "1h"})
	link, _ = out["link"].(string)
	if opState(t, code, out) != "applied" || link == "" {
		t.Fatalf("reissue: %d %v", code, out)
	}
	secret = link[strings.Index(link, "#")+1:]

	f.hc.Jar = anon
	// the browser has its key before it opens the link
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	pub := [32]byte(priv.Public().(ed25519.PublicKey))
	code, opened = f.do("POST", "/api/v1/login/invite/open", map[string]any{"username": "carol", "code": secret})
	if code != 200 {
		t.Fatalf("open: %d %v", code, opened)
	}
	cluster, _ := hex.DecodeString(opened["clusterId"].(string))
	var challenge [32]byte
	challenge[0] = 7
	add := access.CredentialAddition{User: "u-carol", Credential: access.CredentialKey{ID: "web-1", Method: access.PrivateKey, PublicKey: pub}, Label: "laptop", Challenge: challenge}
	proof := ed25519.Sign(priv, access.CredentialAdditionBytes([32]byte(cluster), uint64(opened["accountRevision"].(float64)), add))
	finish := map[string]any{"ticket": opened["ticket"], "credential": map[string]any{"id": "web-1", "publicKey": hex.EncodeToString(pub[:])}, "label": "laptop",
		"challenge": hex.EncodeToString(challenge[:]), "proof": base64.StdEncoding.EncodeToString(proof)}
	if code, out := f.do("POST", "/api/v1/login/invite/finish", finish); code != 200 || out["credential"] != "web-1" {
		t.Fatalf("finish: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/login/invite/finish", finish); code != 410 || errCode(out) != "ticket-expired" {
		t.Fatalf("finish twice: %d %v", code, out)
	}

	// the new key logs in
	code, out = f.do("POST", "/api/v1/auth/key/challenge", map[string]any{"username": "carol", "publicKey": hex.EncodeToString(pub[:])})
	if code != 200 {
		t.Fatalf("key challenge: %d %v", code, out)
	}
	raw, _ := base64.StdEncoding.DecodeString(out["proof"].(string))
	code, out = f.do("POST", "/api/v1/auth/key/login", map[string]any{"ticketId": out["ticketId"], "signature": hex.EncodeToString(ed25519.Sign(priv, raw))})
	if code != 200 {
		t.Fatalf("key login: %d %v", code, out)
	}
	raw, _ = base64.StdEncoding.DecodeString(out["approval"].(string))
	if code, out := f.do("POST", "/api/v1/auth/key/approve", map[string]any{"ticketId": out["ticketId"], "signature": hex.EncodeToString(ed25519.Sign(priv, raw))}); code != 200 {
		t.Fatalf("approve: %d %v", code, out)
	}
	// and turns off the used invitation itself
	_, me := f.do("GET", "/api/v1/me/credentials", nil)
	var used string
	for _, x := range me["credentials"].([]any) {
		c := x.(map[string]any)
		if strings.HasPrefix(c["id"].(string), sfc.InvitePrefix) && c["enabled"] == true {
			used = c["id"].(string)
		}
	}
	code, out = f.do("POST", "/api/v1/ops", map[string]any{"opId": op(), "action": sfc.ActionDisableCredential, "principal": "u-carol", "expected": me["accountRevision"],
		"payload": map[string]any{"User": "u-carol", "Credential": used}})
	if used == "" || opState(t, code, out) != "applied" {
		t.Fatalf("disable used invite %q: %d %v", used, code, out)
	}

	// an expired invitation cannot be opened
	f.hc.Jar = admin
	code, out = f.do("POST", "/api/v1/users/carol/invites", map[string]any{"opId": op(), "expires": "1h"})
	link, _ = out["link"].(string)
	if opState(t, code, out) != "applied" {
		t.Fatalf("invite after key: %d %v", code, out)
	}
	fake.SetClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	f.srv.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	_, out = f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "admin", "method": "password"})
	if code, out := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": "admin"}); code != 200 {
		t.Fatalf("admin login again: %d %v", code, out)
	}
	if inv := inviteRow(t, f, "carol"); inv == nil || inv["state"] != "expired" {
		t.Fatalf("expired row: %v", inv)
	}
	f.hc.Jar = anon
	if code, out := f.do("POST", "/api/v1/login/invite/open", map[string]any{"username": "carol", "code": link[strings.Index(link, "#")+1:]}); code != 410 || errCode(out) != "invite-invalid" {
		t.Fatalf("expired open: %d %v", code, out)
	}
}
