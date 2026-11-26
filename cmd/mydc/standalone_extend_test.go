// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func TestStandaloneExtensionCLIOriginalResultAndNumericLimits(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		issuer, _ := identity.Ephemeral()
		self, _ := identity.Ephemeral()
		t.Cleanup(func() { clear(issuer.Private); clear(self.Private) })
		c := userauth.Client{Self: self, Cluster: [32]byte{84}, Peers: []mydcp.Peer{{ID: "node", Endpoint: "127.0.0.1:7443", Policy: mydcp.Policy{Key: mydcp.Identity(issuer.Public), Respond: true}}}}
		now := time.Now().Unix()
		s := access.Session{Schema: 1, ID: "session", Cluster: c.Cluster, User: "alice", Credential: "key", AccountRevision: 1, Key: self.Public, Issuer: issuer.Public, IssuerEpoch: 1, IssuedAt: now, ExpiresAt: now + 3600, Scopes: []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read, access.Deploy}}}}
		s.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(s))
		ttl := int64(86400)
		code := state.ConditionFailed
		if accepted {
			ttl, code = 3600, state.Applied
		}
		q := control.StandaloneExtendChange{Tenant: "tenant", Name: "debug", Scope: "standalone-scope", Operation: "once", CreatedAt: now - 3000, PreviousExpiresAt: now + 600, TTLSeconds: ttl, Target: [32]byte{7}}
		payload, _ := json.Marshal(q)
		op := control.UserOperation{Schema: 1, Session: s, At: now, Epoch: 1, RootRevision: 7, RequestID: "standalone/extend/tenant/once", Change: control.Change{Schema: 1, Action: "standalone-extend", Principal: s.User, Expected: 2, Payload: payload}}
		op.Signature = ed25519.Sign(self.Private, control.OperationBytes(op))
		home := t.TempDir()
		if _, err := userauth.StageOperation(home, c, op); err != nil {
			t.Fatal(err)
		}
		result := state.Result{Code: code, Index: 8, Revision: 8}
		if err := userauth.RecordOperationResult(home, c, s, op, result); err != nil {
			t.Fatal(err)
		}
		o := standaloneOptions{method: "extend", ttl: ttl}
		o.name.value, o.operation.value = "debug", "once"
		var out, diagnostic bytes.Buffer
		got := runStandaloneExtend(context.Background(), o, "tenant", c, c.Peers[0], userauth.Stored{Session: s}, home, &out, &diagnostic)
		want := 3
		if accepted {
			want = 0
		}
		var view struct {
			Extension control.StandaloneExtensionPlan `json:"extension"`
			Applied   bool                            `json:"extension_applied"`
			Code      string                          `json:"extension_code"`
		}
		if got != want || json.Unmarshal(out.Bytes(), &view) != nil || view.Applied != accepted || view.Extension.MaximumExpiresAt != q.CreatedAt+86400 || !accepted && (view.Code != "STANDALONE_TTL_LIMIT" || view.Extension.AllowedTTLSeconds != 83400) {
			t.Fatal("saved receipt did not render original extension without transport", got, diagnostic.String(), out.String())
		}
		o.ttl++
		out.Reset()
		if runStandaloneExtend(context.Background(), o, "tenant", c, c.Peers[0], userauth.Stored{Session: s}, home, &out, &diagnostic) != 2 || out.Len() != 0 {
			t.Fatal("same ID adopted another extension")
		}
		if checkManagementTenant("tenant", op.Change) != nil || checkManagementTenant("foreign", op.Change) == nil {
			t.Fatal("internal scope/digest confused the generic result/resume tenant selector")
		}
	}
}

func TestStandaloneExtensionCLIRequiresExplicitTTLAndOriginalID(t *testing.T) {
	valid := []string{"extend", "debug", "--ttl-seconds", "3600", "--operation", "once"}
	if _, err := parseStandaloneOptions(valid, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"extend", "debug", "--operation", "once"},
		{"extend", "debug", "--ttl-seconds", "3600"},
		append(append([]string{}, valid...), "--lifetime", "temp"),
		append(append([]string{}, valid...), "--grace-seconds", "10"),
		append(append([]string{}, valid...), "--restart", "always"),
	} {
		if _, err := parseStandaloneOptions(args, io.Discard); err == nil {
			t.Fatal("extension changed another policy or lost original ID", args)
		}
	}
	var out bytes.Buffer
	if userHelp([]string{"standalone", "--help"}, &out) == false || !bytes.Contains(out.Bytes(), []byte("standalone extend NAME")) {
		t.Fatal("extension absent from help")
	}
}
