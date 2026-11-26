// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func TestNodeShellQueriesHaveExactSelectorsAndOriginalSigningRoot(t *testing.T) {
	for _, method := range []string{"node-shell-policy", "node-shell-sessions"} {
		q := Request{Schema: 1, Method: method, Nonce: [32]byte{1}}
		if !q.validMethodFields() || !q.validQuerySelectors() {
			t.Fatal("query rejected", method)
		}
		foreign := []func(*Request){func(r *Request) { r.Tenant = "tenant" }, func(r *Request) { r.Operation = &control.UserOperation{} }, func(r *Request) { r.Container = nil; r.Username = "foreign" }}
		if method == "node-shell-policy" {
			// node-shell-sessions takes a Node filter; the policy has none.
			foreign = append(foreign, func(r *Request) { r.Node = "node-a" })
		}
		for _, mutate := range foreign {
			bad := q
			mutate(&bad)
			if bad.validMethodFields() || bad.validQuerySelectors() {
				t.Fatal("foreign selector accepted", method)
			}
		}
	}
	q := Request{Method: "node-shell-sessions", After: "original"}
	if !q.validNodeShellQuery() {
		t.Fatal("session cursor rejected")
	}
	q.Method = "node-shell-policy"
	if q.validNodeShellQuery() {
		t.Fatal("policy accepts hidden paging state")
	}
	_, c, session, _ := journalFixture(t)
	raw, _ := control.ChangeBytes("open-node-shell", session.User, 0, control.NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24})
	var change control.Change
	_ = json.Unmarshal(raw, &change)
	op, err := c.prepareOperation(session, "original-shell", change, Reply{RootRevision: 99, NodeShellRootRevision: 7, ModuleEpoch: 1}, time.Now().Unix())
	if err != nil || op.RootRevision != 7 || control.UploadCASAllowed(op.Change.Action) || control.StandaloneCASAllowed(op.Change) || control.AppDownCASAllowed(op.Change) || control.AppFieldCASAllowed(op.Change) || !ed25519.Verify(session.Key[:], control.OperationBytes(op), op.Signature) {
		t.Fatal("wrong namespace/mode/signature", err)
	}
	body, _ := json.Marshal(NodeShellRequest{Schema: 1, SessionID: "original-shell", Nonce: [32]byte{1}})
	if len(body) > 1024 {
		t.Fatal("unbounded open body")
	}
	var fake NodeShellRequest
	if json.Unmarshal([]byte(`{"Schema":1}`), &fake) != nil {
		t.Fatal("decode")
	}
	if fake.valid() {
		t.Fatal("missing original accepted")
	}
}
func TestNodeShellChannelPartialFrameNeverRetriesOrAdvancesOriginal(t *testing.T) {
	stream := &partialContainerFrame{}
	channel, err := newNodeShellChannel(context.Background(), nil, stream, 1, [32]byte{1}, time.Now().Add(time.Minute).Unix(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	if err = channel.Send(mydcp.NodeShellRecord{Kind: "stdout", Data: []byte("bounded")}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err = channel.Send(mydcp.NodeShellRecord{Kind: "end", End: &mydcp.NodeShellEnd{Reason: "exit"}}); !errors.Is(err, context.Canceled) || stream.writes.Load() != 1 {
		t.Fatal("partial write retried on original byte stream", err)
	}
}
func TestNodeShellAuthenticationScopeDoesNotGrantTenantOrNodeAuthority(t *testing.T) {
	scopes := fullUserScopes()
	found := false
	for _, scope := range scopes {
		for _, a := range scope.Actions {
			if a == access.NodeShell {
				found = scope.Tenant == "*"
			}
		}
	}
	if !found {
		t.Fatal("new logins omit node-shell authentication ceiling")
	}
	if access.ValidateScopes([]access.Scope{{Tenant: "tenant", Actions: []access.Action{access.NodeShell}}}) {
		t.Fatal("tenant role scope accepted")
	}
}
