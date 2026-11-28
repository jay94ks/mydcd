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

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestNodeShellQueriesHaveExactSelectorsAndOriginalSigningRoot(t *testing.T) {
	for _, method := range []string{"node-shell-policy", "node-shell-sessions"} {
		q := Request{Schema: 1, Method: method, Nonce: [32]byte{1}, Params: json.RawMessage(`{}`)}
		if !q.validMethodFields() {
			t.Fatal("query rejected", method)
		}
		// The typed request carries only its Params; every old selector
		// field next to them is foreign.
		for _, mutate := range []func(*Request){func(r *Request) { r.Tenant = "tenant" }, func(r *Request) { r.Operation = &control.UserOperation{} }, func(r *Request) { r.Node = "node-a" }, func(r *Request) { r.After = "original" }} {
			bad := q
			mutate(&bad)
			if bad.validMethodFields() {
				t.Fatal("foreign selector accepted", method)
			}
		}
	}
	if (Request{Schema: 1, Method: "node-shell-policy", Params: json.RawMessage(`{"After":"original"}`)}).validMethodFields() {
		t.Fatal("policy accepts hidden paging state")
	}
	if !(Request{Schema: 1, Method: "node-shell-sessions", Params: json.RawMessage(`{"After":"original"}`)}).validMethodFields() {
		t.Fatal("session cursor rejected")
	}
	_, c, session, _ := journalFixture(t)
	raw, _ := control.ChangeBytes("open-node-shell", session.User, 0, control.NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24})
	var change control.Change
	_ = json.Unmarshal(raw, &change)
	op, err := c.prepareOperation(session, "original-shell", change, 1, 7, time.Now().Unix())
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
	if err = channel.Send(sfcp.NodeShellRecord{Kind: "stdout", Data: []byte("bounded")}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if err = channel.Send(sfcp.NodeShellRecord{Kind: "end", End: &sfcp.NodeShellEnd{Reason: "exit"}}); !errors.Is(err, context.Canceled) || stream.writes.Load() != 1 {
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
