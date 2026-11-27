// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/userauth"
)

// managedSession is a logged-in session for new-frame commands, built from
// the managed fixture without the wallet prompt of globals.open.
func managedSession(t *testing.T, m *managedNode, home string) *session {
	t.Helper()
	c := m.adminClient()
	sess, err := c.Login(m.ctx, m.Peer, m.user, m.Admin.Private)
	if err != nil {
		t.Fatal("login", err)
	}
	return &session{Client: *c, Target: m.Peer, Stored: userauth.Stored{Session: sess, Username: m.user}, Home: home, Context: "test"}
}

func TestSendChange(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(admin.Private) })
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	m := newManagedNode(t, ctx, root, "node", admin)
	m.EnrollAdmin(access.User{ID: "sys", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}})
	s := managedSession(t, m, home)
	g := &globals{timeout: 20 * time.Second}
	c := &cli.Context{Ctx: ctx}
	opState := func(id string) cli.Op {
		t.Helper()
		x, err := openOps()
		if err != nil {
			t.Fatal(err)
		}
		defer x.Close()
		op, err := x.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		return op
	}

	ch := change{Summary: "tenant create shop", ID: "c1", Action: "create-tenant", Payload: control.TenantID{ID: "shop"}}
	result, err := g.send(c, s, ch)
	if err != nil || result == nil || result.Code != state.Applied {
		t.Fatal("first send", result, err)
	}
	if op := opState("c1"); op.State != cli.Done || op.Kind != "change" || op.Context != "test" {
		t.Fatalf("op after send: %+v", op)
	}
	// The same ID continues the saved original; it is not prepared again.
	if result, err = g.send(c, s, ch); err != nil || result.Code != state.Applied {
		t.Fatal("repeat send", result, err)
	}
	// The same ID cannot name another change.
	other := ch
	other.Payload = control.TenantID{ID: "other"}
	if _, err = g.send(c, s, other); err == nil {
		t.Fatal("ID reused for a different payload")
	}
	// A rejection is final and named.
	dup := change{Summary: "tenant create shop", ID: "c2", Action: "create-tenant", Payload: control.TenantID{ID: "shop"}}
	result, err = g.send(c, s, dup)
	if err == nil || result == nil || result.Code == state.Applied {
		t.Fatal("duplicate tenant accepted", result, err)
	}
	if op := opState("c2"); op.State != cli.Failed || op.Detail == "" {
		t.Fatalf("op after rejection: %+v", op)
	}
	// Async marks an applied change accepted, not done.
	async := change{Summary: "tenant create later", ID: "c3", Action: "create-tenant", Payload: control.TenantID{ID: "later"}, Async: true}
	if _, err = g.send(c, s, async); err != nil {
		t.Fatal(err)
	}
	if op := opState("c3"); op.State != cli.Accepted {
		t.Fatalf("async op: %+v", op)
	}
}

func TestUnknownExitCode(t *testing.T) {
	err := unknown(errOutcomeUnknown{id: "abcd"})
	var exit cli.ExitError
	if !errors.As(err, &exit) || exit.Code != exitUnknown {
		t.Fatal(err)
	}
	if other := errors.New("x"); unknown(other) != other {
		t.Fatal("other error changed")
	}
	if st, _ := changeState(state.Result{Code: state.Expired}, false); st != cli.Sending {
		t.Fatal("expired result is final", st)
	}
}
