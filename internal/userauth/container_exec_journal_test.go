// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/identity"
)

func TestContainerExecJournalRetainsOriginalAcrossNewLoginAndRejectsRetarget(t *testing.T) {
	home, c, session, issuer := journalFixture(t)
	i := containerops.SessionIntent{Schema: 1, Request: "exec-original", User: session.User, Session: access.ExactSessionDigest(session), At: time.Now().Unix(), Target: containerops.Target{Cluster: c.Cluster, Owner: issuer.Public, Binding: [32]byte{1}, Tenant: "tenant", App: "app", Service: "web", Node: "node-a", Instance: "workload/task/tenant/app/web", Generation: 2, Revision: 3, NativeID: "native-original", StartedAt: "2026-01-01T00:00:00Z"}, Spec: containerops.SessionSpec{Kind: "exec", Exec: &containerops.ExecSpec{Argv: []string{"private-cli", ""}}}}
	i.Signature = ed25519.Sign(c.Self.Private, containerops.SessionIntentBytes(i))
	row, err := StageContainerExec(home, c, session, i)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = json.Marshal(row); err == nil || fmt.Sprintf("%+v", row) != "[redacted container exec intent]" {
		t.Fatal("private exec record exposed")
	}
	changed := i
	changed.Target.NativeID = "replacement"
	changed.Signature = ed25519.Sign(c.Self.Private, containerops.SessionIntentBytes(changed))
	if _, err = StageContainerExec(home, c, session, changed); err == nil {
		t.Fatal("original ID retargeted")
	}
	other, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(other.Private)
	current := session
	current.ID = "new-login"
	current.Key = other.Public
	current.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(current))
	later := c
	later.Self = other
	loaded, err := LoadContainerExec(home, later, current, "tenant", "app", i.Request)
	if err != nil || loaded.Intent.Digest() != i.Digest() || loaded.Original.Key != session.Key {
		t.Fatal("new login rewrote old intent", err)
	}
	// A moved endpoint keeps the namespace, which is the cluster.
	later.Peers = append(later.Peers[:0:0], later.Peers...)
	later.Peers[0].Endpoint = "127.0.0.1:7444"
	if _, err = LoadContainerExec(home, later, current, "tenant", "app", i.Request); err != nil {
		t.Fatal("moved endpoint lost original", err)
	}
}
