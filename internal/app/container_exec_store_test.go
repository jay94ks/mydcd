// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/storage"
)

func TestUserExecStoreReservesOneOriginalAndReopensWithoutStartAuthorization(t *testing.T) {
	node, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(node.Private)
	defer clear(user.Private)
	cluster := [32]byte{31}
	session := access.Session{Schema: 1, ID: "login-original", Cluster: cluster, User: "alice", Credential: "user-key", AccountRevision: 1, Key: user.Public, Issuer: node.Public, IssuerEpoch: 1, IssuedAt: 1, ExpiresAt: 3601, Scopes: []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read, access.Deploy}}}}
	session.Signature = ed25519.Sign(node.Private, access.SessionBytes(session))
	i := containerops.SessionIntent{Schema: 1, Request: "exec-original", User: "alice", Session: access.ExactSessionDigest(session), At: 2, Target: containerops.Target{Cluster: cluster, Owner: node.Public, Binding: [32]byte{3}, Tenant: "tenant", App: "app", Service: "web", Node: "node-a", Instance: "workload/task/tenant/app/web", Generation: 3, Revision: 4, NativeID: "native-original", StartedAt: "2026-01-01T00:00:00Z"}, Spec: containerops.SessionSpec{Kind: "exec", Exec: &containerops.ExecSpec{Argv: []string{"custom-cli"}}}}
	i.Signature = ed25519.Sign(user.Private, containerops.SessionIntentBytes(i))
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{Identity: node, reports: db, controlPolicy: control.Policy{Cluster: cluster}}
	defer func() { _ = r.reports.Close() }()
	initial := containerops.ExecReceipt{Schema: 1, Intent: i.Digest(), Phase: containerops.ExecCreating}
	var fresh atomic.Int32
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, new, err := r.reserveUserExec(session, i, initial)
			if err != nil {
				t.Error(err)
			}
			if new {
				fresh.Add(1)
			}
		}()
	}
	workers.Wait()
	if fresh.Load() != 1 {
		t.Fatal("duplicate original reservation", fresh.Load())
	}
	created := initial
	created.Phase, created.ExecID = containerops.ExecCreated, "original-exec-id"
	if err = r.updateUserExec(i, created); err != nil {
		t.Fatal(err)
	}
	sent := created
	sent.Phase = containerops.ExecStartSent
	if err = r.updateUserExec(i, sent); err != nil {
		t.Fatal(err)
	}
	before, err := r.reports.Get(userExecKey(i))
	if err != nil {
		t.Fatal(err)
	}
	if err = r.reports.Close(); err != nil {
		t.Fatal(err)
	}
	r.reports, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	retained, new, err := r.reserveUserExec(session, i, initial)
	if err != nil || new || retained.Phase != containerops.ExecStartSent || retained.ExecID != sent.ExecID {
		t.Fatal("recovery became Create/Attach permission", err, new)
	}
	if err = r.updateUserExec(i, created); err != nil {
		t.Fatal("stale earlier receipt should retain newer marker", err)
	}
	after, _ := r.reports.Get(userExecKey(i))
	if !bytes.Equal(before, after) {
		t.Fatal("stale receipt rewound stored marker")
	}
	other := i
	other.Target.NativeID = "replacement"
	other.Signature = ed25519.Sign(user.Private, containerops.SessionIntentBytes(other))
	if _, _, err = r.reserveUserExec(session, other, containerops.ExecReceipt{Schema: 1, Intent: other.Digest(), Phase: containerops.ExecCreating}); err == nil {
		t.Fatal("same ID rebound to another native")
	}
	if _, err = r.userExecIOFacts(i, true, true, true); err != nil {
		t.Fatal(err)
	}
	row, err := r.userExecRecord(i)
	if err != nil || row.Receipt.Phase != containerops.ExecStartSent || row.Receipt.ExitCode != nil {
		t.Fatal("I/O closure invented native completion", err)
	}
}
