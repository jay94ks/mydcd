// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func volumeFact(t *testing.T, scope volumes.Scope, node string, key ed25519.PrivateKey) volumes.NativeReady {
	t.Helper()
	s := volumes.NativeSpec{Schema: 1, Scope: scope, Node: node, NodeKey: [32]byte(key.Public().(ed25519.PublicKey)), Materialization: "initial", UID: 10001, GID: 10001, Mode: 0750, Retain: true}
	raw, _ := json.Marshal(s)
	c := engine.Client{Owner: engine.Owner(scope.Cluster, s.NodeKey)}
	id, err := c.Identity("volume", volumes.NativeKey(s), reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	r := volumes.NativeReady{Schema: 1, Spec: s, Generation: 1, Owner: volumes.Owner{Node: node, Key: s.NodeKey, Native: id.Name}}
	r.Signature = ed25519.Sign(key, volumes.NativeReadyBytes(r))
	if r.Verify() != nil {
		t.Fatal("fixture native fact")
	}
	return r
}

func TestVolumeCheckpointNativeGrantCurrentAuthorityAndLargeRestore(t *testing.T) {
	admin := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, 32))
	node := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
	a, n := [32]byte(admin.Public().(ed25519.PublicKey)), [32]byte(node.Public().(ed25519.PublicKey))
	p := Policy{Cluster: [32]byte{43}, BootstrapKey: a, TrustRoot: n, Genesis: config.Peer{ID: "node-a", Key: hex.EncodeToString(n[:]), Endpoint: "127.0.0.1:8001", Voter: true}}
	c, _ := access.New(a)
	var err error
	c, err = c.Enroll(a, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: a, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.CreateTenant("admin", "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	c, err = c.SetNodes("admin", "tenant", tenant.Revision, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := state.New("anchor")
	checkpoint := func(key, id string, writes map[string][]byte) {
		t.Helper()
		cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: id, Key: key, Expected: s.Object(key).Revision, Value: "fixed-input"}
		next, result, e := state.ApplyReduced(s, s.Index()+1, cmd, p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
		if e != nil || result.Code != state.Applied {
			t.Fatal("checkpoint", id, result, e)
		}
		s = next
	}
	writes, code := p.checkpoint(s, c)
	if code != state.Applied {
		t.Fatal(code)
	}
	checkpoint(CatalogKey, "catalog", writes)
	u, _ := c.User("admin")
	session := access.Session{Schema: 1, ID: "session-admin", Cluster: p.Cluster, User: "admin", Credential: "key", AccountRevision: u.Revision, Key: a, Issuer: n, IssuerEpoch: 1, IssuedAt: 1, ExpiresAt: 1001, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read, access.ManageVolumes}}}}
	session.Signature = ed25519.Sign(node, access.SessionBytes(session))
	apply := func(id, action string, expected uint64, payload any, want state.Code) {
		t.Helper()
		raw, _ := ChangeBytes(action, "admin", expected, payload)
		var change Change
		_ = json.Unmarshal(raw, &change)
		op := UserOperation{Schema: 1, Session: session, At: 2, Epoch: 1, RequestID: id, RootRevision: s.Object(CommandKey(action)).Revision, Change: change}
		op.Signature = ed25519.Sign(admin, OperationBytes(op))
		cmd, e := op.Command()
		if e != nil {
			t.Fatal(e)
		}
		next, result, e := state.ApplyAdmitted(s, s.Index()+1, cmd, p.Validate, p.Reduce, p.AdmitModule)
		if e != nil || result.Code != want {
			t.Fatal("reduce", id, result.Code, want, e)
		}
		s = next
	}
	scope := volumes.Scope{Cluster: p.Cluster, Tenant: "tenant", App: "app", ID: "data", Generation: 1}
	ready := volumeFact(t, scope, "node-a", node)
	forged := ready
	forged.Signature = bytes.Repeat([]byte{1}, 64)
	apply("forged", "create-volume", 0, forged, state.Invalid)
	apply("create", "create-volume", 0, ready, state.Applied)
	apply("duplicate", "create-volume", 0, ready, state.ConditionFailed)
	apply("writer", "acquire-volume", 1, VolumeAcquire{scope, "database", 3, true}, state.Applied)
	registry, err := p.Volumes(s)
	if err != nil {
		t.Fatal(err)
	}
	core, ok := registry.Volume(scope)
	if !ok {
		t.Fatal("missing volume")
	}
	consumer := core.Consumers()[0]
	request := volumes.StartRequest{Scope: scope, Consumer: consumer, Boot: [32]byte{1}, Challenge: [32]byte{2}, Sequence: 1}
	permit, err := p.VolumePermit(s, n, request)
	if err != nil || permit.Request != request {
		t.Fatal("current owner permission", err)
	}
	if _, err = p.VolumePermit(s, a, request); err == nil {
		t.Fatal("other caller impersonated owner")
	}
	wrong := request
	wrong.Consumer.Lease.Token++
	if _, err = p.VolumePermit(s, n, wrong); err == nil {
		t.Fatal("foreign consumer permit")
	}
	apply("competing-writer", "acquire-volume", core.Revision(), VolumeAcquire{scope, "other-task", 4, true}, state.ConditionFailed)
	tenant, _ = c.Tenant("tenant")
	c, err = c.SetNodes("admin", "tenant", tenant.Revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	writes, _ = p.checkpoint(s, c)
	checkpoint(CatalogKey, "revoke-node", writes)
	if _, err = p.VolumePermit(s, n, request); err == nil {
		t.Fatal("revoked node activated from old shared state")
	}
	gone := volumes.Gone{Scope: scope, Consumer: consumer, Stopped: true, MountsGone: true}
	gone.Signature = ed25519.Sign(node, volumes.GoneBytes(gone))
	apply("release-after-revoke", "release-volume", core.Revision(), gone, state.Applied)
	registry, err = p.Volumes(s)
	if err != nil {
		t.Fatal(err)
	}
	core, _ = registry.Volume(scope)
	if len(core.Consumers()) != 0 {
		t.Fatal("original closure not settled")
	}
	tenant, _ = c.Tenant("tenant")
	c, err = c.SetNodes("admin", "tenant", tenant.Revision, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	writes, _ = p.checkpoint(s, c)
	checkpoint(CatalogKey, "restore-node", writes)
	apply("returned-generation", "acquire-volume", core.Revision(), VolumeAcquire{scope, "database", 3, true}, state.ConditionFailed)
	// Grow fixed typed input beyond one command; no native object is created.
	for i := 0; i < 80; i++ {
		vscope := scope
		vscope.ID = fmt.Sprintf("data-%03d", i)
		fact := volumeFact(t, vscope, "node-a", node)
		vcore, e := volumes.New(c, "admin", vscope, fact.Owner, 3)
		if e != nil {
			t.Fatal(e)
		}
		registry.entries[volumeKey(vscope)] = registeredVolume{Native: fact, State: vcore}
	}
	writes, code = p.volumeCheckpoint(s, registry)
	if code != state.Applied || len(writes) < 4 {
		t.Fatal("large volume checkpoint", code, len(writes))
	}
	for _, b := range writes {
		if len(b) > 32<<10 {
			t.Fatal("oversized checkpoint row")
		}
	}
	checkpoint(VolumesKey, "large-volumes", writes)
	raw, err := state.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	round, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := p.Volumes(round)
	if err != nil || len(restored.entries) != 81 {
		t.Fatal("large snapshot restore", err)
	}
	if !p.storageQuiescent(round) {
		t.Fatal("volume namespace lost ledger-window eligibility")
	}
	page, after, err := restored.Page(c, "admin", "tenant", "")
	if err != nil || len(page) != 8 || after == "" {
		t.Fatal("bounded filtered page", err)
	}
	if _, _, err = restored.Page(c, "missing", "tenant", ""); err == nil {
		t.Fatal("unapproved page read")
	}
	// A hash-correct checkpoint cannot lose a consumer's original grant.
	entry := restored.entries[volumeKey(scope)]
	entry.State, _, err = entry.State.Acquire(c, "admin", entry.State.Revision(), "new-database", 4, true)
	if err != nil {
		t.Fatal(err)
	}
	restored.entries[volumeKey(scope)] = entry
	broken, _ := p.volumeCheckpoint(round, restored)
	cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: "broken-grant", Key: VolumesKey, Expected: round.Object(VolumesKey).Revision, Value: "fixed-input"}
	_, result, err := state.ApplyReduced(round, round.Index()+1, cmd, p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return broken, state.Applied })
	if err != nil || result.Code == state.Applied {
		t.Fatal("orphaned grant checkpoint accepted", err)
	}
}
