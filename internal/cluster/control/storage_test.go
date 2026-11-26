// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

func TestStorageWindowPinsRuntimeNodeIntentUntilOriginalClosure(t *testing.T) {
	f := newBackupCore(t)
	isolateVolumeCore(t, f)
	d, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := d.NodeOperation("isolate-volume-owner")
	f.apply("deny-expiry-before-node-closure", "rotate-ledger", 1, LedgerWindow{NextEpoch: 2}, state.ConditionFailed)
	if f.s.ModuleEpoch() != 1 || f.p.storageQuiescent(f.s) {
		t.Fatal("unresolved node intent lost its receipt window")
	}
	d, _ = f.p.Members(f.s)
	topology, _ := d.Topology()
	node, _ := topology.Node("node-a")
	proof := lifecycle.Proof{Cluster: f.p.Cluster, Node: "node-a", Operation: node.Pending.ID, Generation: node.Generation, Revision: node.Pending.Revision, ConfigurationIndex: topology.Configuration().Index, Closed: true}
	proof.Signature = ed25519.Sign(f.node, lifecycle.ProofBytes(proof)) // Explicit modeled native closure.
	nodeCoreReport(t, f, MemberReport{Action: "node-proof", Node: "node-a", Expected: d.Revision, Proof: &proof}, state.Applied)
	f.apply("explicit-expiry-after-node-closure", "rotate-ledger", 1, LedgerWindow{NextEpoch: 2}, state.Applied)
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err = f.p.Members(f.s)
	closed, found := d.NodeOperation(original.ID)
	if err != nil || !found || f.s.ModuleEpoch() != 2 || !bytes.Equal(original.Origin, closed.Origin) {
		t.Fatal("window expiry/restart erased original node authorization", err)
	}
	var operation UserOperation
	if json.Unmarshal(original.Origin, &operation) != nil {
		t.Fatal("original signed node request")
	}
	command, err := operation.Command()
	if err != nil || !f.s.ModuleExpired(command) {
		t.Fatal("old original request became replayable", err)
	}
}

func TestStorageWindowManagedSourcesRequireExactCompleteProjection(t *testing.T) {
	f, _ := routeControlFixture(t)
	if !f.p.storageQuiescent(f.s) {
		t.Fatal("settled managed networks and unstarted disabled DNS block ledger rotation")
	}
	projection, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	var native []byte
	for key := range projection.ManagedSources {
		if object := f.s.Object(key); object.Present {
			native = []byte(object.Value)
			break
		}
	}
	dnsKey := services.ManagedDNSKey("tenant", "services")
	if len(native) == 0 || !f.s.Object(dnsKey).Present {
		t.Fatal("typed managed source preconditions missing")
	}
	for _, input := range []struct {
		key string
		raw []byte
	}{
		{tenancy.ManagedNetworkSourcePrefix + "unowned", native},
		{services.ManagedDNSKey("tenant", "unowned"), []byte(f.s.Object(dnsKey).Value)},
	} {
		t.Run(input.key, func(t *testing.T) {
			// Corrupt checkpoint input only: no product reducer admits this row.
			command := state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "orphan-source", Key: input.key, Value: "fixture"}
			bad, result, err := state.ApplyReduced(f.s, f.s.Index()+1, command, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
				return map[string][]byte{input.key: input.raw}, state.Applied
			})
			if err != nil || result.Code != state.Applied {
				t.Fatal("corrupt input was not constructed", result, err)
			}
			if f.p.storageQuiescent(bad) {
				t.Fatal("same-prefix orphan/mismatched source authorized ledger rotation")
			}
		})
	}
}

func TestStorageWindowRejectsUnsettledMembershipAndUnknownNamespaces(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{97}, 32))
	var key [32]byte
	copy(key[:], private.Public().(ed25519.PublicKey))
	p := Policy{Cluster: [32]byte{9}, BootstrapKey: key, TrustRoot: key, Genesis: config.Peer{ID: "source", Key: hex.EncodeToString(key[:]), Endpoint: "127.0.0.1:7443", Voter: true}}
	s, _ := state.New("legacy-admin")
	catalog, _ := access.New(key)
	catalog, err := catalog.Enroll(key, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	fixture := func(s state.State, root string, writes map[string][]byte) state.State {
		t.Helper()
		cmd := state.Command{Actor: "legacy-admin", Kind: state.Module, Epoch: 1, RequestID: root, Key: root, Value: "fixture"}
		n, r, err := state.ApplyReduced(s, s.Index()+1, cmd, p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
		if err != nil || r.Code != state.Applied {
			t.Fatal("fixture", r, err)
		}
		return n
	}
	writes, _ := p.checkpoint(s, catalog)
	s = fixture(s, CatalogKey, writes)
	session := access.Session{Schema: 1, ID: "admin-session", Cluster: p.Cluster, User: "admin", Credential: "key", AccountRevision: catalog.Revision(), Key: key, Issuer: key, IssuerEpoch: 1, IssuedAt: 1, ExpiresAt: 100, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.ManageCluster}}}}
	session.Signature = ed25519.Sign(private, access.SessionBytes(session))
	payload, _ := json.Marshal(LedgerWindow{NextEpoch: 2})
	op := UserOperation{Schema: 1, Session: session, At: 2, Epoch: 1, RequestID: "rotate", Change: Change{Schema: 1, Principal: "admin", Action: "rotate-ledger", Expected: 1, Payload: payload}}
	op.Signature = ed25519.Sign(private, OperationBytes(op))
	cmd, _ := op.Command()
	if !p.storageQuiescent(s) {
		t.Fatal("blank settled catalog cannot rotate")
	}
	d, _ := p.Members(s)
	foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{98}, 32))
	d, err = d.Invite(config.Peer{ID: "target", Key: hex.EncodeToString(foreign.Public().(ed25519.PublicKey)), Endpoint: "127.0.0.1:7444"}, "join-target")
	if err != nil {
		t.Fatal(err)
	}
	writes, _ = p.memberCheckpoint(s, d)
	pending := fixture(s, MembersKey, writes)
	unknown := fixture(s, "control/future-app", map[string][]byte{"control/future-app": []byte("uninspected-request-reference")})
	for _, input := range []state.State{pending, unknown} {
		n, r, err := state.ApplyAdmitted(input, input.Index()+1, cmd, p.Validate, p.Reduce, p.AdmitModule)
		original, found := n.LookupResult(cmd)
		if err != nil || r.Code != state.ConditionFailed || n.ModuleEpoch() != 1 || n.Object(StorageKey).Present || !found || original != r {
			t.Fatal("unsafe expiry accepted", r, err)
		}
	}
	n, r, err := state.ApplyAdmitted(s, s.Index()+1, cmd, p.Validate, p.Reduce, p.AdmitModule)
	if err != nil || r.Code != state.Applied {
		t.Fatal("settled expiry rejected", r, err)
	}
	if st, err := p.Storage(n); err != nil || st.Epoch != 2 || st.RotatedAt != uint64(op.At) || st.RotatedBy != op.Session.User || st.RotationOperation != op.RequestID {
		t.Fatal("storage/floor mismatch", st, err)
	}
	// Changing the method/kind does not bypass typed rotation authority.
	forged := cmd
	forged.Kind = state.Module
	if _, code := p.Reduce(s, forged); code == state.Applied {
		t.Fatal("ordinary module changed window")
	}
	op.Change.Action = "put-user"
	op.Signature = ed25519.Sign(private, OperationBytes(op))
	wrong, _ := op.Command()
	wrong.Kind, wrong.Key = state.ModuleWindow, StorageKey
	if _, code := p.Reduce(s, wrong); code == state.Applied {
		t.Fatal("forged command kind changed window")
	}
	// A structurally well-formed but different floor cannot be restored.
	raw, _ := state.Encode(n)
	if _, err := state.Decode(raw); err != nil {
		t.Fatal(err)
	}
}
