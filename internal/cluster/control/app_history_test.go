// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
)

// This fixture represents terminal metadata, not proof of a native effect.
func appHistoryFixture(t *testing.T) (Policy, state.State, Apps, access.Catalog) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{101}, 32))
	var key [32]byte
	copy(key[:], private.Public().(ed25519.PublicKey))
	p := Policy{Cluster: [32]byte{31}, BootstrapKey: key, TrustRoot: key, Genesis: config.Peer{ID: "source", Key: hex.EncodeToString(key[:]), Endpoint: "127.0.0.1:7443", Voter: true}}
	c, _ := access.New(key)
	c, err := c.Enroll(key, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.CreateTenant("admin", "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	session := access.Session{Schema: 1, ID: "session", Cluster: p.Cluster, User: "admin", Credential: "key", AccountRevision: c.Revision(), Key: key, Issuer: key, IssuerEpoch: 1, IssuedAt: 1, ExpiresAt: 100, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.ManageCluster, access.Deploy}}}}
	session.Signature = ed25519.Sign(private, access.SessionBytes(session))
	makeOperation := func(id, action string, expected uint64, payload any) UserOperation {
		raw, _ := json.Marshal(payload)
		op := UserOperation{Schema: 1, Session: session, At: 2, Epoch: 1, RequestID: id, Change: Change{Schema: 1, Principal: "admin", Action: action, Expected: expected, Payload: raw}}
		op.Signature = ed25519.Sign(private, OperationBytes(op))
		return op
	}
	origin := makeOperation("begin", "begin-app", 0, AppBegin{Tenant: "tenant", App: "app", Deployment: "deploy", Operation: "original"})
	down := makeOperation("down", "down-app", 1, AppDown{Tenant: "tenant", App: "app", Operation: "stop"})
	command, _ := origin.Command()
	var record struct {
		Schema                  uint8
		Cluster                 [32]byte
		Tenant, App, Deployment string
		Revision                uint64
		Active                  json.RawMessage
		History                 []deployment.OperationSummary
		MinEpoch                map[string]uint64
		Claims                  []deployment.Claim
		Stopping                bool
		Retirement              json.RawMessage
	}
	record.Schema, record.Cluster, record.Tenant, record.App, record.Deployment, record.Revision = 1, p.Cluster, "tenant", "app", "deploy", 5
	for _, id := range []string{"older", "original"} {
		record.History = append(record.History, deployment.OperationSummary{ID: id, Status: "Retired", Plan: [32]byte{1}, CompletedAt: 9, Submitter: command.Actor, Epoch: 1})
	}
	raw, _ := json.Marshal(record)
	i, err := deployment.DecodeInventory(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := deployment.NewBindings(p.Cluster)
	a := Apps{entries: map[string]appEntry{appKey("tenant", "app"): {Inventory: i, Origin: origin, Down: &down}}, bindings: b}
	s, _ := state.New("legacy-admin")
	for _, root := range []string{CatalogKey, AppsKey} {
		writes, code := p.checkpoint(s, c)
		if code != state.Applied {
			t.Fatal(code)
		}
		if root == AppsKey {
			var code state.Code
			writes, code = p.appsCheckpoint(s, a)
			if code != state.Applied {
				t.Fatal(code)
			}
		}
		var result state.Result
		s, result, err = state.ApplyReduced(s, s.Index()+1, state.Command{Kind: state.Module, Actor: "legacy-admin", Epoch: 1, RequestID: root, Key: root, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
		if err != nil || result.Code != state.Applied {
			t.Fatal(result, err)
		}
	}
	a, err = p.Apps(s)
	if err != nil {
		t.Fatal(err)
	}
	return p, s, a, c
}

func TestAppHistoryCASConsumesCommittedFloorAndPreservesOriginalAnchor(t *testing.T) {
	p, s, a, c := appHistoryFixture(t)
	q := AppHistorySelection{"tenant", "app"}
	// Terminal source metadata is a fixture input. The existing real epoch,
	// closure and cleanup gates must protect it just like operation history.
	source := a.entries[appKey("tenant", "app")]
	body := []byte("# retained original bytes\nname: app\n")
	source.LastVersion = 7
	source.Versions = []appVersion{{AppRevisionView: AppRevisionView{Revision: 7, Tenant: "tenant", App: "app", Deployment: "deploy", Digest: sha256.Sum256(body), Plan: [32]byte{1}, Length: len(body), SubmittedBy: "admin", Operation: "original", AcceptedAt: 2, CompletedAt: 9, Source: "upload", Status: "Retired", OriginalRetained: true}, Body: body}}
	a.entries[appKey("tenant", "app")] = source
	if _, err := a.rotateHistory(5, c, "admin", s, q); err == nil {
		t.Fatal("invented uncommitted epoch")
	}
	// Commit a real A1 floor in the pure state machine; authentication/Raft/DB
	// are exercised by the CLI integration, not inferred from this fixture.
	cmd := state.Command{Kind: state.ModuleWindow, Actor: "user/admin", Epoch: 1, RequestID: "window", Key: StorageKey, Value: "fixture"}
	var result state.Result
	var err error
	s, result, err = state.ApplyAdmitted(s, s.Index()+1, cmd, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
		return map[string][]byte{StorageKey: []byte("fixture")}, state.Applied
	}, func(state.State, state.Command) bool { return true })
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	for _, input := range []struct {
		rev   uint64
		actor string
		q     AppHistorySelection
	}{{4, "admin", q}, {5, "unknown", q}, {5, "admin", AppHistorySelection{"foreign", "app"}}} {
		if _, err := a.rotateHistory(input.rev, c, input.actor, s, input.q); err == nil {
			t.Fatal("bad CAS/permission/scope accepted")
		}
	}
	original := a.entries[appKey("tenant", "app")]
	next, err := a.rotateHistory(5, c, "admin", s, q)
	if err != nil {
		t.Fatal(err)
	}
	entry := next.entries[appKey("tenant", "app")]
	if len(original.Versions) != 1 || len(entry.Versions) != 0 || entry.LastVersion != 7 {
		t.Fatal("source reclamation mutated original or reset version counter")
	}
	if original.Compacted != nil || entry.Compacted == nil || !entry.Inventory.OperationExpired(entry.Compacted.Submitter, 1) {
		t.Fatal("mutation/floor/anchor")
	}
	if _, found := entry.Inventory.Operation("older"); found {
		t.Fatal("old history survived")
	}
	for _, id := range []string{"original", "older"} {
		out, err := next.Operation(c, "admin", "tenant", AppOperationRequest{App: "app", ID: id})
		if err != nil || out.Found != (id == "original") || out.Current {
			t.Fatal(out, err)
		}
		if out.Operation != nil {
			out.Operation.Status = "forged"
		}
	}
	if entry.Compacted.Status != "Retired" || !bytes.Equal(OperationBytes(original.Origin), OperationBytes(entry.Origin)) {
		t.Fatal("aliased original result")
	}
	writes, code := p.appsCheckpoint(s, next)
	if code != state.Applied {
		t.Fatal(code)
	}
	// Decode through the actual checkpoint reader without manufacturing native
	// observations or changing the independent A1 expiry proof.
	s, result, err = state.ApplyReduced(s, s.Index()+1, state.Command{Kind: state.Module, Actor: "legacy-admin", Epoch: 1, RequestID: "checkpoint", Key: AppsKey, Expected: s.Object(AppsKey).Revision, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	if _, err = p.Apps(s); err != nil {
		t.Fatal("checkpoint rejected owned anchor", err)
	}
	for _, mutate := range []func(*appEntry){func(e *appEntry) { e.Compacted.ID = "other" }, func(e *appEntry) { e.Compacted.Epoch = 2 }, func(e *appEntry) { e.Compacted.Status = "Succeeded" }, func(e *appEntry) { e.Down = nil }} {
		copy := entry
		summary := *entry.Compacted
		copy.Compacted = &summary
		mutate(&copy)
		if validCompactedApp(copy.Inventory, copy.Origin, copy.Down, *copy.Compacted) {
			t.Fatal("forged compacted anchor accepted")
		}
	}
}
