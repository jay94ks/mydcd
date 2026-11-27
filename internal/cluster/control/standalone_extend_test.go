// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
)

func TestStandaloneExtensionArithmeticAndNumericBounds(t *testing.T) {
	plan, err := PlanStandaloneExtension(2, 3602, 3002, 3600)
	if err != nil || plan.ProposedExpiresAt != 6602 || plan.MaximumExpiresAt != 86402 || plan.AllowedTTLSeconds != 83400 || plan.RemainingExtensionSeconds != 79800 {
		t.Fatal("50 minute extension did not use now plus TTL", plan, err)
	}
	for _, tc := range []struct {
		name                       string
		created, previous, at, ttl int64
		want                       error
	}{
		{"over-cap", 2, 3602, 3002, 83401, ErrStandaloneExtensionLimit},
		{"unchanged", 2, 3602, 3002, 600, ErrStandaloneExtensionNotIncreased},
		{"shortens", 2, 3602, 3002, 1, ErrStandaloneExtensionNotIncreased},
		{"expired", 2, 3602, 3602, 3600, ErrStandaloneExtensionExpired},
		{"zero", 2, 3602, 3002, 0, access.ErrInvalid},
		{"negative", 2, 3602, 3002, -1, access.ErrInvalid},
		{"before-created", 2, 3602, 1, 3600, access.ErrInvalid},
		{"created-overflow", math.MaxInt64 - 86399, math.MaxInt64 - 86398, math.MaxInt64 - 86398, 1, access.ErrInvalid},
		{"proposed-overflow", 2, 3602, 3002, math.MaxInt64, access.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PlanStandaloneExtension(tc.created, tc.previous, tc.at, tc.ttl)
			if !errors.Is(err, tc.want) {
				t.Fatal(got, err, tc.want)
			}
			if tc.name == "over-cap" && (got.MaximumExpiresAt != 86402 || got.AllowedTTLSeconds != 83400 || got.RemainingExtensionSeconds != 82800 || got.ProposedExpiresAt != 86403) {
				t.Fatal("rejection lost exact numeric remaining bound", got)
			}
		})
	}
	atCap, err := PlanStandaloneExtension(2, 3602, 3002, 83400)
	if err != nil || atCap.ProposedExpiresAt != 86402 || atCap.RemainingExtensionSeconds != 0 {
		t.Fatal("exact 24 hour cap refused", atCap, err)
	}
}

func standaloneExtendSession(f *backupCoreFixture, at int64) {
	f.session.IssuedAt = at
	f.session.ExpiresAt = at + access.MaxSessionSeconds
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
}

func standaloneExtendIntent(t *testing.T, f *backupCoreFixture, scope, id string, at, ttl int64) (UserOperation, state.Command) {
	t.Helper()
	a, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	e := a.entries[appKey("tenant", scope)]
	q := StandaloneExtendChange{Tenant: "tenant", Name: e.Standalone.Name, Scope: scope, Operation: id, CreatedAt: e.Standalone.CreatedAt, PreviousExpiresAt: e.Standalone.ExpiresAt, TTLSeconds: ttl, Target: e.standaloneTarget()}
	raw, err := ChangeBytes("standalone-extend", f.session.User, e.Standalone.Revision, q)
	if err != nil {
		t.Fatal(err)
	}
	var change Change
	_ = json.Unmarshal(raw, &change)
	op := UserOperation{Schema: 1, Session: f.session, At: at, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "standalone/extend/" + id, Change: change}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	command, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	return op, command
}

func TestStandaloneExtensionUsesOriginalFSMAndPreservesNativeSources(t *testing.T) {
	f, scope, task := standaloneNativeCASFixture(t)
	standaloneExtendSession(f, 3000)
	op, command := standaloneExtendIntent(t, f, scope, "first-extension", 3002, 3600)
	standaloneCASConnections(t, f, scope, 3003)
	disconnected := standaloneReportCore(t, f, scope, "connections", "", 3004)
	disconnectCommand, err := disconnected.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, disconnectCommand, state.Applied)
	standaloneCASNativeObservation(t, f, scope, task, 3004)
	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", scope)]
	inventory, _ := entry.Inventory.Encode()
	origin, _ := json.Marshal(entry.Origin)
	policy := standalonePolicyOrigin(entry)
	sources, _ := json.Marshal(apps.sources)
	bindings, _ := apps.bindings.Encode()
	metadata := *entry.Standalone
	native := f.s.Object(task)
	before := f.s
	result := applyDownCAS(t, f, command, state.Applied)
	apps, err = f.p.Apps(f.s)
	entry = apps.entries[appKey("tenant", scope)]
	afterInventory, _ := entry.Inventory.Encode()
	afterOrigin, _ := json.Marshal(entry.Origin)
	afterSources, _ := json.Marshal(apps.sources)
	afterBindings, _ := apps.bindings.Encode()
	proof, _ := json.Marshal(entry.Standalone.LastExtension)
	originalProof, _ := json.Marshal(op)
	if err != nil || command.Kind != state.ModuleAppCAS || entry.Standalone.ExpiresAt != 6602 || !bytes.Equal(inventory, afterInventory) || !bytes.Equal(origin, afterOrigin) || !bytes.Equal(sources, afterSources) || !bytes.Equal(bindings, afterBindings) || !sameStandaloneExtensionOperation(policy, standalonePolicyOrigin(entry)) || !bytes.Equal(proof, originalProof) || f.s.Object(task) != native {
		t.Fatal("extension changed native/workload/accepted authority or original proof", err)
	}
	got := *entry.Standalone
	got.ExpiresAt, got.Revision, got.LastExtension = metadata.ExpiresAt, metadata.Revision, nil
	left, _ := json.Marshal(metadata)
	right, _ := json.Marshal(got)
	if !bytes.Equal(left, right) {
		t.Fatal("extension changed grace, connection, creation or other metadata")
	}
	events, err := f.p.ProjectEvents(before, f.s, command, result)
	if err != nil || len(events) != 1 || events[0].Kind != "standalone-extended" || events[0].Target.App != scope || events[0].Detail.Operation != op.RequestID || events[0].Detail.Value != 6602 {
		t.Fatal("missing original extension event", events, err)
	}
	views, _, err := f.p.StandalonePage(f.s, f.session, 3005, "tenant", "debug", "")
	if err != nil || len(views) != 1 || views[0].RemainingSeconds != 3597 || views[0].Metadata.LastExtension != nil {
		t.Fatal("public TTL did not use extension or exposed signed proof", err)
	}
	if f.p.CheckStandalonePolicy(f.s, standaloneReportCore(t, f, scope, "expire", "ttl", 3602)) || !f.p.CheckStandalonePolicy(f.s, standaloneReportCore(t, f, scope, "expire", "disconnected", 3604)) {
		t.Fatal("extension changed the independent disconnect grace or retained the original TTL deadline")
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Apps(f.s); err != nil {
		t.Fatal("snapshot proof validation", err)
	}
	if applyDownCAS(t, f, command, state.Applied) != result {
		t.Fatal("replay changed original receipt")
	}
	originalResult, err := StandaloneExtensionResult(op)
	if err != nil || originalResult.ProposedExpiresAt != 6602 || originalResult.RemainingExtensionSeconds != 79800 {
		t.Fatal("original numeric outcome was not reproducible", originalResult, err)
	}
}

func sameStandaloneExtensionOperation(a, b UserOperation) bool {
	return bytes.Equal(OperationBytes(a), OperationBytes(b)) && bytes.Equal(a.Signature, b.Signature)
}

func TestStandaloneExtensionRejectsLifecycleScopeAndStaleManagement(t *testing.T) {
	for _, mode := range []string{"fixed", "stopped", "cleanup", "down", "expired", "cap", "shorten", "created", "previous", "scope", "foreign", "target", "future-revision", "future-root", "competing-extension", "competing-pin", "credential", "deploy-scope", "operation-ceiling"} {
		t.Run(mode, func(t *testing.T) {
			lifetime := "temp"
			if mode == "fixed" {
				lifetime = "fixed"
			}
			var f *backupCoreFixture
			var scope string
			if mode == "stopped" {
				f, scope = standaloneStoppedExtensionFixture(t)
			} else {
				f, scope = standaloneCoreFixture(t, lifetime)
			}
			standaloneExtendSession(f, 3000)
			// A fixed object has no expiry. Use a structurally valid frozen
			// temp coordinate so the actual lifecycle gate must refuse it.
			if mode == "fixed" {
				a, _ := f.p.Apps(f.s)
				e := a.entries[appKey("tenant", scope)]
				q := StandaloneExtendChange{Tenant: "tenant", Name: "debug", Scope: scope, Operation: "refused-extension", CreatedAt: 2, PreviousExpiresAt: 3602, TTLSeconds: 3600, Target: e.standaloneTarget()}
				raw, _ := ChangeBytes("standalone-extend", "admin", e.Standalone.Revision, q)
				var change Change
				_ = json.Unmarshal(raw, &change)
				op := UserOperation{Schema: 1, Session: f.session, At: 3002, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "fixed-extension", Change: change}
				op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
				command, err := op.Command()
				if err != nil {
					t.Fatal(err)
				}
				applyDownCAS(t, f, command, state.ConditionFailed)
				return
			}
			op, _ := standaloneExtendIntent(t, f, scope, "refused-extension", 3002, 3600)
			var q StandaloneExtendChange
			_ = json.Unmarshal(op.Change.Payload, &q)
			want := state.ConditionFailed
			switch mode {
			case "expired":
				op.At = 3602
			case "cap":
				q.TTLSeconds = 83401
			case "shorten":
				q.TTLSeconds = 1
			case "created":
				q.CreatedAt++
			case "previous":
				q.PreviousExpiresAt++
			case "scope":
				q.Scope = deployment.StandaloneScopeName("tenant", "foreign")
			case "foreign":
				q.Tenant = "foreign"
				op.Session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Deploy}}}
				op.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(op.Session))
				want = state.Forbidden
			case "target":
				q.Target[0] ^= 1
			case "future-revision":
				op.Change.Expected += 100
			case "future-root":
				op.RootRevision += 100
			case "deploy-scope":
				op.Session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
				op.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(op.Session))
				want = state.Forbidden
			}
			op.Change.Payload, _ = json.Marshal(q)
			op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
			command, err := op.Command()
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "cleanup":
				report := standaloneReportCore(t, f, scope, "expire", "ttl", 3602)
				cleanup, err := report.Command()
				if err != nil {
					t.Fatal(err)
				}
				applyRestartCore(t, f, cleanup, state.Applied)
			case "down":
				_, remove := signedStandaloneCAS(t, f, "standalone-remove", "remove-first", op.Change.Expected, op.RootRevision, StandaloneChange{Tenant: "tenant", Name: "debug", Operation: "remove-first", Target: &q.Target}, true)
				// This independent original remove must be signed with a session
				// valid at its own time, rather than a future renewed credential.
				var earlier UserOperation
				_ = json.Unmarshal([]byte(remove.Value), &earlier)
				earlier.At = 3001
				earlier.Signature = ed25519.Sign(f.admin, OperationBytes(earlier))
				remove, err = earlier.Command()
				if err != nil {
					t.Fatal(err)
				}
				applyDownCAS(t, f, remove, state.Applied)
			case "competing-extension":
				_, first := standaloneExtendIntent(t, f, scope, "extend-first", 3001, 3600)
				applyDownCAS(t, f, first, state.Applied)
			case "competing-pin":
				payload, _ := json.Marshal(StandaloneChange{Tenant: "tenant", Name: "debug", Operation: "pin-first", Target: &q.Target})
				pin := UserOperation{Schema: 1, Session: f.session, At: 3001, Epoch: f.s.ModuleEpoch(), RootRevision: op.RootRevision, RequestID: "pin-first", Change: Change{Schema: 1, Principal: "admin", Action: "standalone-pin", Expected: op.Change.Expected, Payload: payload}}
				pin.Signature = ed25519.Sign(f.admin, OperationBytes(pin))
				first, err := pin.Command()
				if err != nil {
					t.Fatal(err)
				}
				applyDownCAS(t, f, first, state.Applied)
			case "credential", "operation-ceiling":
				// f.apply uses At=2: give that independent user-management
				// command a valid session without changing the original op.
				standaloneExtendSession(f, 1)
				// A key's ceiling is fixed when it is added: the narrower
				// ceiling is a replacement key, the original turned off.
				var ceiling []string
				if mode == "operation-ceiling" {
					ceiling = []string{"standalone-remove"}
				}
				recovery := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{145}, ed25519.SeedSize))
				f.replaceOwnKey("key", "recovery", [32]byte(recovery.Public().(ed25519.PublicKey)), ceiling)
				clear(recovery)
				want = state.Forbidden
			}
			before := f.s.Object(AppsKey)
			applyDownCAS(t, f, command, want)
			if f.s.Object(AppsKey) != before {
				t.Fatal("refused extension changed shared source")
			}
		})
	}
}

func TestStandaloneExtensionUsesCurrentCreatorManagerAndCredentialBoundary(t *testing.T) {
	for _, role := range []access.Role{access.Manager, access.Viewer} {
		t.Run(string(role), func(t *testing.T) {
			f, scope := standaloneCoreFixture(t, "temp")
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{146}, ed25519.SeedSize))
			defer clear(key)
			public := [32]byte(key.Public().(ed25519.PublicKey))
			f.apply("extension-user", "put-user", 0, access.User{ID: "operator", Username: "operator", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: public, Enabled: true}}}, state.Applied)
			// Membership setup uses the existing administrator credential with
			// its required explicit scope; the operator session below remains
			// limited to Read/Deploy for the actual extension assertion.
			f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageMembers)
			f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
			f.apply("extension-membership", "set-membership", 0, access.Membership{Tenant: "tenant", User: "operator", Role: role, Enabled: true}, state.Applied)
			c, _ := f.p.Catalog(f.s)
			apps, _ := f.p.Apps(f.s)
			entry := apps.entries[appKey("tenant", scope)]
			if standaloneActor(c, entry, "operator") != (role == access.Manager) || !standaloneActor(c, entry, "admin") {
				t.Fatal("extension did not reuse original temp delete ownership gate")
			}
			u, _ := c.User("operator")
			f.admin = key
			f.session = access.Session{Schema: 1, ID: "extension-operator", Cluster: f.p.Cluster, User: "operator", Credential: "key", AccountRevision: u.Revision, Key: public, Issuer: [32]byte(f.node.Public().(ed25519.PublicKey)), IssuerEpoch: 1, Scopes: []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read, access.Deploy}}}}
			standaloneExtendSession(f, 3000)
			_, command := standaloneExtendIntent(t, f, scope, "other-user", 3002, 3600)
			want := state.Applied
			if role == access.Viewer {
				want = state.Forbidden
			}
			applyDownCAS(t, f, command, want)
		})
	}
}

func TestStandaloneExtensionKeepsOriginalResultAndProofAfterLaterExtensionAndPin(t *testing.T) {
	f, scope := standaloneCoreFixture(t, "temp")
	standaloneExtendSession(f, 3000)
	first, firstCommand := standaloneExtendIntent(t, f, scope, "first", 3002, 3600)
	firstResult := applyDownCAS(t, f, firstCommand, state.Applied)
	second, secondCommand := standaloneExtendIntent(t, f, scope, "second", 3100, 3600)
	applyDownCAS(t, f, secondCommand, state.Applied)
	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", scope)]
	target := entry.standaloneTarget()
	payload, _ := json.Marshal(StandaloneChange{Tenant: "tenant", Name: "debug", NewName: "kept", Operation: "pin-after-extension", Target: &target})
	pin := UserOperation{Schema: 1, Session: f.session, At: 3200, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "pin-after-extension", Change: Change{Schema: 1, Principal: "admin", Action: "standalone-pin", Expected: entry.Standalone.Revision, Payload: payload}}
	pin.Signature = ed25519.Sign(f.admin, OperationBytes(pin))
	pinCommand, err := pin.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyDownCAS(t, f, pinCommand, state.Applied)
	apps, err = f.p.Apps(f.s)
	entry = apps.entries[appKey("tenant", scope)]
	if err != nil || entry.Standalone.Lifetime != "fixed" || entry.Standalone.Name != "kept" || entry.Standalone.LastExtension == nil || !sameStandaloneExtensionOperation(*entry.Standalone.LastExtension, second) || !sameStandaloneExtensionOperation(standalonePolicyOrigin(entry), pin) {
		t.Fatal("pin replaced extension proof or assigned it policy authority", err)
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Apps(f.s); err != nil {
		t.Fatal("extension proof invalid after pinned snapshot", err)
	}
	before := f.s.Object(AppsKey)
	if applyDownCAS(t, f, firstCommand, state.Applied) != firstResult || f.s.Object(AppsKey) != before {
		t.Fatal("replay changed original receipt or pinned state")
	}
	original, err := StandaloneExtensionResult(first)
	if err != nil || original.ProposedExpiresAt != 6602 || original.MaximumExpiresAt != 86402 || original.RemainingExtensionSeconds != 79800 {
		t.Fatal("later extension/pin rewrote original numeric outcome", original, err)
	}
}

func TestStandaloneExtensionSnapshotRejectsForgedProofAndOwnedCopyMutation(t *testing.T) {
	f, scope := standaloneCoreFixture(t, "temp")
	standaloneExtendSession(f, 3000)
	_, command := standaloneExtendIntent(t, f, scope, "proof", 3002, 3600)
	applyDownCAS(t, f, command, state.Applied)
	for _, mode := range []string{"signature", "created", "expiry", "scope", "tenant", "name", "future-revision", "missing-operation", "missing-proof", "cap"} {
		t.Run(mode, func(t *testing.T) {
			apps, err := f.p.Apps(f.s)
			if err != nil {
				t.Fatal(err)
			}
			entry := apps.entries[appKey("tenant", scope)]
			m := *entry.Standalone
			proof := *m.LastExtension
			var q StandaloneExtendChange
			_ = json.Unmarshal(proof.Change.Payload, &q)
			switch mode {
			case "signature":
				proof.Signature[0] ^= 1
			case "created":
				m.CreatedAt++
			case "expiry":
				m.ExpiresAt++
			case "scope":
				q.Scope = deployment.StandaloneScopeName("tenant", "other")
			case "tenant":
				q.Tenant = "foreign"
			case "name":
				q.Name = "foreign"
			case "future-revision":
				proof.Change.Expected = m.Revision
			case "missing-operation":
				q.Operation = ""
			case "missing-proof":
				m.LastExtension = nil
			case "cap":
				q.TTLSeconds = 86400
			}
			if mode != "signature" {
				proof.Change.Payload, _ = json.Marshal(q)
				proof.Signature = ed25519.Sign(f.admin, OperationBytes(proof))
			}
			if mode != "missing-proof" {
				m.LastExtension = &proof
			}
			entry.Standalone = &m
			apps.entries[appKey("tenant", scope)] = entry
			writes, code := f.p.appsCheckpoint(f.s, apps)
			if code != state.Applied {
				t.Fatal("construct malformed snapshot input", code)
			}
			bad := permitDecodeWrites(t, f.s, AppsKey, writes)
			if _, err := f.p.Apps(bad); err == nil {
				t.Fatal("malformed extension proof restored", mode)
			}
		})
	}
	owned, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := owned.entries[appKey("tenant", scope)]
	entry.Standalone.LastExtension.Signature[0] ^= 1
	if _, err := f.p.Apps(f.s); err != nil {
		t.Fatal("owned extension proof contaminated borrowed snapshot", err)
	}
}

func TestStandaloneExtensionAbsentFieldPreservesLegacyMetadataAndTargetBytes(t *testing.T) {
	f, scope := standaloneCoreFixture(t, "temp")
	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", scope)]
	m := *entry.Standalone
	// This is the exact pre-extension metadata field order and omitempty shape.
	old := struct {
		Name, Scope, Creator, Node         string
		Lifetime, Mode, Restart, Desired   string
		Connections                        int
		DisconnectedAt, ConnectionAt       int64
		Cleanup                            *StandalonePolicyReport `json:",omitempty"`
		Revision                           uint64
		CreatedAt, ExpiresAt, GraceSeconds int64
		LastChange                         *UserOperation `json:",omitempty"`
	}{m.Name, m.Scope, m.Creator, m.Node, m.Lifetime, m.Mode, m.Restart, m.Desired, m.Connections, m.DisconnectedAt, m.ConnectionAt, m.Cleanup, m.Revision, m.CreatedAt, m.ExpiresAt, m.GraceSeconds, m.LastChange}
	legacy, _ := json.Marshal(old)
	current, _ := json.Marshal(m)
	if !bytes.Equal(legacy, current) || bytes.Contains(current, []byte("LastExtension")) {
		t.Fatal("absent optional extension changed schema1 metadata bytes")
	}
	old.Connections, old.ConnectionAt, old.DisconnectedAt, old.Revision = 0, 0, 0, 0
	raw, _ := json.Marshal(struct {
		Scope    deployment.AppScope
		Origin   [32]byte
		Metadata any
		Down     [32]byte
		Controls [][32]byte
		Clears   [][32]byte
	}{entry.Inventory.Scope(), appRegistrationDigest(entry.Origin), old, [32]byte{}, nil, nil})
	legacyTarget := sha256.Sum256(append([]byte("sfc-standalone-target-1\x00"), raw...))
	if legacyTarget != entry.standaloneTarget() {
		t.Fatal("absent extension changed legacy management target")
	}
	for _, mutation := range []string{"no-operation", "zero-target", "zero-expected"} {
		standaloneExtendSession(f, 3000)
		op, _ := standaloneExtendIntent(t, f, scope, "malformed", 3002, 3600)
		var q StandaloneExtendChange
		_ = json.Unmarshal(op.Change.Payload, &q)
		switch mutation {
		case "no-operation":
			q.Operation = ""
		case "zero-target":
			q.Target = [32]byte{}
		case "zero-expected":
			op.Change.Expected = 0
		}
		op.Change.Payload, _ = json.Marshal(q)
		op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
		if _, err := op.Command(); err == nil {
			t.Fatal("new extension admitted missing signed identity/mode", mutation)
		}
	}
}

func TestStandaloneExtensionTotalLifetimeCapIsEnforcedByFSM(t *testing.T) {
	f, scope := standaloneCoreFixture(t, "temp")
	standaloneExtendSession(f, 3000)
	accepted, command := standaloneExtendIntent(t, f, scope, "exact-cap", 3002, 83400)
	applyDownCAS(t, f, command, state.Applied)
	apps, err := f.p.Apps(f.s)
	if err != nil || apps.entries[appKey("tenant", scope)].Standalone.ExpiresAt != 86402 {
		t.Fatal("exact cap was not accepted by original reducer", err)
	}
	for _, refusal := range []struct {
		id   string
		ttl  int64
		want error
	}{{"unchanged-full-cap", 83302, ErrStandaloneExtensionNotIncreased}, {"over-full-cap", 83303, ErrStandaloneExtensionLimit}} {
		op, command := standaloneExtendIntent(t, f, scope, refusal.id, 3100, refusal.ttl)
		plan, err := StandaloneExtensionResult(op)
		if !errors.Is(err, refusal.want) || plan.MaximumExpiresAt != 86402 || plan.AllowedTTLSeconds != 83302 || plan.RemainingExtensionSeconds != 0 {
			t.Fatal("full lifetime lost original numeric remaining bound", plan, err)
		}
		before := f.s.Object(AppsKey)
		applyDownCAS(t, f, command, state.ConditionFailed)
		if f.s.Object(AppsKey) != before {
			t.Fatal("over-cap/unchanged extension changed state")
		}
	}
	if original, err := StandaloneExtensionResult(accepted); err != nil || original.ProposedExpiresAt != 86402 || original.RemainingExtensionSeconds != 0 {
		t.Fatal("later refusals changed accepted result", original, err)
	}
}

func TestStandaloneExtensionSubmissionChecksCurrentExpiryAfterOriginalReceipt(t *testing.T) {
	f, scope := standaloneCoreFixture(t, "temp")
	standaloneExtendSession(f, 3000)
	op, command := standaloneExtendIntent(t, f, scope, "delayed-original", 3002, 3600)
	before := f.s.Object(AppsKey)
	if err := f.p.CheckStandaloneExtensionSubmission(f.s, op, 3601); err != nil {
		t.Fatal("live current temp rejected", err)
	}
	if err := f.p.CheckStandaloneExtensionSubmission(f.s, op, 3602); !errors.Is(err, ErrStandaloneExtensionExpired) {
		t.Fatal("late unconfirmed original bypassed current expiry", err)
	}
	if f.s.Object(AppsKey) != before {
		t.Fatal("submission preflight mutated state")
	}
	for _, mode := range []string{"scope", "name", "tenant", "created", "deploy-scope"} {
		t.Run(mode, func(t *testing.T) {
			bad := op
			var q StandaloneExtendChange
			_ = json.Unmarshal(op.Change.Payload, &q)
			switch mode {
			case "scope":
				q.Scope = deployment.StandaloneScopeName("tenant", "foreign")
			case "name":
				q.Name = "foreign"
			case "tenant":
				q.Tenant = "foreign"
			case "created":
				q.CreatedAt++
			case "deploy-scope":
				bad.Session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
				bad.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(bad.Session))
			}
			bad.Change.Payload, _ = json.Marshal(q)
			bad.Signature = ed25519.Sign(f.admin, OperationBytes(bad))
			if err := f.p.CheckStandaloneExtensionSubmission(f.s, bad, 3602); !errors.Is(err, access.ErrDenied) {
				t.Fatal("preflight disclosed expiry without exact owned scope/current Deploy", err)
			}
		})
	}
	// Apply at the immutable signed time through the actual FSM. The edge
	// check after that committed receipt cannot replace its accepted outcome,
	// even after the later extended deadline or current credential revocation.
	applyDownCAS(t, f, command, state.Applied)
	if err := f.p.CheckStandaloneExtensionSubmission(f.s, op, 6602); err != nil {
		t.Fatal("receipt replay was turned into an expired new submission", err)
	}
	if err := f.p.CheckStandaloneExtensionSubmission(f.s, UserOperation{}, 0); err != nil {
		t.Fatal("non-extension submission changed", err)
	}
	stopped, stoppedScope := standaloneStoppedExtensionFixture(t)
	standaloneExtendSession(stopped, 3000)
	stoppedOp, _ := standaloneExtendIntent(t, stopped, stoppedScope, "stopped-delayed", 3002, 3600)
	if err := stopped.p.CheckStandaloneExtensionSubmission(stopped.s, stoppedOp, 3602); !errors.Is(err, access.ErrDenied) {
		t.Fatal("submission disclosed time error or allowed extension after accepted stop intent", err)
	}
}

func standaloneStoppedExtensionFixture(t *testing.T) (*backupCoreFixture, string) {
	t.Helper()
	f, scope, _ := standaloneNativeCASFixture(t)
	plan, err := f.p.PlanTaskControl(f.s, f.session, 11, "tenant", containerops.Selection{Standalone: "debug"}, "standalone-stop")
	if err != nil {
		t.Fatal(err)
	}
	q := TaskRestartChange{Tenant: "tenant", Standalone: "debug", Operation: "stop-before-extension", Target: plan.Target, ManagementTarget: plan.ManagementTarget}
	q.Selection.Service, q.Selection.Instance = plan.Container.Service, plan.Container.Instance
	_, stop := signedStandaloneCAS(t, f, "standalone-stop", "stop-before-extension", plan.StandaloneRevision, f.s.Object(AppsKey).Revision, q, true)
	applyDownCAS(t, f, stop, state.Applied)
	return f, scope
}
