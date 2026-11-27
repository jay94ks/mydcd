// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

func nodeShellCore(t *testing.T) *backupCoreFixture {
	t.Helper()
	f, _ := moveCore(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.NodeShell, access.ManageMembers)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	return f
}
func nodeShellSessionFor(t *testing.T, f *backupCoreFixture, user string, key ed25519.PrivateKey, actions ...access.Action) access.Session {
	t.Helper()
	c, _ := f.p.Catalog(f.s)
	u, ok := c.User(user)
	if !ok {
		t.Fatal(user)
	}
	s := f.session
	s.ID = "shell-" + user
	s.User = user
	s.Key = [32]byte(key.Public().(ed25519.PublicKey))
	s.AccountRevision = u.Revision
	s.Scopes = []access.Scope{{Tenant: "*", Actions: actions}}
	s.Signature = ed25519.Sign(f.node, access.SessionBytes(s))
	return s
}
func nodeShellApply(t *testing.T, f *backupCoreFixture, session access.Session, key ed25519.PrivateKey, id, action string, expected uint64, payload any, at int64, want state.Code) (UserOperation, state.Command, state.Result) {
	t.Helper()
	return nodeShellApplyRoot(t, f, session, key, id, action, expected, payload, at, f.s.Object(CommandKey(action)).Revision, want)
}

// nodeShellApplyRoot signs the operation on a given root revision, as a
// client that read the shell book before a node's report moved it.
func nodeShellApplyRoot(t *testing.T, f *backupCoreFixture, session access.Session, key ed25519.PrivateKey, id, action string, expected uint64, payload any, at int64, root uint64, want state.Code) (UserOperation, state.Command, state.Result) {
	t.Helper()
	raw, err := ChangeBytes(action, session.User, expected, payload)
	if err != nil {
		t.Fatal(err)
	}
	var change Change
	_ = json.Unmarshal(raw, &change)
	op := UserOperation{Schema: 1, Session: session, At: at, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: root, Change: change}
	op.Signature = ed25519.Sign(key, OperationBytes(op))
	cmd, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	var result state.Result
	f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal(id, result, want, err)
	}
	return op, cmd, result
}
func nodeShellOwnerReport(t *testing.T, f *backupCoreFixture, key ed25519.PrivateKey, report NodeShellReport, want state.Code) state.Command {
	t.Helper()
	b, err := f.p.NodeShells(f.s)
	if err != nil {
		t.Fatal(err)
	}
	report.Schema = 1
	report.Cluster = f.p.Cluster
	report.Reporter = [32]byte(key.Public().(ed25519.PublicKey))
	report.Epoch = f.s.ModuleEpoch()
	report.RootRevision = f.s.Object(NodeShellKey).Revision
	report.PolicyRevision = b.Policy.Revision
	report.RequestID = fmt.Sprintf("shell-report-%d", f.s.Index())
	if report.Sequence == 0 {
		report.Sequence = 1
		if report.Kind == "ready" {
			for _, old := range b.Readiness {
				if old.Node == report.Node {
					report.Sequence = old.Sequence + 1
				}
			}
		} else {
			old, ok := b.Record(report.SessionID)
			if ok && old.Report != nil {
				report.Sequence = old.Report.Sequence + 1
			}
		}
	}
	report.Signature = ed25519.Sign(key, NodeShellReportBytes(report))
	cmd, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	var result state.Result
	f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal("owner report", report.Kind, result, want, err)
	}
	return cmd
}
func nodeShellEnable(t *testing.T, f *backupCoreFixture, node string, sudo bool) {
	t.Helper()
	b, _ := f.p.NodeShells(f.s)
	f.apply("shell-enable-"+node, "set-node-shell-node", b.Policy.Revision, NodeShellNodeChange{Node: node, Shell: "on", Sudo: sudo}, state.Applied)
	key := f.node
	if node == "node-b" {
		key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
		defer clear(key)
	}
	nodeShellOwnerReport(t, f, key, NodeShellReport{Node: node, Kind: "ready", Ready: true, Sudo: sudo, At: 2}, state.Applied)
}
func nodeShellAlice(t *testing.T, f *backupCoreFixture) ed25519.PrivateKey {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{126}, 32))
	t.Cleanup(func() { clear(key) })
	f.apply("shell-alice", "put-user", 0, access.User{ID: "alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, Enabled: true, PublicKey: [32]byte(key.Public().(ed25519.PublicKey))}}}, state.Applied)
	f.apply("shell-tenant-manager", "set-membership", 0, access.Membership{Tenant: "tenant", User: "alice", Role: access.Manager, Enabled: true}, state.Applied)
	return key
}
func nodeShellGrant(t *testing.T, f *backupCoreFixture, user string, nodes []string) {
	t.Helper()
	b, _ := f.p.NodeShells(f.s)
	f.apply(fmt.Sprintf("shell-grant-%d", f.s.Index()), "set-node-shell-grant", b.Policy.Revision, NodeShellGrantChange{User: user, Nodes: nodes}, state.Applied)
}

func TestNodeShellCoreDefaultOffExactNodeGrantAndCurrentCredential(t *testing.T) {
	f := nodeShellCore(t)
	nodeShellEnable(t, f, "node-b", false)
	aliceKey := nodeShellAlice(t, f)
	nodeShellGrant(t, f, "alice", []string{"node-b"})
	// Grant changes advance policy; readiness must prove that exact current policy.
	keyB := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
	defer clear(keyB)
	nodeShellOwnerReport(t, f, keyB, NodeShellReport{Node: "node-b", Kind: "ready", Ready: true, At: 2}, state.Applied)
	alice := nodeShellSessionFor(t, f, "alice", aliceKey, access.NodeShell, access.Read)
	for _, q := range []struct{ node, code string }{{"node-a", "forbidden"}, {"node-c", "forbidden"}} {
		op, _, _ := nodeShellApply(t, f, alice, aliceKey, "alice-"+q.node, "open-node-shell", 0, NodeShellOpen{Node: q.node, Cols: 80, Rows: 24}, 2, state.Forbidden)
		if NodeShellErrorCode(f.p.CheckNodeShellOpen(f.s, op, 2)) != q.code {
			t.Fatal("tenant manager inferred a host grant")
		}
	}
	_, _, disabled := nodeShellApply(t, f, f.session, f.admin, "admin-disabled", "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.NodeShellDisabled)
	if disabled.Reason != "node-shell-disabled" || !disabled.ValidReason() {
		t.Fatal("cluster default on")
	}
	_, _, _ = nodeShellApply(t, f, alice, aliceKey, "alice-b", "open-node-shell", 0, NodeShellOpen{Node: "node-b", Cols: 80, Rows: 24}, 2, state.Applied)
	b, _ := f.p.NodeShells(f.s)
	row, ok := b.Record("alice-b")
	if !ok || row.Session.State != "queued" || row.Session.OpenedAt != 0 || row.Session.Account != "sfc-shell" || row.Session.Sudo {
		t.Fatal("intent pretended SSH was opened")
	}
	if _, err := f.p.NodeShellPermit(f.s, [32]byte(keyB.Public().(ed25519.PublicKey)), "alice-b", 2); err != nil {
		t.Fatal("exact target owner denied", err)
	}
	if _, err := f.p.NodeShellPermit(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), "alice-b", 2); err == nil {
		t.Fatal("foreign owner acquired original shell")
	}
}

func TestNodeShellCoreOriginalLimitNativeOpenedAndClosedBySignedAdministrator(t *testing.T) {
	f := nodeShellCore(t)
	bobKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{127}, 32))
	defer clear(bobKey)
	f.apply("shell-bob", "put-user", 0, access.User{ID: "bob", Username: "bob", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, Enabled: true, PublicKey: [32]byte(bobKey.Public().(ed25519.PublicKey))}}}, state.Applied)
	nodeShellEnable(t, f, "node-a", false)
	_, original, receipt := nodeShellApply(t, f, f.session, f.admin, "shell-original", "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.Applied)
	for i := 1; i < 4; i++ {
		nodeShellApply(t, f, f.session, f.admin, fmt.Sprintf("shell-other-%d", i), "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.Applied)
	}
	_, _, limited := nodeShellApply(t, f, f.session, f.admin, "shell-limit", "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.NodeShellLimit)
	if limited.Reason != "limit" || !limited.ValidReason() {
		t.Fatal("simultaneous limit not deterministic")
	}
	before := f.s
	var result state.Result
	var err error
	f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, original, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result != receipt {
		t.Fatal("exact original was resubmitted instead of recovered", err)
	}
	if events, err := f.p.NodeShellEvents(before, f.s, original, result); err != nil || len(events) != 0 {
		t.Fatal("duplicate emitted another opened/denied event", err)
	}
	before = f.s
	opened := nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "opened", SessionID: "shell-original", At: 3, LastActivity: 3}, state.Applied)
	openedResult, _ := f.s.LookupResult(opened)
	events, err := f.p.NodeShellEvents(before, f.s, opened, openedResult)
	if err != nil || len(events) != 1 || events[0].Kind != "node-shell-opened" {
		t.Fatal("queued/opened event boundary", err)
	}
	nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "activity", SessionID: "shell-original", At: 4, LastActivity: 4, BytesIn: 2, BytesOut: 10}, state.Applied)
	// Without an accepted close, an owner cannot invent a closing administrator.
	nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "closed", SessionID: "shell-original", At: 5, LastActivity: 4, BytesIn: 2, BytesOut: 10, Reason: "closed"}, state.Invalid)
	bob := nodeShellSessionFor(t, f, "bob", bobKey, access.ManageCluster, access.NodeShell)
	nodeShellApply(t, f, bob, bobKey, "bob-close", "close-node-shell", 0, NodeShellClose{SessionID: "shell-original"}, 5, state.Applied)
	b, _ := f.p.NodeShells(f.s)
	record, _ := b.Record("shell-original")
	if record.Session.State != "closing" || record.Session.End == nil || record.Session.End.ClosedBy == nil || record.Session.End.ClosedBy.User != "bob" || record.Session.ClosedAt != 0 {
		t.Fatal("native exit was inferred or close actor came from owner")
	}
	before = f.s
	closed := nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "closed", SessionID: "shell-original", At: 6, LastActivity: 4, BytesIn: 2, BytesOut: 10, Reason: "closed", Code: 0}, state.Applied)
	closedResult, _ := f.s.LookupResult(closed)
	events, err = f.p.NodeShellEvents(before, f.s, closed, closedResult)
	if err != nil || len(events) != 1 || events[0].Detail.ClosedBy == nil || events[0].Detail.ClosedBy.User != "bob" || events[0].Detail.BytesIn != 2 || events[0].Detail.BytesOut != 10 {
		t.Fatal("closed event lost exact actor/accounting", err)
	}
	b, _ = f.p.NodeShells(f.s)
	record, _ = b.Record("shell-original")
	record.Session.End.ClosedBy.User = "forged"
	again, _ := b.Record("shell-original")
	if again.Session.End.ClosedBy.User != "bob" {
		t.Fatal("public row aliases private origin")
	}
	raw, _ := state.Encode(f.s)
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err = f.p.NodeShells(restored)
	again, _ = b.Record("shell-original")
	if err != nil || again.Session.State != "closed" || again.Session.End.ClosedBy.User != "bob" || again.Opened == nil || again.Opened.At != 3 {
		t.Fatal("snapshot lost original SSH receipt/closed actor", err)
	}
}

func TestNodeShellCorePolicyGrantAndCredentialRevocationCloseOriginalWithoutInventingExit(t *testing.T) {
	for _, kind := range []string{"node-off", "grant", "sudo", "credential"} {
		t.Run(kind, func(t *testing.T) {
			f := nodeShellCore(t)
			aliceKey := nodeShellAlice(t, f)
			nodeShellGrant(t, f, "alice", []string{"node-a"})
			nodeShellEnable(t, f, "node-a", kind == "sudo")
			alice := nodeShellSessionFor(t, f, "alice", aliceKey, access.NodeShell, access.Read)
			nodeShellApply(t, f, alice, aliceKey, "revoked-shell", "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.Applied)
			nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "opened", SessionID: "revoked-shell", At: 3, LastActivity: 3}, state.Applied)
			b, _ := f.p.NodeShells(f.s)
			switch kind {
			case "node-off":
				nodeShellApply(t, f, f.session, f.admin, "turn-shell-off", "set-node-shell-node", b.Policy.Revision, NodeShellNodeChange{Node: "node-a", Shell: "off"}, 4, state.Applied)
			case "grant":
				nodeShellApply(t, f, f.session, f.admin, "revoke-shell-grant", "set-node-shell-grant", b.Policy.Revision, NodeShellGrantChange{User: "alice"}, 4, state.Applied)
			case "sudo":
				nodeShellApply(t, f, f.session, f.admin, "revoke-shell-sudo", "set-node-shell-node", b.Policy.Revision, NodeShellNodeChange{Node: "node-a", Shell: "on", Sudo: false}, 4, state.Applied)
			case "credential":
				c, _ := f.p.Catalog(f.s)
				account, _ := c.User("alice")
				nodeShellApply(t, f, f.session, f.admin, "revoke-shell-credential", "set-account-scope", account.Revision, access.AccountScope{User: "alice", Add: []string{"close-node-shell"}}, 4, state.Applied)
			}
			b, err := f.p.NodeShells(f.s)
			row, _ := b.Record("revoked-shell")
			if err != nil || row.Session.State != "closing" || row.Session.ClosedAt != 0 || row.Session.End.ClosedBy.User != "admin" || row.Session.End.Reason != "policy" {
				t.Fatal("revocation lost signed actor/original lifecycle", err)
			}
			if _, err = f.p.NodeShellPermit(f.s, row.Owner, "revoked-shell", 4); err == nil {
				t.Fatal("revoked original could start/reconnect")
			}
			nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "closed", SessionID: "revoked-shell", At: 5, LastActivity: 3, Reason: "policy"}, state.Applied)
			b, err = f.p.NodeShells(f.s)
			row, _ = b.Record("revoked-shell")
			if err != nil || row.Session.State != "closed" || row.CloseOrigin == nil || row.CloseOrigin.Session.User != "admin" {
				t.Fatal("owner changed close cause", err)
			}
		})
	}
}

func TestNodeShellCoreExitIdleNoActorAndNoScreenMetadata(t *testing.T) {
	f := nodeShellCore(t)
	nodeShellEnable(t, f, "node-a", false)
	for _, id := range []string{"natural-exit", "idle-exit"} {
		nodeShellApply(t, f, f.session, f.admin, id, "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.Applied)
		nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "opened", SessionID: id, At: 3, LastActivity: 3}, state.Applied)
	}
	nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "closed", SessionID: "natural-exit", At: 4, LastActivity: 3, Reason: "exit"}, state.Applied)
	nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "closed", SessionID: "idle-exit", At: 4, LastActivity: 3, Reason: "idle"}, state.ConditionFailed)
	nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "closed", SessionID: "idle-exit", At: 1803, LastActivity: 3, Reason: "idle"}, state.Applied)
	b, _ := f.p.NodeShells(f.s)
	for _, id := range []string{"natural-exit", "idle-exit"} {
		r, _ := b.Record(id)
		if r.Session.End.ClosedBy != nil || r.CloseOrigin != nil || r.Session.State != "closed" {
			t.Fatal("natural exit invented operator")
		}
	}
	// There is no raw screen/keyboard field in any accepted typed request/report.
	raw := []byte(`{"Node":"node-a","Cols":80,"Rows":24,"Data":"secret keystrokes"}`)
	doc, _ := json.Marshal(ChangeDocument{Schema: 1, Action: "open-node-shell", Payload: raw})
	if _, err := InputChange(doc, "admin"); err == nil {
		t.Fatal("screen/keyboard entered the checkpoint")
	}
}

func TestNodeShellCoreViewsFreshnessOwnerProofAndSignedPolicyCAS(t *testing.T) {
	f := nodeShellCore(t)
	aliceKey := nodeShellAlice(t, f)
	nodeShellGrant(t, f, "alice", []string{"node-a"})
	nodeShellEnable(t, f, "node-a", false)
	alice := nodeShellSessionFor(t, f, "alice", aliceKey, access.NodeShell)
	nodeShellApply(t, f, alice, aliceKey, "alice-view", "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.Applied)
	nodeShellApply(t, f, f.session, f.admin, "admin-view", "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.Applied)
	page, err := f.p.NodeShellSessions(f.s, alice, 2, "")
	if err != nil || len(page.Sessions) != 1 || page.Sessions[0].SessionID != "alice-view" {
		t.Fatal("private session enumeration", err)
	}
	all, err := f.p.NodeShellSessions(f.s, f.session, 2, "")
	if err != nil || all.Total != 2 {
		t.Fatal("admin session enumeration", err)
	}
	view, err := f.p.NodeShellPolicy(f.s, alice, 2)
	if err != nil || len(view.Nodes) != 1 || view.Nodes[0].Node != "node-a" || !view.Nodes[0].Ready || len(view.Grants) != 1 || view.Grants[0].User != "alice" {
		t.Fatal("grant-filtered policy", err)
	}
	view, err = f.p.NodeShellPolicy(f.s, alice, 33)
	if err != nil || view.Nodes[0].Ready {
		t.Fatal("stale readiness became actual proof", err)
	}
	raw, _ := json.Marshal(page)
	for _, private := range []string{"Signature", "Origin", "Ready", "Report", "Cols", "Rows", "screen", "keystroke"} {
		if bytes.Contains(raw, []byte(`"`+private+`"`)) {
			t.Fatal("public session exposed private proof/input", private)
		}
	}
	limited := nodeShellSessionFor(t, f, "admin", f.admin, access.Read)
	if _, err = f.p.NodeShellPolicy(f.s, limited, 2); err == nil {
		t.Fatal("limited admin read token became host scope")
	}
	nodeShellApply(t, f, limited, f.admin, "limited-open", "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.Forbidden)
	b, _ := f.p.NodeShells(f.s)
	nodeShellApply(t, f, alice, aliceKey, "tenant-edits-host-policy", "set-node-shell-policy", b.Policy.Revision, NodeShellPolicyChange{Enabled: true, MaxSessions: 4, IdleSeconds: 1800}, 2, state.Forbidden)
	nodeShellApply(t, f, f.session, f.admin, "stale-policy", "set-node-shell-policy", 0, NodeShellPolicyChange{Enabled: true, MaxSessions: 4, IdleSeconds: 1800}, 2, state.ConditionFailed)
	nodeShellApply(t, f, f.session, f.admin, "future-policy", "set-node-shell-policy", b.Policy.Revision+1, NodeShellPolicyChange{Enabled: true, MaxSessions: 4, IdleSeconds: 1800}, 2, state.ConditionFailed)
	if _, err = f.p.NodeShellOwner(f.s, [32]byte(aliceKey.Public().(ed25519.PublicKey)), "node-a"); err == nil {
		t.Fatal("user key read owner work")
	}
	if _, err = f.p.NodeShellOwner(f.s, f.p.TrustRoot, "node-a"); err != nil {
		t.Fatal("current owner cannot read disabled/ready policy", err)
	}
	foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
	defer clear(foreign)
	nodeShellOwnerReport(t, f, foreign, NodeShellReport{Node: "node-a", Kind: "opened", SessionID: "alice-view", At: 3, LastActivity: 3}, state.Forbidden)
	if f.p.storageQuiescent(f.s) {
		t.Fatal("active shell references did not block ledger retirement")
	}
}

func TestNodeShellCoreRejectsForgedSnapshotAndRawRevocation(t *testing.T) {
	f := nodeShellCore(t)
	aliceKey := nodeShellAlice(t, f)
	nodeShellGrant(t, f, "alice", []string{"node-a"})
	nodeShellEnable(t, f, "node-a", false)
	alice := nodeShellSessionFor(t, f, "alice", aliceKey, access.NodeShell)
	nodeShellApply(t, f, alice, aliceKey, "snapshot-shell", "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.Applied)
	nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "opened", SessionID: "snapshot-shell", At: 3, LastActivity: 3}, state.Applied)
	c, _ := f.p.Catalog(f.s)
	account, _ := c.User("alice")
	expected := account.Revision
	scope := access.AccountScope{User: "alice", Add: []string{"close-node-shell"}}
	raw, err := ChangeBytes("set-account-scope", "admin", expected, scope)
	if err != nil {
		t.Fatal(err)
	}
	rawCommand := state.Command{Kind: state.Module, Actor: fmt.Sprintf("%x", f.admin.Public().(ed25519.PublicKey)), Epoch: f.s.ModuleEpoch(), RequestID: "raw-revoke-shell", Key: CatalogKey, Expected: f.s.Object(CatalogKey).Revision, Value: string(raw)}
	// Exercise the legacy raw reducer boundary directly: its caller key is
	// current, but it has no signed UserOperation to record as ClosedBy. The
	// managed FSM also refuses registering this raw actor as a new principal.
	writes, code := f.p.Reduce(f.s, rawCommand)
	if code != state.ConditionFailed || len(writes) != 0 {
		t.Fatal("unsigned catalog change invented close actor", code)
	}
	nodeShellApply(t, f, f.session, f.admin, "signed-revoke-shell", "set-account-scope", expected, scope, 4, state.Applied)
	nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "closed", SessionID: "snapshot-shell", At: 5, LastActivity: 3, Reason: "policy"}, state.Applied)
	base, err := f.p.NodeShells(f.s)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*NodeShellBook){
		"origin-signature":    func(b *NodeShellBook) { b.Records[0].Origin.Signature[0] ^= 1 },
		"readiness-signature": func(b *NodeShellBook) { b.Records[0].Ready.Signature[0] ^= 1 },
		"opened-signature":    func(b *NodeShellBook) { b.Records[0].Opened.Signature[0] ^= 1 },
		"owner":               func(b *NodeShellBook) { b.Records[0].Owner = [32]byte{9} },
		"closed-actor":        func(b *NodeShellBook) { b.Records[0].Session.End.ClosedBy.User = "alice" },
		"closed-display":      func(b *NodeShellBook) { b.Records[0].Session.End.ClosedBy.Username = "admin\nforged" },
		"closed-time":         func(b *NodeShellBook) { b.Records[0].Session.ClosedAt++ },
		"policy-proof":        func(b *NodeShellBook) { b.Changes[0].Signature[0] ^= 1 },
		"policy-account":      func(b *NodeShellBook) { b.Policy.Account = "root" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			book := cloneNodeShell(base)
			mutate(&book)
			writes, code := f.p.nodeShellCheckpoint(f.s, book)
			if code != state.Applied {
				t.Fatal(code)
			}
			// Model malformed durable input, bypassing only its writer. The actual
			// checkpoint decoder and cross-root validator must reject it after restore.
			bad, _, err := state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "tamper-" + name, Key: NodeShellKey, Expected: f.s.Object(NodeShellKey).Revision, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := state.Encode(bad)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := state.Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.p.NodeShells(restored); err == nil {
				t.Fatal("forged snapshot accepted")
			}
		})
	}
}

func TestNodeShellCoreCurrentIdentityCanOnlySettleOriginalHistoricalOwner(t *testing.T) {
	f := nodeShellCore(t)
	nodeShellEnable(t, f, "node-a", false)
	nodeShellApply(t, f, f.session, f.admin, "identity-shell", "open-node-shell", 0, NodeShellOpen{Node: "node-a", Cols: 80, Rows: 24}, 2, state.Applied)
	nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "opened", SessionID: "identity-shell", At: 3, LastActivity: 3}, state.Applied)
	original, _ := f.p.NodeShells(f.s)
	row, _ := original.Record("identity-shell")
	nextKey := rotateRQ9CoreOwner(t, f)
	defer clear(nextKey)
	current := [32]byte(nextKey.Public().(ed25519.PublicKey))
	if _, err := f.p.NodeShellPermit(f.s, current, "identity-shell", 4); err == nil {
		t.Fatal("identity cleanup authority became new SSH permission")
	}
	if _, err := f.p.NodeShellOwner(f.s, row.Owner, "node-a"); err == nil {
		t.Fatal("historical owner authenticated a current owner view")
	}
	nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "closed", SessionID: "identity-shell", At: 4, LastActivity: 3, Reason: "exit"}, state.Forbidden)
	nodeShellOwnerReport(t, f, nextKey, NodeShellReport{Node: "node-a", Kind: "activity", SessionID: "identity-shell", At: 4, LastActivity: 3}, state.ConditionFailed)
	nodeShellOwnerReport(t, f, nextKey, NodeShellReport{Node: "node-a", Kind: "closed", SessionID: "identity-shell", At: 4, LastActivity: 3, Reason: "exit"}, state.Applied)
	book, err := f.p.NodeShells(f.s)
	saved, _ := book.Record("identity-shell")
	if err != nil || saved.Owner != row.Owner || saved.Opened.Reporter != row.Owner || saved.Report.Reporter != current || !bytes.Equal(OperationBytes(saved.Origin), OperationBytes(row.Origin)) || saved.Session.End.ClosedBy != nil {
		t.Fatal("cleanup rewrote original owner/actor", err)
	}
	raw, _ := state.Encode(f.s)
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.NodeShells(restored); err != nil {
		t.Fatal("retained cleanup lineage lost across restore", err)
	}
}

func TestNodeShellCoreRetainsOriginalTypedRefusalsAfterPolicyChangesAndSnapshot(t *testing.T) {
	for _, code := range []state.Code{state.NodeShellDisabled, state.NodeShellNotReady, state.NodeShellLimit, state.NodeShellUnreachable} {
		t.Run(state.RejectionReason(code), func(t *testing.T) {
			f := nodeShellCore(t)
			node := "node-a"
			switch code {
			case state.NodeShellNotReady:
				f.apply("enable-without-ssh-ready", "set-node-shell-node", 0, NodeShellNodeChange{Node: node, Shell: "on"}, state.Applied)
			case state.NodeShellLimit:
				nodeShellEnable(t, f, node, false)
				for i := 0; i < 4; i++ {
					nodeShellApply(t, f, f.session, f.admin, fmt.Sprintf("held-shell-%d", i), "open-node-shell", 0, NodeShellOpen{Node: node, Cols: 80, Rows: 24}, 2, state.Applied)
				}
			case state.NodeShellUnreachable:
				node = "node-c"
			}
			root := f.s.Object(NodeShellKey)
			op, command, refused := nodeShellApply(t, f, f.session, f.admin, "retained-refused-shell", "open-node-shell", 0, NodeShellOpen{Node: node, Cols: 80, Rows: 24}, 2, code)
			if refused.Reason != state.RejectionReason(code) || !refused.ValidReason() || f.s.Object(NodeShellKey) != root {
				t.Fatal("open refusal lost original typed reason or changed shell state", refused)
			}
			book, err := f.p.NodeShells(f.s)
			if err != nil {
				t.Fatal(err)
			}
			f.apply("new-shell-policy-after-refusal", "set-node-shell-policy", book.Policy.Revision, NodeShellPolicyChange{Enabled: true, MaxSessions: 16, IdleSeconds: 1800}, state.Applied)
			nodeShellOwnerReport(t, f, f.node, NodeShellReport{Node: "node-a", Kind: "ready", Ready: true, At: 2}, state.Applied)
			// The first three refusals are now admissible under current policy.
			// That fresh decision must never replace the retained original result.
			if code != state.NodeShellUnreachable && f.p.CheckNodeShellOpen(f.s, op, 2) != nil {
				t.Fatal("fixture did not change the fresh decision after original refusal")
			}
			raw, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			f.s, err = state.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if result, found := f.s.LookupResult(command); !found || result != refused {
				t.Fatal("snapshot lost original node shell refusal", result)
			}
			root = f.s.Object(NodeShellKey)
			var result state.Result
			f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
			if err != nil || result != refused || f.s.Object(NodeShellKey) != root {
				t.Fatal("replay replaced original typed refusal with current policy decision", result, err)
			}
			book, err = f.p.NodeShells(f.s)
			_, accepted := book.Record(op.RequestID)
			if err != nil || accepted {
				t.Fatal("rejected original replay allocated a queued/native session", err)
			}
		})
	}
}

// A node's readiness report moves the shell book's root revision. A user
// operation signed on the root it read just before still applies: the
// policy changes carry their own CAS (the policy revision) and an open is
// checked against the current readiness. A root from the future does not.
func TestNodeShellUserOperationsSurviveANodeReportMovingTheRoot(t *testing.T) {
	f := nodeShellCore(t)
	nodeShellEnable(t, f, "node-b", false)
	keyB := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
	defer clear(keyB)
	read := f.s.Object(NodeShellKey).Revision
	nodeShellOwnerReport(t, f, keyB, NodeShellReport{Node: "node-b", Kind: "ready", Ready: true, At: 2}, state.Applied)
	if f.s.Object(NodeShellKey).Revision == read {
		t.Fatal("the readiness report did not move the root")
	}
	b, _ := f.p.NodeShells(f.s)
	nodeShellApplyRoot(t, f, f.session, f.admin, "stale-root-policy", "set-node-shell-node", b.Policy.Revision, NodeShellNodeChange{Node: "node-b", Shell: "on", Sudo: true}, 2, read, state.Applied)
	// the policy CAS still holds
	nodeShellApplyRoot(t, f, f.session, f.admin, "stale-policy", "set-node-shell-node", b.Policy.Revision, NodeShellNodeChange{Node: "node-b", Shell: "on"}, 2, f.s.Object(NodeShellKey).Revision, state.ConditionFailed)
	read = f.s.Object(NodeShellKey).Revision
	nodeShellOwnerReport(t, f, keyB, NodeShellReport{Node: "node-b", Kind: "ready", Ready: true, Sudo: true, At: 2}, state.Applied)
	nodeShellApplyRoot(t, f, f.session, f.admin, "stale-root-open", "open-node-shell", 0, NodeShellOpen{Node: "node-b", Cols: 80, Rows: 24}, 2, read, state.Applied)
	nodeShellApplyRoot(t, f, f.session, f.admin, "future-root", "open-node-shell", 0, NodeShellOpen{Node: "node-b", Cols: 80, Rows: 24}, 2, f.s.Object(NodeShellKey).Revision+1, state.ConditionFailed)
}
