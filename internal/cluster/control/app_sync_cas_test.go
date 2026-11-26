// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"

	"gopkg.in/yaml.v3"
)

func syncCASFixture(t *testing.T) *backupCoreFixture {
	t.Helper()
	f := deliveryControlFixture(t)
	stopUnsentDeliveryForHistory(t, f)
	a, _ := f.p.Apps(f.s)
	d, _ := a.Delivery("tenant", "source-app")
	q := AppCDChange{Tenant: "tenant", App: "source-app"}
	f.apply("resume-idle", "resume-app-cd", d.Revision(), q, state.Applied)
	a, _ = f.p.Apps(f.s)
	d, _ = a.Delivery("tenant", "source-app")
	f.apply("replan-idle", "replan-app", d.Revision(), q, state.Applied)
	return f
}

func syncCASSelection(t *testing.T, f *backupCoreFixture) (AppCDChange, uint64) {
	t.Helper()
	a, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := a.entries[appKey("tenant", "source-app")]
	v := appCDView(entry)
	if v == nil || v.Candidate == nil || v.Target == ([32]byte{}) {
		t.Fatal("missing public target")
	}
	return AppCDChange{Tenant: "tenant", App: "source-app", Target: &v.Target,
		Choice: &AppDeliveryChoice{Operation: "selected-sync", Candidate: v.Candidate.Candidate, Registration: v.Registration}}, v.Revision
}

func signedSyncCAS(t *testing.T, f *backupCoreFixture, id, action string, root, expected uint64, q AppCDChange) (UserOperation, state.Command) {
	t.Helper()
	raw, err := ChangeBytes(action, "admin", expected, q)
	if err != nil {
		t.Fatal(err)
	}
	var change Change
	if json.Unmarshal(raw, &change) != nil {
		t.Fatal("change")
	}
	op := UserOperation{Schema: 1, Session: f.session, At: 11, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: root, Change: change}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	cmd, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	return op, cmd
}

func publishSyncCASSource(t *testing.T, f *backupCoreFixture, id string, body []byte) {
	t.Helper()
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
	a, _ := f.p.Apps(f.s)
	d, _ := a.Delivery("tenant", "source-app")
	ticket, _ := d.FetchTicket()
	source := AppDeliveryInput{Ticket: ticket, Upload: id, Commit: strings.Repeat("2", 40)}
	begin := AppUploadBegin{Tenant: "tenant", App: "source-app", Deployment: "deploy", ID: id, Length: len(body), Digest: sha256.Sum256(body)}
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "input", Ticket: &ticket, Input: &source, Begin: &begin}, state.Applied)
	for index, at := 0, 0; at < len(body); index, at = index+1, at+deployment.ArtifactPartBytes {
		part := AppUploadPart{Tenant: "tenant", ID: id, Index: index, Data: body[at:min(at+deployment.ArtifactPartBytes, len(body))]}
		deliveryControlProgress(t, f, AppDeliveryProgress{Action: "part", Ticket: &ticket, Part: &part}, state.Applied)
	}
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "received", Ticket: &ticket}, state.Applied)
}

func syncCASBody(t *testing.T, f *backupCoreFixture) []byte {
	t.Helper()
	a, _ := f.p.Apps(f.s)
	d, _ := a.Delivery("tenant", "source-app")
	b, _ := d.CandidateBlueprint()
	raw, _ := b.Encode()
	var record struct{ Input deployment.Compose }
	if json.Unmarshal(raw, &record) != nil {
		t.Fatal("blueprint")
	}
	body, err := yaml.Marshal(record.Input)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestAppSyncCASBookkeepingStrictModeAndSnapshotOriginalResult(t *testing.T) {
	f := syncCASFixture(t)
	body := syncCASBody(t, f)
	publishSyncCASSource(t, f, "first-read", body)
	q, revision := syncCASSelection(t, f)
	root := f.s.Object(AppsKey).Revision
	op, cmd := signedSyncCAS(t, f, "target-sync", "sync-app", root, revision, q)
	strict := q
	strict.Target = nil
	_, legacyRoot := signedSyncCAS(t, f, "strict-root", "sync-app", root, revision, strict)
	publishSyncCASSource(t, f, "same-read", body)
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
	current, advanced := syncCASSelection(t, f)
	if *current.Target != *q.Target || advanced <= revision || cmd.Kind != state.ModuleAppCAS || legacyRoot.Kind != state.Module {
		t.Fatal("source bookkeeping changed execution intent or CAS mode")
	}
	applyDownCAS(t, f, legacyRoot, state.ConditionFailed)
	_, legacyRevision := signedSyncCAS(t, f, "strict-revision", "sync-app", f.s.Object(AppsKey).Revision, revision, strict)
	applyDownCAS(t, f, legacyRevision, state.ConditionFailed)
	result := applyDownCAS(t, f, cmd, state.Applied)
	wire, err := state.EncodeCommand(cmd)
	decoded, decodeErr := state.DecodeCommand(wire)
	if err != nil || decodeErr != nil || decoded != cmd || op.VerifyOriginal(f.p.Cluster) != nil {
		t.Fatal("signed mode/target changed on wire", err, decodeErr)
	}
	a, err := f.p.Apps(f.s)
	entry := a.entries[appKey(q.Tenant, q.App)]
	if err != nil || entry.Sync == nil || entry.Sync.User == nil || !bytes.Equal(OperationBytes(*entry.Sync.User), OperationBytes(op)) {
		t.Fatal("accepted sync lost its original signature/target", err)
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil || applyDownCAS(t, f, cmd, state.Applied) != result {
		t.Fatal("snapshot lost original receipt", err)
	}
	if _, err := f.p.Apps(f.s); err != nil {
		t.Fatal("restored sync proof", err)
	}
	_, stale := signedSyncCAS(t, f, "stale-sync", "sync-app", f.s.Object(AppsKey).Revision, revision, q)
	applyDownCAS(t, f, stale, state.ConditionFailed)
}

func TestAppSyncCASTargetIgnoresHealthFreshness(t *testing.T) {
	f, _ := fieldCASFixture(t)
	q, revision := syncCASSelection(t, f)
	fieldCASObservation(t, f)
	current, advanced := syncCASSelection(t, f)
	if *current.Target != *q.Target || current.Choice.Candidate != q.Choice.Candidate || advanced <= revision {
		t.Fatal("same execution's fresh observation changed intent")
	}
}

func TestAppSyncCASRejectsChangedIntent(t *testing.T) {
	for _, change := range []string{"candidate", "policy", "pause", "execution", "retirement", "override", "registration"} {
		t.Run(change, func(t *testing.T) {
			f := syncCASFixture(t)
			var field AppCDField
			if change == "override" || change == "retirement" {
				f, field = fieldCASFixture(t)
			}
			q, revision := syncCASSelection(t, f)
			_, original := signedSyncCAS(t, f, "original-sync", "sync-app", f.s.Object(AppsKey).Revision, revision, q)
			a, _ := f.p.Apps(f.s)
			d, _ := a.Delivery(q.Tenant, q.App)
			switch change {
			case "candidate":
				publishSyncCASSource(t, f, "new-candidate", append([]byte("# changed source\n"), syncCASBody(t, f)...))
			case "policy":
				p := d.Policy()
				p.Poll++
				f.apply("policy", "configure-app-cd", d.Revision(), AppCDChange{Tenant: q.Tenant, App: q.App, Policy: &p, PolicyRevision: d.PolicyRevision()}, state.Applied)
			case "pause":
				f.apply("pause", "pause-app-cd", d.Revision(), AppCDChange{Tenant: q.Tenant, App: q.App}, state.Applied)
			case "execution":
				strict := q
				strict.Target = nil
				strict.Choice = &AppDeliveryChoice{Operation: "other-sync", Candidate: q.Choice.Candidate, Registration: q.Choice.Registration}
				f.apply("other-sync", "sync-app", revision, strict, state.Applied)
			case "retirement":
				i, _ := a.Inventory(q.Tenant, q.App)
				f.apply("down", "down-app", i.Revision(), AppDown{Tenant: q.Tenant, App: q.App, Operation: "stop-source"}, state.Applied)
			case "override":
				_, cmd := signedFieldCAS(t, f, "override", f.s.Object(AppsKey).Revision, field.Revision, AppOverrideChange{Tenant: q.Tenant, App: q.App, Path: field.Path, Value: []byte(`"0.2"`), Refs: field.Refs, Target: &field.Target}, true)
				applyDownCAS(t, f, cmd, state.Applied)
			case "registration":
				entry := a.entries[appKey(q.Tenant, q.App)]
				entry.Origin.RequestID = "replaced-registration"
				entry.Origin.Signature = ed25519.Sign(f.admin, OperationBytes(entry.Origin))
				a.entries[appKey(q.Tenant, q.App)] = entry
				writes, code := f.p.appsCheckpoint(f.s, a)
				if code != state.Applied {
					t.Fatal(code)
				}
				var err error
				f.s, _, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "replacement", Key: AppsKey, Expected: f.s.Object(AppsKey).Revision, Value: "mock"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
				if err != nil {
					t.Fatal(err)
				}
			}
			current, _ := syncCASSelection(t, f)
			if *current.Target == *q.Target {
				t.Fatal("actual intent changed without changing target")
			}
			before := f.s.Object(AppsKey)
			applyDownCAS(t, f, original, state.ConditionFailed)
			if f.s.Object(AppsKey) != before {
				t.Fatal("rejected original changed replacement")
			}
		})
	}
}

func TestAppSyncCASRejectsFutureCoordinatesAndRevokedScope(t *testing.T) {
	for _, name := range []string{"future-root", "future-revision", "wrong-target", "no-current-cd"} {
		t.Run(name, func(t *testing.T) {
			f := syncCASFixture(t)
			q, revision := syncCASSelection(t, f)
			root, want := f.s.Object(AppsKey).Revision, state.ConditionFailed
			switch name {
			case "future-root":
				root++
			case "future-revision":
				revision++
			case "wrong-target":
				q.Target[0] ^= 1
			case "no-current-cd":
				f.session.Scopes[0].Actions = []access.Action{access.Read, access.Deploy}
				f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
				want = state.Forbidden
			}
			_, cmd := signedSyncCAS(t, f, "reject", "sync-app", root, revision, q)
			applyDownCAS(t, f, cmd, want)
		})
	}
}

func TestAppSyncCASLegacyBytesAndSignedTargetStayExact(t *testing.T) {
	f := syncCASFixture(t)
	q, revision := syncCASSelection(t, f)
	op, _ := signedSyncCAS(t, f, "selected", "recover-app", f.s.Object(AppsKey).Revision, revision, q)
	if !AppSyncCASAllowed(op.Change) {
		t.Fatal("recover did not select target CAS")
	}
	for _, mode := range []string{"target", "action"} {
		bad := op
		switch mode {
		case "target":
			altered := q
			target := *q.Target
			target[0] ^= 1
			altered.Target = &target
			bad.Change.Payload, _ = json.Marshal(altered)
		case "action":
			bad.Change.Action = "sync-app"
		}
		if bad.VerifyOriginal(f.p.Cluster) == nil {
			t.Fatal("changed signed intent accepted", mode)
		}
	}
	q.Target = nil
	legacy := struct {
		Tenant, App    string
		Choice         *AppDeliveryChoice              `json:",omitempty"`
		Policy         *deployment.DeliveryDeclaration `json:",omitempty"`
		PolicyRevision uint64                          `json:",omitempty"`
	}{Tenant: q.Tenant, App: q.App, Choice: q.Choice}
	old, _ := json.Marshal(legacy)
	now, _ := json.Marshal(q)
	if !bytes.Equal(old, now) {
		t.Fatal("nil target changed legacy payload bytes")
	}
	strict, cmd := signedSyncCAS(t, f, "legacy", "sync-app", f.s.Object(AppsKey).Revision, revision, q)
	if cmd.Kind != state.Module || strict.VerifyOriginal(f.p.Cluster) != nil {
		t.Fatal("legacy signed mode changed")
	}
}

func TestAppConfigureTargetCASIgnoresObservationsAndPreservesStrictReceipt(t *testing.T) {
	f, _ := fieldCASFixture(t)
	a, _ := f.p.Apps(f.s)
	v := appCDView(a.entries[appKey("tenant", "source-app")])
	policy := v.Policy
	policy.Poll++
	q := AppCDChange{Tenant: "tenant", App: "source-app", Policy: &policy, PolicyRevision: v.PolicyRevision, Target: &v.Target}
	root := f.s.Object(AppsKey).Revision
	op, cmd := signedSyncCAS(t, f, "configure-target", "configure-app-cd", root, v.Revision, q)
	legacy := q
	legacy.Target = nil
	_, strict := signedSyncCAS(t, f, "configure-strict", "configure-app-cd", root, v.Revision, legacy)
	fieldCASObservation(t, f)
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
	managedDNSTaskCoreBegin(t, f, "unrelated-configure", "10.80.1.11", "unrelated")
	a, _ = f.p.Apps(f.s)
	current := appCDView(a.entries[appKey(q.Tenant, q.App)])
	if current.Target != v.Target || current.Revision <= v.Revision || cmd.Kind != state.ModuleAppCAS || AppSyncCASAllowed(op.Change) || !AppCDTargetCASAllowed(op.Change) {
		t.Fatal("configuration intent or signed mode changed with observation")
	}
	rejected := applyDownCAS(t, f, strict, state.ConditionFailed)
	result := applyDownCAS(t, f, cmd, state.Applied)
	a, _ = f.p.Apps(f.s)
	after := appCDView(a.entries[appKey(q.Tenant, q.App)])
	if after.PolicyRevision != v.PolicyRevision+1 || after.Policy.Poll != policy.Poll || op.Change.Expected != v.Revision || op.RootRevision != root {
		t.Fatal("policy was not changed once under its original coordinates")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil || applyDownCAS(t, f, cmd, state.Applied) != result || applyDownCAS(t, f, strict, state.ConditionFailed) != rejected {
		t.Fatal("snapshot changed original configuration results", err)
	}
	_, stale := signedSyncCAS(t, f, "configure-stale-policy", "configure-app-cd", f.s.Object(AppsKey).Revision, v.Revision, q)
	applyDownCAS(t, f, stale, state.ConditionFailed)
}

func TestAppConfigureTargetCASRejectsChangedIntentAndInvalidAuthority(t *testing.T) {
	for _, test := range []string{"health-then-strict", "policy", "pause", "wrong-target", "future-root", "future-revision", "wrong-policy-revision", "revoked"} {
		t.Run(test, func(t *testing.T) {
			f, _ := fieldCASFixture(t)
			a, _ := f.p.Apps(f.s)
			v := appCDView(a.entries[appKey("tenant", "source-app")])
			policy := v.Policy
			policy.Poll++
			q := AppCDChange{Tenant: "tenant", App: "source-app", Policy: &policy, PolicyRevision: v.PolicyRevision, Target: &v.Target}
			root, revision := f.s.Object(AppsKey).Revision, v.Revision
			want := state.ConditionFailed
			switch test {
			case "health-then-strict":
				q.Target = nil
				fieldCASObservation(t, f)
				root = f.s.Object(AppsKey).Revision
			case "policy":
				f.apply("other-policy", "configure-app-cd", v.Revision, AppCDChange{Tenant: q.Tenant, App: q.App, Policy: &policy, PolicyRevision: v.PolicyRevision}, state.Applied)
			case "pause":
				f.apply("other-pause", "pause-app-cd", v.Revision, AppCDChange{Tenant: q.Tenant, App: q.App}, state.Applied)
			case "wrong-target":
				v.Target[0] ^= 1
			case "future-root":
				root++
			case "future-revision":
				revision++
			case "wrong-policy-revision":
				q.PolicyRevision++
			case "revoked":
				f.session.Scopes[0].Actions = []access.Action{access.Read, access.Deploy}
				f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
				want = state.Forbidden
			}
			_, cmd := signedSyncCAS(t, f, "configure-denied", "configure-app-cd", root, revision, q)
			before := f.s.Object(AppsKey)
			applyDownCAS(t, f, cmd, want)
			if f.s.Object(AppsKey) != before {
				t.Fatal("rejected configuration changed app state")
			}
		})
	}
}

func TestAppReplanTargetCASIgnoresObservationsAndPreservesStrictReceipt(t *testing.T) {
	f, _ := fieldCASFixture(t)
	a, _ := f.p.Apps(f.s)
	v := appCDView(a.entries[appKey("tenant", "source-app")])
	q := AppCDChange{Tenant: "tenant", App: "source-app", Target: &v.Target}
	root := f.s.Object(AppsKey).Revision
	op, cmd := signedSyncCAS(t, f, "replan-target", "replan-app", root, v.Revision, q)
	legacy := q
	legacy.Target = nil
	_, strict := signedSyncCAS(t, f, "replan-strict", "replan-app", root, v.Revision, legacy)
	fieldCASObservation(t, f)
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
	managedDNSTaskCoreBegin(t, f, "unrelated-replan", "10.80.1.11", "unrelated")
	a, _ = f.p.Apps(f.s)
	current := appCDView(a.entries[appKey(q.Tenant, q.App)])
	if current.Target != v.Target || current.Revision <= v.Revision || cmd.Kind != state.ModuleAppCAS || AppSyncCASAllowed(op.Change) || !AppCDTargetCASAllowed(op.Change) {
		t.Fatal("reconsideration intent or signed mode changed with observation")
	}
	rejected := applyDownCAS(t, f, strict, state.ConditionFailed)
	result := applyDownCAS(t, f, cmd, state.Applied)
	a, _ = f.p.Apps(f.s)
	after := appCDView(a.entries[appKey(q.Tenant, q.App)])
	if after.PolicyRevision != v.PolicyRevision || after.Candidate == nil || after.Candidate.Candidate == v.Candidate.Candidate || after.Candidate.Intent != v.Candidate.Intent || op.Change.Expected != v.Revision || op.RootRevision != root {
		t.Fatal("policy was not changed once under its original coordinates")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil || applyDownCAS(t, f, cmd, state.Applied) != result || applyDownCAS(t, f, strict, state.ConditionFailed) != rejected {
		t.Fatal("snapshot changed original reconsideration results", err)
	}
	_, stale := signedSyncCAS(t, f, "replan-stale-candidate", "replan-app", f.s.Object(AppsKey).Revision, v.Revision, q)
	applyDownCAS(t, f, stale, state.ConditionFailed)
}

func TestAppReplanTargetCASRejectsChangedIntentAndAuthority(t *testing.T) {
	for _, name := range []string{"candidate", "policy", "pause", "wrong-target", "future-root", "future-revision", "revoked"} {
		t.Run(name, func(t *testing.T) {
			f, _ := fieldCASFixture(t)
			apps, _ := f.p.Apps(f.s)
			v := appCDView(apps.entries[appKey("tenant", "source-app")])
			q := AppCDChange{Tenant: "tenant", App: "source-app", Target: &v.Target}
			root, revision := f.s.Object(AppsKey).Revision, v.Revision
			want := state.ConditionFailed
			switch name {
			case "candidate":
				body := syncCASBody(t, f)
				publishSyncCASSource(t, f, "new-replan-source", append(body, []byte("\n# a new commit\n")...))
			case "policy":
				policy := v.Policy
				policy.Poll++
				f.apply("replan-new-policy", "configure-app-cd", v.Revision, AppCDChange{Tenant: q.Tenant, App: q.App, Policy: &policy, PolicyRevision: v.PolicyRevision}, state.Applied)
			case "pause":
				f.apply("replan-new-pause", "pause-app-cd", v.Revision, AppCDChange{Tenant: q.Tenant, App: q.App}, state.Applied)
			case "wrong-target":
				v.Target[0] ^= 1
			case "future-root":
				root++
			case "future-revision":
				revision++
			case "revoked":
				f.session.Scopes[0].Actions = []access.Action{access.Read, access.Deploy}
				f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
				want = state.Forbidden
			}
			_, command := signedSyncCAS(t, f, "stale-replan", "replan-app", root, revision, q)
			before := f.s.Object(AppsKey)
			applyDownCAS(t, f, command, want)
			if f.s.Object(AppsKey) != before {
				t.Fatal("rejected reconsideration mutated app state")
			}
		})
	}
}
