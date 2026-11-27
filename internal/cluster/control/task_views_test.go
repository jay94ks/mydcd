// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/observability"
)

// These native facts are signed model inputs to the real product FSM. Actual
// Docker/two-node behavior remains part of the RQ3 final adapter verification.
func TestTaskPagesFilterBeforePagingAndNeverPromoteStaleEvidence(t *testing.T) {
	f, o, selection := logClearPlanFixture(t, "local")
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageMembers)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	o.Sequence++
	o.TaskFact = &containerops.TaskFact{Name: "owned-native", State: "running", RestartCount: 3, LastCheck: &containerops.TaskCheck{Checker: "docker-health", Status: "pass", At: o.At}}
	o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
	managedDNSTaskCoreProgress(t, f, "source-app", "observe", o.Key, &o)
	page, err := f.p.TaskPage(f.s, f.session, 10, TaskSelection{Tenant: "tenant", App: selection.App, Node: "node-a"}, "")
	if err != nil || len(page.Tasks) != 1 || page.RootRevision != f.s.Object(AppsKey).Revision {
		t.Fatal("task projection", err, len(page.Tasks))
	}
	row := page.Tasks[0]
	if row.TaskID != o.Key || row.Service != "web" || row.Observed != "running" || row.Container != o.Native || row.RestartCount == nil || *row.RestartCount != 3 || row.ContainerName != "owned-native" || row.LastCheck == nil {
		t.Fatal("wrong original task/fact", row)
	}
	network := false
	for _, ref := range row.Resources {
		network = network || ref.Kind == "network" && ref.Name == "services" && ref.Borrowed
	}
	if !network {
		t.Fatal("managed network reference lost", row.Resources)
	}
	raw, _ := json.Marshal(page)
	for _, private := range []string{"Signature", "Session", "VerifierRef", "Config", "Environment"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private configuration in task page", private)
		}
	}
	row.Resources[0].Name = "changed"
	row.LastCheck.Status = "fail"
	again, err := f.p.TaskPage(f.s, f.session, 10, TaskSelection{Tenant: "tenant"}, "")
	if err != nil || again.Tasks[0].LastCheck.Status != "pass" {
		t.Fatal("projection aliases committed source", err)
	}
	stale, err := f.p.TaskPage(expireAll(t, f.p, f.s, f.node, o.At+AppObservationMaxAge+1), f.session, int64(o.At+AppObservationMaxAge+1), TaskSelection{Tenant: "tenant"}, "")
	if err != nil || stale.Tasks[0].Observed != "unknown" || stale.Tasks[0].RestartCount != nil || stale.Tasks[0].ObservedAt != o.At {
		t.Fatal("stale observation became running/current count", err)
	}
	for _, q := range []TaskSelection{{Node: "other-node"}, {Tenant: "tenant", App: "other-app"}} {
		got, err := f.p.TaskPage(f.s, f.session, 10, q, "")
		if err != nil || len(got.Tasks) != 0 {
			t.Fatal("filter ignored", q, err)
		}
	}
	limited := f.session
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Deploy}}}
	limited.Signature = ed25519.Sign(f.node, access.SessionBytes(limited))
	if _, err = f.p.TaskPage(f.s, limited, 10, TaskSelection{}, ""); !errors.Is(err, access.ErrDenied) {
		t.Fatal("non-read session saw task existence", err)
	}
	if _, err = f.p.TaskPage(f.s, f.session, 10, TaskSelection{Tenant: "foreign"}, ""); !errors.Is(err, access.ErrDenied) {
		t.Fatal("foreign tenant selection", err)
	}
	// Same opaque position cannot be moved to a different selector or state.
	basis := taskCursorBasis(f.s, f.session, TaskSelection{Tenant: "tenant"})
	cursor := nextTaskCursor(basis, 0)
	if _, err = f.p.TaskPage(f.s, f.session, 10, TaskSelection{Tenant: "tenant", App: "source-app"}, cursor); !errors.Is(err, access.ErrConflict) {
		t.Fatal("cursor changed query", err)
	}
	o.Sequence++
	copy := o.TaskFact.Clone()
	o.TaskFact = &copy
	o.TaskFact.State = "exited"
	o.Healthy = false
	o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
	managedDNSTaskCoreProgress(t, f, "source-app", "observe", o.Key, &o)
	if _, err = f.p.TaskPage(f.s, f.session, 10, TaskSelection{Tenant: "tenant"}, cursor); !errors.Is(err, access.ErrConflict) {
		t.Fatal("cursor mixed root revisions", err)
	}
	exited, err := f.p.TaskPage(f.s, f.session, 10, TaskSelection{Tenant: "tenant"}, "")
	if err != nil || exited.Tasks[0].Observed != "exited" {
		t.Fatal("signed actual state ignored", err)
	}
	f.apply("task-reader", "put-user", 0, access.User{ID: "reader", Username: "reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(f.admin.Public().(ed25519.PublicKey)), Enabled: true}}}, state.Applied)
	f.apply("task-reader-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: "reader", Role: access.Viewer, Enabled: true}, state.Applied)
	catalog, _ := f.p.Catalog(f.s)
	user, _ := catalog.User("reader")
	reader := f.session
	reader.User = "reader"
	reader.AccountRevision = user.Revision
	reader.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	reader.Signature = ed25519.Sign(f.node, access.SessionBytes(reader))
	visible, err := f.p.TaskPage(f.s, reader, 10, TaskSelection{Node: "node-a"}, "")
	if err != nil || len(visible.Tasks) != 1 {
		t.Fatal("read-only viewer cannot see own task", err)
	}
	hidden, err := f.p.TaskPage(f.s, reader, 10, TaskSelection{Node: "other-node"}, "")
	if err != nil || len(hidden.Tasks) != 0 || hidden.Next != "" {
		t.Fatal("node filter leaked hidden rows/cursor", err)
	}
}

func TestTaskProjectionIncludesAcceptedUncollectedSourcesAndFrozenNetworkNames(t *testing.T) {
	f, _, _ := logClearPlanFixture(t, "local")
	apps, err := f.p.ReadApps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := apps.entries[appKey("tenant", "source-app")]
	claims := entry.Inventory.Claims()
	withoutTasks := []deployment.Claim{}
	for _, claim := range claims {
		if claim.Step.Kind != "task" {
			withoutTasks = append(withoutTasks, claim)
		}
	}
	candidates, err := acceptedTaskCandidates(f.s, apps, entry.Inventory.Scope(), withoutTasks)
	if err != nil || len(candidates) != 1 || candidates[0].native != "" || candidates[0].observation != nil || candidates[0].goal.Kind != "task" {
		t.Fatal("accepted Task was hidden or native evidence invented before collection", candidates, err)
	}
	// A claim at a newer generation of the same alias is not the original
	// Task's dependency. Keep the original reference even when both exist.
	for _, claim := range withoutTasks {
		if claim.Step.Kind != "network-ref" {
			continue
		}
		var changed deployment.NetworkReference
		if json.Unmarshal(claim.Step.Goal, &changed) != nil {
			t.Fatal("network fixture")
		}
		changed.ManagedName = "another-generation"
		claim.Result.Generation++
		claim.Result.Revision++
		claim.Step.Goal, _ = json.Marshal(changed)
		withoutTasks = append([]deployment.Claim{claim}, withoutTasks...)
		break
	}
	ref, err := taskNetworkReference(f.s, candidates[0].goal, "lan", withoutTasks)
	if err != nil || ref.Name != "services" || !ref.Borrowed {
		t.Fatal("later reference renamed original Task dependency", ref, err)
	}
}

// Process measurement is not a replacement for the control Start witness.
func TestTaskMeasurementShowsRestartWithoutRewritingControlEvidence(t *testing.T) {
	f, o, _ := logClearPlanFixture(t, "local")
	before, _ := state.Encode(f.s)
	fact := containerops.TaskFact{Name: "exact-native", Image: "sha256:actual", State: "running", RestartCount: 2}
	task := observability.Task{Tenant: "tenant", App: "source-app", Deployment: "deploy", Key: o.Key, Native: o.Native, Generation: o.Generation, Revision: o.Revision, Fact: fact, StartedAt: "2026-11-21T00:00:00Z"}
	report := observability.Report{Kind: "node-observation", Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Key: [32]byte(f.node.Public().(ed25519.PublicKey)), Index: f.s.Index(), At: 10000, Task: &task}
	report.Signature = ed25519.Sign(f.node, observability.SigningBytes(report))
	if !report.Valid() {
		t.Fatal("task measurement fixture")
	}
	page, err := f.p.TaskPage(f.s, f.session, 10, TaskSelection{Tenant: "tenant"}, "", []observability.Report{report})
	if err != nil || len(page.Tasks) != 1 || page.Tasks[0].Observed != "running" || page.Tasks[0].ImageID != "sha256:actual" || page.Tasks[0].RestartCount == nil || *page.Tasks[0].RestartCount != 2 {
		t.Fatal("signed live diagnostic", err, page)
	}
	after, _ := state.Encode(f.s)
	if !bytes.Equal(before, after) {
		t.Fatal("read diagnostic changed lifecycle FSM")
	}
	task.Generation++
	report.Signature = ed25519.Sign(f.node, observability.SigningBytes(report))
	unrelated, err := f.p.TaskPage(f.s, f.session, 10, TaskSelection{Tenant: "tenant"}, "", []observability.Report{report})
	if err != nil || len(unrelated.Tasks) != 1 || unrelated.Tasks[0].ImageID == "sha256:actual" {
		t.Fatal("measurement crossed original generation", err)
	}
}

func TestTaskEndpointProjectionUsesFreshExactOwnerFacts(t *testing.T) {
	for _, mode := range []string{"legacy", "unknown", "present", "absent", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f, o, _ := logClearPlanFixture(t, "local")
			o.Sequence++
			o.TaskFact = &containerops.TaskFact{Name: "exact-owned", State: "running"}
			var want *bool
			if mode == "present" || mode == "absent" {
				present := mode == "present"
				o.TaskFact.EndpointPresent, want = &present, &present
			}
			if mode == "unknown" {
				present := true
				o.TaskFact.State, o.Healthy, o.TaskFact.EndpointPresent = "unknown", false, &present
			}
			if mode == "missing" {
				o.TaskFact.State, o.Healthy = "missing", false
				present := false
				want = &present
			}
			o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
			managedDNSTaskCoreProgress(t, f, "source-app", "observe", o.Key, &o)
			page, err := f.p.TaskPage(f.s, f.session, 10, TaskSelection{Tenant: "tenant"}, "")
			if err != nil || len(page.Tasks) != 1 {
				t.Fatal(page, err)
			}
			row := page.Tasks[0]
			if (row.EndpointPresent == nil) != (want == nil) || want != nil && *row.EndpointPresent != *want {
				t.Fatal("unknown/absent/present endpoint evidence conflated", mode, row)
			}
			raw, _ := json.Marshal(row)
			if bytes.Contains(raw, []byte("EndpointPresent")) != (want != nil) {
				t.Fatal("legacy unknown changed optional JSON shape", mode)
			}
			if row.EndpointPresent != nil {
				*row.EndpointPresent = !*row.EndpointPresent
				again, err := f.p.TaskPage(f.s, f.session, 10, TaskSelection{Tenant: "tenant"}, "")
				if err != nil || again.Tasks[0].EndpointPresent == nil || *again.Tasks[0].EndpointPresent != *want {
					t.Fatal("Task projection aliases signed endpoint proof", err)
				}
			}
			stale, err := f.p.TaskPage(expireAll(t, f.p, f.s, f.node, o.At+AppObservationMaxAge+1), f.session, int64(o.At+AppObservationMaxAge+1), TaskSelection{Tenant: "tenant"}, "")
			if err != nil || stale.Tasks[0].EndpointPresent != nil || stale.Tasks[0].Observed != "unknown" {
				t.Fatal("stale endpoint proof became current/absent", err)
			}
		})
	}
}

func TestTaskEndpointNewerMeasurementReplacesAndClearsOlderProof(t *testing.T) {
	f, o, _ := logClearPlanFixture(t, "local")
	present := true
	o.Sequence++
	o.TaskFact = &containerops.TaskFact{Name: "exact-owned", State: "running", EndpointPresent: &present}
	o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
	managedDNSTaskCoreProgress(t, f, "source-app", "observe", o.Key, &o)
	before, _ := state.Encode(f.s)
	for _, mode := range []string{"legacy", "unknown", "present", "absent", "missing", "future", "stale", "foreign-generation"} {
		t.Run(mode, func(t *testing.T) {
			fact := containerops.TaskFact{Name: "current-owner", State: "running"}
			at, now := uint64(11000), int64(11)
			want := (*bool)(nil)
			switch mode {
			case "unknown":
				value := true
				fact.State, fact.EndpointPresent = "unknown", &value
			case "present", "absent", "stale", "foreign-generation":
				value := mode != "absent"
				fact.EndpointPresent = &value
				want = &value
				if mode == "stale" {
					now, want = 42, nil
				}
			case "missing":
				fact.State = "missing"
				value := false
				want = &value
			case "future":
				at = 12000
			}
			task := observability.Task{Tenant: "tenant", App: "source-app", Deployment: "deploy", Key: o.Key, Native: o.Native, Generation: o.Generation, Revision: o.Revision, Fact: fact}
			if mode == "foreign-generation" {
				task.Generation++
				task.Revision++
			}
			report := observability.Report{Kind: "node-observation", Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Key: [32]byte(f.node.Public().(ed25519.PublicKey)), Index: f.s.Index(), At: at, Task: &task}
			report.Signature = ed25519.Sign(f.node, observability.SigningBytes(report))
			if !report.Valid() {
				t.Fatal("invalid signed measurement fixture")
			}
			page, err := f.p.TaskPage(f.s, f.session, now, TaskSelection{Tenant: "tenant"}, "", []observability.Report{report})
			if err != nil || len(page.Tasks) != 1 || (page.Tasks[0].EndpointPresent == nil) != (want == nil) || want != nil && *page.Tasks[0].EndpointPresent != *want {
				t.Fatal("newer/unknown/stale/foreign report reused old endpoint proof", mode, page, err)
			}
		})
	}
	after, _ := state.Encode(f.s)
	if !bytes.Equal(before, after) {
		t.Fatal("endpoint projection changed lifecycle state")
	}
}
