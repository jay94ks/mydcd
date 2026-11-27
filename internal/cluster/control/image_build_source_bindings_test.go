// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func buildBoundSourceFixture(t *testing.T) (*nodeStorageFixture, ImageBuildJobPlan, []imagebuild.FrozenSource, []ImageBuildSourceBinding) {
	t.Helper()
	f, plan := buildJobFixture(t)
	session := f.sessions["manager"]
	session.Scopes[0].Actions = append(session.Scopes[0].Actions, access.Deploy)
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	rules := append(slices.Clone(tenant.ImageSources), access.TrustRule{Registry: "ghcr.io", Repository: "**"})
	resolveTrust(t, f, rules)
	spec := imagesource.Source{Tenant: "tenant", ID: "source-reader", Authority: "ghcr.io", Repository: "team/**", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{Spec: spec}, state.Applied)
	bind, err := f.p.PlanExternalRegistryBind(f.s, session, 2, "tenant", spec.ID, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "bind-external-registry", bind.Expected, bind.Selection, state.Applied)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	q := buildBaseQuery(plan, "ghcr.io/team/base:latest")
	inputs := []imagebuild.FrozenSource{{Source: q.Source, Image: "ghcr.io/team/base@sha256:" + strings.Repeat("a", 64)}}
	sources, err := f.p.ImageBuildBeginSources(f.s, plan.Spec.Scope.Root.Key, ImageBuildJobWorkQuery{Tenant: "tenant", ID: plan.Spec.ID, At: 3}, inputs)
	if err != nil || len(sources) != 1 || sources[0].External == nil || sources[0].ReadSet == ([32]byte{}) {
		t.Fatal(sources, err)
	}
	return f, plan, inputs, sources
}

// Real FSM/signatures and restore validation; native completion and registry
// I/O are injected. Runtime/SDK/token lifetime is part of RQ6's final batch.
func TestBuildSourceReaderRemainsReservedThroughDrainUnknownCancelAndRestore(t *testing.T) {
	f, plan, inputs, sources := buildBoundSourceFixture(t)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin", Inputs: inputs}, state.Forbidden)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin", Inputs: inputs, Sources: sources}, state.Applied)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "uncertain"}, state.Applied)
	selection := *sources[0].External
	if held, err := f.p.ExternalRegistryImageBuildsPending(f.s, selection); err != nil || !held {
		t.Fatal("running source not reserved", held, err)
	}
	other := selection
	other.Generation++
	if held, err := f.p.ExternalRegistryImageBuildsPending(f.s, other); err != nil || held {
		t.Fatal("another reader generation was pinned", held, err)
	}
	f.apply("manager", "unbind-external-registry", 2, RegistrySelection{Tenant: "tenant", ID: selection.ID}, state.Applied)
	work, err := f.p.ImageBuildJobWork(f.s, plan.Spec.Scope.Root.Key, ImageBuildJobWorkQuery{Tenant: "tenant", ID: plan.Spec.ID, At: 3})
	if err != nil || work.Allowed {
		t.Fatal("drained reader still grants new I/O", work, err)
	}
	f.apply("manager", "cancel-image-build", 3, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, f.s, state.Command{}) != nil {
		t.Fatal("cancelled original reader reference did not restore", err)
	}
	entries, err := f.p.ExternalRegistries(f.s)
	if err != nil || len(entries) != 1 || entries[0].Reader == nil {
		t.Fatal(entries, err)
	}
	reader := entries[0].Reader
	proof := ExternalRegistryReaderClosed{Schema: 1, Cluster: f.p.Cluster, Owner: reader.Owner, Tenant: selection.Tenant, ID: selection.ID, Generation: selection.Generation, Closed: true, At: 3, Index: f.s.Index(), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(ExternalRegistriesKey).Revision}
	proof.Signature = ed25519.Sign(f.node, ExternalRegistryReaderClosedBytes(proof))
	cmd, err := proof.Command()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.ResolveExternalRegistryClose(f.s, reader.Owner, []byte(cmd.Value)); err == nil {
		t.Fatal("zero owner RPCs released a credential still used by the original builder")
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Forbidden {
		t.Fatal("reducer bypassed original build reservation", result, err)
	}
	f.s = next
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "complete", Closure: &closure}, state.Applied)
	if held, err := f.p.ExternalRegistryImageBuildsPending(f.s, selection); err != nil || held {
		t.Fatal("positive original job completion did not release reader", held, err)
	}
	// Fresh envelope after another shared transaction: same original reader,
	// no new bind and no invented Vault usage release.
	proof.Index = f.s.Index()
	proof.Signature = ed25519.Sign(f.node, ExternalRegistryReaderClosedBytes(proof))
	cmd, err = proof.Command()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.ResolveExternalRegistryClose(f.s, reader.Owner, []byte(cmd.Value)); err != nil {
		t.Fatal("closed original job stranded source", err)
	}
	next, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal("source close after actual job settlement", result, err)
	}
	if f.p.Validate(state.State{}, next, state.Command{}) != nil {
		t.Fatal("terminal source history must survive reader removal")
	}
}

func TestBuildBeginRejectsChangedOrUnrelatedSourceBinding(t *testing.T) {
	f, plan, inputs, sources := buildBoundSourceFixture(t)
	for _, edit := range []func(*ImageBuildSourceBinding){
		func(b *ImageBuildSourceBinding) { b.Owner[0] ^= 1 },
		func(b *ImageBuildSourceBinding) { b.ReadSet[0] ^= 1 },
		func(b *ImageBuildSourceBinding) { b.External.Generation++ },
		func(b *ImageBuildSourceBinding) { b.External.Tenant = "foreign" },
		func(b *ImageBuildSourceBinding) { b.External.ID = "other" },
		func(b *ImageBuildSourceBinding) { b.Image = "ghcr.io/team/other@sha256:" + strings.Repeat("a", 64) },
	} {
		raw, _ := json.Marshal(sources)
		var bad []ImageBuildSourceBinding
		if err := json.Unmarshal(raw, &bad); err != nil {
			t.Fatal(err)
		}
		edit(&bad[0])
		buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin", Inputs: inputs, Sources: bad}, state.Forbidden)
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin", Inputs: inputs, Sources: append(slices.Clone(sources), sources[0])}, state.Forbidden)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin", Inputs: inputs, Sources: sources}, state.Applied)
	book, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := book.Job("tenant", plan.Spec.ID)
	if !ok || validateImageBuildJob(row, f.p.Cluster) != nil || len(row.Sources) != 1 || row.Begin == nil || len(row.Begin.Sources) != 0 || len(row.Progress.Sources) != 0 {
		t.Fatal("normalized signed source not stored once", err)
	}
	row.Sources[0].ReadSet[0] ^= 1
	if validateImageBuildJob(row, f.p.Cluster) == nil {
		t.Fatal("restored source no longer authenticated by original begin")
	}
}

func TestManagedBuildInputRetainsItsOwnRegistryAndPullCannotBroadenFrozenInputs(t *testing.T) {
	f, plan := buildJobFixture(t)
	registries, err := f.p.Registries(f.s)
	if err != nil {
		t.Fatal(err)
	}
	output, _ := registries.Entry("tenant", "private")
	base := output.Spec
	base.ID, base.Address, base.Authority = "bases", "0.0.0.0:5444", "bases.example.test:5444"
	base.Volume = volumes.Scope{Cluster: f.p.Cluster, Tenant: "tenant", ID: "base-data", Generation: 1, Registry: base.ID}
	f.apply("manager", "create-volume", 0, volumeFact(t, base.Volume, "node-a", f.node), state.Applied)
	f.apply("manager", "put-registry", 0, RegistryPut{Spec: base}, state.Applied)
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: base.ID, Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: base.ID, Action: "serving", SpecRevision: 1, Generation: 1, Observation: &RegistryObservation{Boot: [32]byte{1}, Certificate: [32]byte{2}}}, state.Applied)
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	resolveTrust(t, f, append(slices.Clone(tenant.ImageSources), access.TrustRule{Registry: base.Authority, Repository: "**"}))
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	source := buildBaseQuery(plan, base.Authority+"/team/base:latest").Source
	inputs := []imagebuild.FrozenSource{{Source: source, Image: base.Authority + "/team/base@sha256:" + strings.Repeat("a", 64)}}
	sources, err := f.p.ImageBuildBeginSources(f.s, plan.Spec.Scope.Root.Key, ImageBuildJobWorkQuery{Tenant: "tenant", ID: plan.Spec.ID, At: 3}, inputs)
	if err != nil || len(sources) != 1 || sources[0].Managed == nil || sources[0].Managed.ID != base.ID {
		t.Fatal(sources, err)
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin", Inputs: inputs, Sources: sources}, state.Applied)
	registries, err = f.p.Registries(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := registries.Entry("tenant", base.ID)
	if held, err := f.p.RegistryImageBuildsPending(f.s, entry.Active.Reference()); err != nil || !held {
		t.Fatal("FROM registry was not retained independently of output", held, err)
	}
	q := ImageBuildRegistryRequest{Tenant: "tenant", Job: plan.Spec.ID, Snapshot: plan.Spec.Digest(), Action: "pull", Image: inputs[0].Image, At: 3}
	if _, err := f.p.ImageBuildRegistryPermit(f.s, plan.Spec.Scope.Root.Key, q); err != nil {
		t.Fatal("original managed pull denied", err)
	}
	q.Image = base.Authority + "/team/other@sha256:" + strings.Repeat("b", 64)
	if _, err := f.p.ImageBuildRegistryPermit(f.s, plan.Spec.Scope.Root.Key, q); err == nil {
		t.Fatal("job authority widened to an unrelated trusted image")
	}
	f.apply("manager", "cancel-image-build", 2, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	if held, err := f.p.RegistryImageBuildsPending(f.s, entry.Active.Reference()); err != nil || !held {
		t.Fatal("cancel released original FROM store", held, err)
	}
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "complete", Closure: &closure}, state.Applied)
	if held, err := f.p.RegistryImageBuildsPending(f.s, entry.Active.Reference()); err != nil || held {
		t.Fatal("FROM store stranded after positive closure", held, err)
	}
}
