// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"gopkg.in/yaml.v3"
)

type deliveryFixture struct {
	*executionFixture
	d       Delivery
	ctx     PlanningContext
	repo    *git.Repository
	fs      billy.Filesystem
	body    []byte
	commits int64
}

func deliveryBody(t *testing.T, mode string) []byte {
	t.Helper()
	c := smallCompose(t)
	c.Networks = map[string]ComposeNetwork{"app": {External: true, Name: "shared-services"}}
	c.MyDC.Delivery = &DeliveryDeclaration{}
	p := c.MyDC.Delivery
	p.Enabled = true
	p.Source.Kind = "git"
	p.Source.Repository = "https://git.mydc.test/tenant/app.git"
	p.Source.Ref = "refs/heads/main"
	p.Source.Path = "app.yaml"
	p.Source.Credential = "git-read"
	p.Sync.Mode = mode
	if err := c.normalize(); err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func newDeliveryFixture(t *testing.T, mode string) *deliveryFixture {
	t.Helper()
	return newDeliveryFixturePolicy(t, mode, "report")
}
func newDeliveryFixturePolicy(t *testing.T, mode, drift string) *deliveryFixture {
	t.Helper()
	base, _, ctx := managedNetworkFixture(t)
	shared, err := state.New("submitter")
	if err != nil {
		t.Fatal(err)
	}
	// Model already committed management sources in the SAME shared state.
	// Subsequent app commands cannot erase their identity from Current.
	for _, key := range mapKeys(ctx.Current) {
		value := ctx.Current[key].Value
		command := state.Command{Kind: state.Module, Actor: "submitter", Epoch: 1, RequestID: "management-" + requestID("source", key), Key: key, Value: "fixture"}
		var result state.Result
		shared, result, err = state.ApplyReduced(shared, shared.Index()+1, command, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
			return map[string][]byte{key: []byte(value)}, state.Applied
		})
		if err != nil || result.Code != state.Applied {
			t.Fatal("modeled management source", result, err)
		}
	}
	ctx.Current = shared.Objects("")
	ctx.Features["git-cd"] = true
	body := deliveryBody(t, mode)
	input, err := ParseCompose(body)
	if err != nil {
		t.Fatal(err)
	}
	input.MyDC.Delivery.Sync.Drift = drift
	body, err = yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDelivery(base.c, ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	b := Blueprint{d.d.Candidate.Plan}
	e, err := NewExecution(b, base.c, ctx, "operation", "submitter", 1)
	if err != nil {
		t.Fatal(err)
	}
	x := &executionFixture{f: base, b: b, e: e, shared: shared, now: 100}
	fs := memfs.New()
	repo, err := git.Init(memory.NewStorage(), fs)
	if err != nil {
		t.Fatal(err)
	}
	f := &deliveryFixture{x, d, ctx, repo, fs, body, 0}
	f.saveDelivery(d, nil)
	return f
}
func (f *deliveryFixture) saveDelivery(d Delivery, err error) {
	f.f.t.Helper()
	if err != nil {
		f.f.t.Fatal(err)
	}
	raw, err := d.Encode()
	if err != nil {
		f.f.t.Fatal("delivery encode", err)
	}
	f.d, err = DecodeDelivery(raw)
	if err != nil {
		f.f.t.Fatal("delivery decode", err)
	}
}
func (f *deliveryFixture) commit(body []byte) string {
	f.f.t.Helper()
	file, err := f.fs.Create("app.yaml")
	if err != nil {
		f.f.t.Fatal(err)
	}
	if _, err = file.Write(body); err != nil {
		f.f.t.Fatal(err)
	}
	file.Close()
	w, err := f.repo.Worktree()
	if err != nil {
		f.f.t.Fatal(err)
	}
	if _, err = w.Add("app.yaml"); err != nil {
		f.f.t.Fatal(err)
	}
	f.commits++
	h, err := w.Commit("source", &git.CommitOptions{Author: &object.Signature{Name: "fixture", Email: "fixture@mydc.test", When: time.Unix(f.commits, 0)}})
	if err != nil {
		f.f.t.Fatal(err)
	}
	return h.String()
}
func (f *deliveryFixture) fetch() DeliveryFetch {
	f.f.t.Helper()
	d, ticket, err := f.d.Fetch(f.d.Revision(), f.f.c, f.ctx)
	f.saveDelivery(d, err)
	return ticket
}
func (f *deliveryFixture) receive(body []byte) string {
	f.f.t.Helper()
	commit := f.commit(body)
	ticket := f.fetch()
	input, err := ReadDeliveryInput(f.repo, ticket, commit, "app.yaml", 4<<20)
	if err != nil {
		f.f.t.Fatal(err)
	}
	f.saveDelivery(f.d.Received(f.d.Revision(), f.f.c, f.ctx, input))
	return commit
}
func (f *deliveryFixture) approve() {
	f.f.t.Helper()
	id, _ := f.d.Candidate()
	f.saveDelivery(f.d.Approve(f.d.Revision(), f.f.c, f.ctx, "alice", id))
}
func (f *deliveryFixture) start(id string) {
	f.f.t.Helper()
	f.saveDelivery(f.d.Start(f.d.Revision(), f.f.c, f.ctx, id, "submitter", 1))
	f.e, _ = f.d.Inventory().Execution()
	f.b = Blueprint{f.e.d.Plan}
}
func (f *deliveryFixture) syncDelivery() {
	f.f.t.Helper()
	f.saveDelivery(f.d.AdvanceExecution(f.d.Revision(), f.e, f.shared))
	f.ctx.Current = f.shared.Objects("")
}
func (f *deliveryFixture) completeDelivery() {
	f.f.t.Helper()
	for _, s := range f.b.Steps() {
		f.completeStep(s.Key)
	}
	f.save(f.e.Finish(f.e.Revision(), f.now))
	f.syncDelivery()
}
func deliveryRaw(t *testing.T, d Delivery) []byte {
	t.Helper()
	raw, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDeliveryManualApprovalPinsExactCandidateAndSameExecution(t *testing.T) {
	f := newDeliveryFixture(t, "manual")
	first := f.receive(f.body)
	status, err := f.d.Status(f.f.c, f.ctx, 100)
	if err != nil || status.Operation != "AwaitingApproval" || status.Source != "ChangeAvailable" {
		t.Fatal(status, err)
	}
	before := deliveryRaw(t, f.d)
	if _, err = f.d.Start(f.d.Revision(), f.f.c, f.ctx, "first", "submitter", 1); err == nil {
		t.Fatal("manual source mutated without approval")
	}
	if !bytes.Equal(before, deliveryRaw(t, f.d)) {
		t.Fatal("failed start changed source")
	}
	f.approve()
	secondBody := append([]byte("# second source\n"), f.body...)
	second := f.receive(secondBody)
	if first == second {
		t.Fatal("branch did not advance")
	}
	if _, err = f.d.Start(f.d.Revision(), f.f.c, f.ctx, "first", "submitter", 1); err == nil {
		t.Fatal("old approval accepted new raw/commit")
	}
	f.approve()
	f.start("first")
	if f.d.d.Running.Candidate.Artifact.Commit != second {
		t.Fatal("selected mutable source")
	}
	if f.d.d.Inventory.Active.Operation != "first" {
		t.Fatal("CD did not reuse Inventory execution")
	}
}
func TestDeliverySourceFailureRetainsLastCandidateAndNeverMeansEmpty(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	original, _ := f.d.Candidate()
	f.start("first")
	ticket := f.fetch()
	if _, err := ReadDeliveryInput(f.repo, ticket, "HEAD", "app.yaml", 4<<20); err == nil {
		t.Fatal("mutable source accepted")
	}
	if _, err := ReadDeliveryInput(f.repo, ticket, strings.Repeat("0", 40), "app.yaml", 4<<20); err == nil {
		t.Fatal("missing source accepted")
	}
	f.saveDelivery(f.d.SourceFailed(f.d.Revision(), ticket, "missing"))
	after, _ := f.d.Candidate()
	if original != after || f.d.d.Running.Operation != "first" || f.d.d.Inventory.Active == nil {
		t.Fatal("source failure deleted candidate/running")
	}
	status, err := f.d.Status(f.f.c, f.ctx, 100)
	if err != nil || status.Source != "SourceError" {
		t.Fatal(status, err)
	}
	if _, err = f.d.SourceFailed(f.d.Revision(), ticket, "missing"); err == nil {
		t.Fatal("old fetch result consumed twice")
	}
	ticket = f.fetch()
	if _, err = f.d.SourceFailed(f.d.Revision(), ticket, "token=private-error"); err == nil {
		t.Fatal("private transport text entered shared state")
	}
	bad := DeliveryInput{ticket, deliveryArtifact{Kind: "git", Commit: strings.Repeat("a", 40), Path: "app.yaml", Body: []byte("services: {}\n"), Digest: sha256.Sum256([]byte("services: {}\n"))}}
	if _, err = f.d.Received(f.d.Revision(), f.f.c, f.ctx, bad); err == nil {
		t.Fatal("invalid source treated as application removal")
	}
}
func TestDeliveryNewestQueuedCommitPreservesOriginalUnknownOnHandoff(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	originalCommit := f.receive(f.body)
	f.start("first")
	key := f.b.Steps()[0].Key
	original := f.prepare(key)
	f.send(key)
	f.save(f.e.Unknown(f.e.Revision(), key))
	f.syncDelivery()
	f.receive(append([]byte("# queued second\n"), f.body...))
	latest := f.receive(append([]byte("# queued latest\n"), f.body...))
	if f.d.d.Candidate.Artifact.Commit != latest || f.d.d.Running.Candidate.Artifact.Commit != originalCommit {
		t.Fatal("queue overwrote original input")
	}
	if _, err := f.d.Start(f.d.Revision(), f.f.c, f.ctx, "second", "submitter", 1); err == nil {
		t.Fatal("unknown original replaced")
	}
	f.saveDelivery(DecodeDelivery(deliveryRaw(t, f.d)))
	e, _ := f.d.Inventory().Execution()
	s, _ := e.Stage(key)
	if s.Command == nil || *s.Command != original || e.Status() != "Unknown" {
		t.Fatal("handoff lost exact unknown original")
	}
	result := f.apply(original)
	f.save(f.e.Commit(f.e.Revision(), key, original, result))
	f.syncDelivery()
	if f.d.d.Candidate.Artifact.Commit != latest || f.d.d.Running.Candidate.Artifact.Commit != originalCommit {
		t.Fatal("late result acknowledged newest source")
	}
}
func TestDeliveryDesiredSyncIsIndependentOfNativeHealthAndCompletion(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	f.start("first")
	// Commit declarations through the existing executor; it still requires
	// exact owner observations and activation readiness for its own progress.
	f.completeDelivery()
	status, err := f.d.Status(f.f.c, f.ctx, f.now)
	if err != nil || status.Sync != "InSync" || status.Operation != "Succeeded" || status.Health != "Healthy" {
		t.Fatal(status, err)
	}
	status, err = f.d.Status(f.f.c, f.ctx, f.now+100)
	if err != nil || status.Sync != "InSync" || status.Operation != "Succeeded" {
		t.Fatal("expired health changed immutable completion/sync", status, err)
	}
	if e, _ := f.d.Inventory().Execution(); expired(e).Health(f.now+100) != "Unknown" {
		t.Fatal("expired owner facts remained current health")
	}
}
func TestDeliveryPermissionRevocationAndStaleCASCannotStartOrFetch(t *testing.T) {
	f := newDeliveryFixture(t, "manual")
	f.receive(f.body)
	f.approve()
	if _, err := f.d.Start(f.d.Revision()-1, f.f.c, f.ctx, "first", "submitter", 1); err == nil {
		t.Fatal("stale delivery CAS")
	}
	m, _ := f.f.c.Membership("tenant", "alice")
	var err error
	f.f.c, err = f.f.c.SetMembership("admin", m.Revision, access.Membership{Tenant: "tenant", User: "alice", Role: access.Manager, Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.Start(f.d.Revision(), f.f.c, f.ctx, "first", "submitter", 1); err == nil {
		t.Fatal("revoked principal started")
	}
	if _, _, err = f.d.Fetch(f.d.Revision(), f.f.c, f.ctx); err == nil {
		t.Fatal("revoked principal fetched")
	}
}
func TestDeliverySourceCannotGrantDifferentTenantPolicyOrCredential(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	for _, change := range []func(*Compose){func(c *Compose) { c.MyDC.Delivery.Source.Credential = "wider" }, func(c *Compose) { c.MyDC.Delivery.Sync.Prune = true }} {
		c, err := ParseCompose(f.body)
		if err != nil {
			t.Fatal(err)
		}
		change(&c)
		body, _ := yaml.Marshal(c)
		commit := f.commit(body)
		ticket := f.fetch()
		input, err := ReadDeliveryInput(f.repo, ticket, commit, "app.yaml", 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		before := deliveryRaw(t, f.d)
		if _, err = f.d.Received(f.d.Revision(), f.f.c, f.ctx, input); err == nil {
			t.Fatal("Git self-authorized scope or policy")
		}
		if !bytes.Equal(before, deliveryRaw(t, f.d)) {
			t.Fatal("bad source partially published")
		}
		f.saveDelivery(f.d.SourceFailed(f.d.Revision(), ticket, "policy"))
	}
}
func TestDeliveryPauseKeepsUnknownAndStopsPollingAndNewSubmission(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	f.start("first")
	key := f.b.Steps()[0].Key
	original := f.prepare(key)
	f.send(key)
	f.save(f.e.Unknown(f.e.Revision(), key))
	f.syncDelivery()
	f.saveDelivery(f.d.Pause(f.d.Revision(), f.f.c, "alice", true, f.shared))
	if _, _, err := f.d.Fetch(f.d.Revision(), f.f.c, f.ctx); err == nil {
		t.Fatal("paused controller polled")
	}
	e, _ := f.d.Inventory().Execution()
	stage, _ := e.Stage(key)
	if stage.Command == nil || *stage.Command != original || e.Status() != "Unknown" {
		t.Fatal("pause erased original unknown")
	}
	result := f.apply(original)
	f.e = e
	f.save(f.e.Commit(f.e.Revision(), key, original, result))
	f.syncDelivery()
	f.saveDelivery(f.d.Pause(f.d.Revision(), f.f.c, "alice", false, f.shared))
}
func TestDeliverySnapshotRejectsErasedOriginalArtifactOperationAndApproval(t *testing.T) {
	f := newDeliveryFixture(t, "manual")
	f.receive(f.body)
	f.approve()
	f.start("first")
	key := f.b.Steps()[0].Key
	f.prepare(key)
	f.send(key)
	f.save(f.e.Unknown(f.e.Revision(), key))
	f.syncDelivery()
	raw := deliveryRaw(t, f.d)
	for _, change := range []func(*deliveryRecord){
		func(r *deliveryRecord) { r.Running = nil },
		func(r *deliveryRecord) { r.Running.Candidate.Artifact.Body = nil },
		func(r *deliveryRecord) { r.Running.Operation = "other" },
		func(r *deliveryRecord) { r.Candidate.ID[0]++ },
		func(r *deliveryRecord) { r.Inventory.Active.Stages[0].Journal.Pending = nil },
		func(r *deliveryRecord) {
			r.Approval = &deliveryApproval{Actor: "alice", Candidate: [32]byte{1}, CatalogRevision: r.CatalogFloor}
		},
	} {
		var record deliveryRecord
		json.Unmarshal(raw, &record)
		change(&record)
		bad, _ := json.Marshal(record)
		if _, err := DecodeDelivery(bad); err == nil {
			t.Fatal("incomplete original snapshot accepted")
		}
	}
	body := f.d.d.Running.Candidate.Artifact.Body
	if len(body) == 0 || !bytes.Equal(body, f.body) {
		t.Fatal("handoff requires a mutable ref fetch")
	}
}
func TestDeliveryNativeOrDesiredAbsenceCannotAuthorizeFreshGeneration(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	f.start("first")
	f.completeDelivery()
	f.saveDelivery(f.d.Replan(f.d.Revision(), f.f.c, f.ctx))
	key := ResourceKey("task", "tenant", "php-mysql", "db")
	current := f.ctx.Current[key]
	delete(f.ctx.Current, key)
	f.saveDelivery(f.d.Replan(f.d.Revision(), f.f.c, f.ctx))
	before := deliveryRaw(t, f.d)
	if _, err := f.d.Start(f.d.Revision(), f.f.c, f.ctx, "second", "submitter", 1); err == nil {
		t.Fatal("absence invented a new generation without original native closure")
	}
	if !bytes.Equal(before, deliveryRaw(t, f.d)) {
		t.Fatal("absence reset original inventory")
	}
	f.ctx.Current[key] = current
}

func TestDeliveryBlankNetworkCatalogAndLocalFileDefaultsRemainValid(t *testing.T) {
	f := makeFixture(t)
	ctx := contextFor(t, f)
	if ctx.Networks.Revision() != 0 {
		t.Fatal("initial catalog was not blank")
	}
	c := smallCompose(t)
	c.Networks = nil
	for name, service := range c.Services {
		service.Networks = nil
		c.Services[name] = service
	}
	web := c.Services["web"]
	web.CPUs, web.Memory, web.MyDC.Node = "", "", ""
	c.Services["web"] = web
	ctx.DefaultNode = "node-a"
	volume := c.Volumes["mysql-data"]
	volume.MyDC.Node = ""
	c.Volumes["mysql-data"] = volume
	body, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDelivery(f.c, ctx, body); err == nil {
		t.Fatal("blank management catalog created an unbound container network")
	}
	// A blank cluster is valid, but an app must borrow an explicitly prepared
	// network. Test ordinary file defaults with that actual input contract.
	f, c, ctx, _ = externalFixture(t)
	ctx.DefaultNode = "node-a"
	web = c.Services["web"]
	web.CPUs, web.Memory, web.MyDC.Node = "", "", ""
	c.Services["web"] = web
	body, err = yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDelivery(f.c, ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	raw := deliveryRaw(t, d)
	restored, err := DecodeDelivery(raw)
	if err != nil {
		t.Fatal(err)
	}
	if restored.d.NetworkFloor != ctx.Networks.Revision() || restored.d.Policy.Enabled || restored.d.Policy.Sync.Mode != "manual" || restored.d.Candidate.Plan.Input.Services["web"].MyDC.Node != "node-a" {
		t.Fatal("blank catalog/local delivery defaults changed")
	}
	if _, _, err = restored.Fetch(restored.Revision(), f.c, ctx); err == nil {
		t.Fatal("plain Compose deployment polled Git")
	}
}

func TestDeliveryExplicitSourceChangeFencesOldFetchApprovalAndKeepsOriginal(t *testing.T) {
	f := newDeliveryFixture(t, "manual")
	original := f.receive(f.body)
	f.approve()
	f.start("first")
	oldTicket := f.fetch()
	oldInput, err := ReadDeliveryInput(f.repo, oldTicket, original, "app.yaml", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	updated := f.d.d.Policy
	updated.Source.Credential = "new-read-profile"
	f.saveDelivery(f.d.Configure(f.d.Revision(), f.d.d.PolicyRevision, f.f.c, f.ctx, "alice", updated))
	if f.d.d.Running.Candidate.Artifact.Commit != original || f.d.d.Running.Operation != "first" || f.d.d.Inventory.Active.Operation != "first" {
		t.Fatal("reconfiguration erased accepted original")
	}
	if _, err = f.d.Received(f.d.Revision(), f.f.c, f.ctx, oldInput); err == nil {
		t.Fatal("old source read published under new credential registration")
	}
	if _, err = f.d.Start(f.d.Revision(), f.f.c, f.ctx, "second", "submitter", 1); err == nil {
		t.Fatal("last valid source treated as newly authorized")
	}
	status, err := f.d.Status(f.f.c, f.ctx, 100)
	if err != nil || status.Sync != "Unknown" {
		t.Fatal(status, err)
	}
	c, err := ParseCompose(f.body)
	if err != nil {
		t.Fatal(err)
	}
	c.MyDC.Delivery = &updated
	body, _ := yaml.Marshal(c)
	commit := f.receive(body)
	if f.d.d.Candidate.Artifact.Commit != commit || f.d.d.Candidate.PolicyRevision != 2 || f.d.d.Running.Candidate.PolicyRevision != 1 {
		t.Fatal("source policy epochs mixed")
	}
}
func TestDeliveryMalformedPolicyAndForeignNetworkCatalogAreRejected(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	for _, change := range []func(*DeliveryDeclaration){func(p *DeliveryDeclaration) { p.Source.Repository = "https://name:password@git.mydc.test/app" }, func(p *DeliveryDeclaration) { p.Limits.Active = 2 }, func(p *DeliveryDeclaration) { p.Source.Path = "../app.yaml" }} {
		policy := f.d.d.Policy
		change(&policy)
		if _, err := f.d.Configure(f.d.Revision(), f.d.d.PolicyRevision, f.f.c, f.ctx, "alice", policy); err == nil {
			t.Fatal("bad source policy accepted")
		}
	}
	ctx := f.ctx
	ctx.Cluster = [32]byte{99}
	if _, err := NewDelivery(f.f.c, ctx, f.body); err == nil {
		t.Fatal("foreign network root used by registration")
	}
	if _, _, err := f.d.Fetch(f.d.Revision(), f.f.c, ctx); err == nil {
		t.Fatal("foreign cluster fetched source")
	}
}

// External management changes are modeled as committed Desired metadata only;
// no fake observation is synthesized for the changed revision.
func (f *deliveryFixture) editDesired(key string, change func(*GoalCommand)) {
	f.f.t.Helper()
	old := f.shared.Object(key)
	var g GoalCommand
	if json.Unmarshal([]byte(old.Value), &g) != nil {
		f.f.t.Fatal("missing original goal")
	}
	change(&g)
	result := f.apply(state.Command{Actor: "submitter", Epoch: 1, RequestID: "runtime-edit", Kind: state.Mutate, Key: key, Expected: old.Revision, Value: string(goal(g))})
	if result.Code != state.Applied || result.Generation != old.Generation {
		f.f.t.Fatal("runtime edit changed original generation", result)
	}
	f.ctx.Current = f.shared.Objects("")
}
func changeTaskImage(g *GoalCommand) {
	var service ComposeService
	json.Unmarshal(g.Config, &service)
	service.Image = "docker.io/library/mysql@sha256:" + strings.Repeat("b", 64)
	g.Config = goal(service)
}
func TestDeliveryReportDoesNotRewriteDriftOrReuseOldHealthy(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	f.start("first")
	f.completeDelivery()
	key := ResourceKey("task", "tenant", "php-mysql", "db")
	f.editDesired(key, changeTaskImage)
	f.receive(append([]byte("# unchanged source intent\n"), f.body...))
	status, err := f.d.Status(f.f.c, f.ctx, f.now)
	if err != nil || status.Sync != "OutOfSync" || status.Operation != "Succeeded" || status.Health != "Unknown" {
		t.Fatal(status, err)
	}
	_, err = f.d.Start(f.d.Revision(), f.f.c, f.ctx, "second", "submitter", 1)
	problem, ok := err.(*InputError)
	if !ok || problem.Code != "CD_DRIFT_REPORT_ONLY" {
		t.Fatal("report policy corrected runtime drift", err)
	}
}
func TestDeliveryReconcileUsesOriginalGenerationForRuntimeGoal(t *testing.T) {
	f := newDeliveryFixturePolicy(t, "automatic", "reconcile")
	f.receive(f.body)
	f.start("first")
	f.completeDelivery()
	key := ResourceKey("delivery", "tenant", "php-mysql", "source")
	original := f.shared.Object(key)
	f.editDesired(key, func(g *GoalCommand) {
		var policy DeliveryDeclaration
		json.Unmarshal(g.Config, &policy)
		policy.Poll++
		g.Config = goal(policy)
	})
	f.receive(append([]byte("# same desired source\n"), f.body...))
	f.start("second")
	command := f.prepare(key)
	stage, _ := f.e.Stage(key)
	if stage.Noop || command.Expected != f.shared.Object(key).Revision {
		t.Fatal("runtime reconcile bypassed current CAS")
	}
	f.send(key)
	result := f.apply(command)
	if result.Generation != original.Generation {
		t.Fatal("runtime reconcile recreated resource")
	}
	f.save(f.e.Commit(f.e.Revision(), key, command, result))
	f.syncDelivery()
	if f.d.d.LastSuccess.Operation != "first" || f.d.d.Running.Operation != "second" {
		t.Fatal("new command was marked completed without observations")
	}
}
func TestDeliveryReconcileCannotRecreateUnclosedTask(t *testing.T) {
	f := newDeliveryFixturePolicy(t, "automatic", "reconcile")
	f.receive(f.body)
	f.start("first")
	f.completeDelivery()
	key := ResourceKey("task", "tenant", "php-mysql", "db")
	f.editDesired(key, changeTaskImage)
	f.receive(append([]byte("# same source still requires native closure\n"), f.body...))
	_, err := f.d.Start(f.d.Revision(), f.f.c, f.ctx, "second", "submitter", 1)
	problem, ok := err.(*InputError)
	if !ok || problem.Code != "TRANSITION_REQUIRED" {
		t.Fatal("reconcile replaced native task without closure", err)
	}
}

func TestDeliveryExplicitSyncApprovalCanRestoreReportedRuntimeSetting(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	f.start("first")
	f.completeDelivery()
	key := ResourceKey("delivery", "tenant", "php-mysql", "source")
	f.editDesired(key, func(g *GoalCommand) {
		var policy DeliveryDeclaration
		json.Unmarshal(g.Config, &policy)
		policy.Poll++
		g.Config = goal(policy)
	})
	f.receive(append([]byte("# explicit reviewed sync under report policy\n"), f.body...))
	f.approve()
	f.start("second")
	if f.d.d.Running.Operation != "second" || f.d.d.Policy.Sync.Drift != "report" || f.d.d.LastSuccess.Operation != "first" {
		t.Fatal("explicit sync changed policy or claimed completion")
	}
}

func TestDeliveryLocalFileUpdatesUseSameInventoryAndCannotReplaceGitSource(t *testing.T) {
	f := newDeliveryFixture(t, "manual")
	gitOriginal := deliveryRaw(t, f.d)
	if _, err := f.d.SubmitFile(f.d.Revision(), f.f.c, f.ctx, "alice", f.body); err == nil {
		t.Fatal("local upload silently replaced a registered Git source")
	}
	if !bytes.Equal(gitOriginal, deliveryRaw(t, f.d)) {
		t.Fatal("source conflict changed accepted input")
	}
	input, err := ParseCompose(f.body)
	if err != nil {
		t.Fatal(err)
	}
	input.MyDC.Delivery = nil
	body, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	f.saveDelivery(NewDelivery(f.f.c, f.ctx, body))
	f.approve()
	f.start("first")
	original := f.d.d.Running.Candidate.Artifact.Digest
	next := append([]byte("# new local submission\n"), body...)
	f.saveDelivery(f.d.SubmitFile(f.d.Revision(), f.f.c, f.ctx, "alice", next))
	if f.d.d.Candidate.Artifact.Digest == original || f.d.d.Running.Candidate.Artifact.Digest != original || f.d.d.Inventory.Active.Operation != "first" || f.d.d.Approval != nil {
		t.Fatal("local file replacement overwrote original or reused approval")
	}
	input.MyDC.Delivery = &DeliveryDeclaration{}
	if input.normalize() != nil {
		t.Fatal("local defaults")
	}
	input.MyDC.Delivery.Sync.Prune = true
	body, err = yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.d.SubmitFile(f.d.Revision(), f.f.c, f.ctx, "alice", body); err == nil {
		t.Fatal("file update self-authorized new deletion policy")
	}
}
