// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// CheckerBuildReport uses installed-member Management and the existing finite
// report ledger. Only native owners issue closure; a relay cannot forge one.
type CheckerBuildReport struct {
	Schema                               uint8
	Cluster, Reporter                    [32]byte
	Tenant, ID, Action                   string
	Expected, Epoch, RootRevision, Index uint64
	At                                   int64
	Intent                               *checker.BuildIntent  `json:",omitempty"`
	Closure                              *checker.BuildClosure `json:",omitempty"`
	Signature                            []byte
}

func CheckerBuildReportBytes(r CheckerBuildReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("mydc-checker-build-report-1\x00"), raw...)
}
func (r CheckerBuildReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	c := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: LifecycleKey, Expected: r.RootRevision, Value: string(raw)}
	c.RequestID = state.ReportRequestID(c)
	_, err = state.EncodeCommand(c)
	return c, err
}
func (p Policy) checkerBuildReport(s state.State, c state.Command) (CheckerBuildReport, error) {
	var r CheckerBuildReport
	if c.Kind != state.ModuleReport || c.Key != LifecycleKey || canonical([]byte(c.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Reporter == ([32]byte{}) || r.Epoch != s.ModuleEpoch() || r.Index == 0 || r.Index > s.Index() || r.At <= 0 || !ed25519.Verify(r.Reporter[:], CheckerBuildReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	if err != nil || want != c {
		return r, ErrCatalog
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(r.Reporter) {
		return r, access.ErrDenied
	}
	switch r.Action {
	case "reserve":
		if r.Expected != 0 || r.Intent == nil || r.Closure != nil || r.Intent.Validate() != nil || r.Intent.Cluster != r.Cluster || r.Intent.Tenant != r.Tenant || r.Intent.ID != r.ID {
			return r, ErrCatalog
		}
	case "dispatch":
		if r.Expected == 0 || r.Intent != nil || r.Closure != nil {
			return r, ErrCatalog
		}
	case "close":
		if r.Expected == 0 || r.Intent != nil || r.Closure == nil {
			return r, ErrCatalog
		}
	default:
		return r, ErrCatalog
	}
	return r, nil
}

func (p Policy) ResolveCheckerBuildReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r CheckerBuildReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, ErrCatalog
	}
	c, err := r.Command()
	if err != nil {
		return c, err
	}
	_, err = p.checkerBuildReport(s, c)
	return c, err
}

// checkerBuildContext joins the immutable build to its actual accepted app
// parent and original Task program. Used for new reserve/dispatch/source reads;
// cleanup deliberately does not require still-enabled policy or live Task.
func (p Policy) checkerBuildContext(s state.State, b checker.BuildIntent, at int64) (checker.Use, error) {
	if b.Validate() != nil || b.Cluster != p.Cluster || at <= 0 || at > math.MaxInt64/1000 || at*1000 >= b.DeadlineUnixMilli {
		return checker.Use{}, ErrCatalog
	}
	book, err := p.Lifecycles(s)
	if err != nil {
		return checker.Use{}, err
	}
	parent, ok := book.Use(b.Tenant, b.AppUseID)
	if !ok || parent.Kind != "app-binding" || parent.Digest() != b.AppUse || parent.PolicyRevision != b.Selection.PolicyRevision {
		return parent, access.ErrDenied
	}
	apps, err := p.Apps(s)
	if err != nil {
		return parent, err
	}
	binding, ok := apps.binding(parent.Parent)
	if !ok {
		return parent, access.ErrDenied
	}
	want, ok := CheckerBindingUse(binding)
	if !ok || !sameCheckerUse(want, parent) {
		return parent, access.ErrDenied
	}
	source, ok := apps.BindingSource(parent.Parent)
	if !ok {
		return parent, access.ErrDenied
	}
	if _, err := p.AppBindingPermit(s, p.resourceCallerForNode(s, parent.Node, parent.Owner), AppBindingRequest{Task: source.Task, Digest: parent.Parent, At: at}); err != nil {
		return parent, err
	}
	var goal deployment.GoalCommand
	var service deployment.ComposeService
	if canonical([]byte(s.Object(source.Task.Key).Value), &goal) != nil || canonical(goal.Config, &service) != nil || service.LifecycleProgram == nil {
		return parent, access.ErrDenied
	}
	program := service.LifecycleProgram
	if program.ValidateCatalog(book) != nil {
		return parent, access.ErrDenied
	}
	if checkerBuildProgramAllowed(b, *program) != nil {
		return parent, access.ErrDenied
	}
	policy, ok := book.AdmissionPolicy(b.Tenant, b.Selection.PolicyRevision)
	if !ok || !slices.Contains(policy.Build.Nodes, b.Node) || !slices.Contains(policy.Build.Targets, b.Target) {
		return parent, access.ErrDenied
	}
	members, err := p.Members(s)
	owner, ownerErr := p.nodeOwner(s, b.Node)
	if err != nil || ownerErr != nil || !p.ownsResource(s, owner, b.Owner) || !members.WorkKey(owner) || p.currentResourceKey(s, parent.Owner, true) == ([32]byte{}) {
		return parent, access.ErrDenied
	}
	for _, input := range b.Inputs {
		fact, _, err := book.SourceForUse(parent, input.Content)
		if err != nil || p.currentResourceKey(s, fact.Owner, true) == ([32]byte{}) {
			return parent, access.ErrDenied
		}
	}
	users, err := p.Catalog(s)
	if err != nil || users.Authorize(parent.Principal, b.Tenant, access.ManageServices, b.Node) != nil {
		return parent, access.ErrDenied
	}
	if err := p.imageCacheAvailable(s, b.Node, policy.Build.Image); err != nil {
		return parent, err
	}
	if _, err := users.CheckImage(parent.Principal, b.Tenant, b.Node, policy.Build.Image); err != nil {
		return parent, err
	}
	return parent, nil
}

func (p Policy) reduceCheckerBuild(s state.State, c state.Command) (map[string][]byte, state.Code) {
	r, err := p.checkerBuildReport(s, c)
	if err != nil {
		return nil, state.Forbidden
	}
	book, err := p.Lifecycles(s)
	if err != nil {
		return nil, state.Invalid
	}
	switch r.Action {
	case "reserve":
		b := *r.Intent
		// A repeat returns its immutable original phase, never a new native job.
		if old, ok := book.BuildJob(b.Tenant, b.ID); ok {
			if old.Intent.Digest() != b.Digest() {
				return nil, state.ConditionFailed
			}
			return p.lifecycleCheckpoint(s, book)
		}
		members, memberErr := p.Members(s)
		if memberErr != nil || !members.WorkKey(b.Owner) {
			return nil, state.Forbidden
		}
		parent, e := p.checkerBuildContext(s, b, r.At)
		policy, ok := book.AdmissionPolicy(b.Tenant, b.Selection.PolicyRevision)
		if e != nil || !p.ownsResource(s, r.Reporter, parent.Owner) || !ok || r.At > math.MaxInt64/1000 {
			return nil, state.Forbidden
		}
		start := r.At * 1000
		if b.DeadlineUnixMilli <= start || b.DeadlineUnixMilli-start > policy.Build.TimeoutMS {
			return nil, state.ConditionFailed
		}
		book, err = book.ReserveBuild(b)
	case "dispatch":
		job, ok := book.BuildJob(r.Tenant, r.ID)
		if !ok || !p.ownsResource(s, r.Reporter, job.Intent.Owner) {
			return nil, state.Forbidden
		}
		if _, e := p.checkerBuildContext(s, job.Intent, r.At); e != nil {
			return nil, state.Forbidden
		}
		if r.At > math.MaxInt64/1000 || r.At*1000 >= job.Intent.DeadlineUnixMilli {
			return nil, state.ConditionFailed
		}
		book, err = book.DispatchBuild(r.Tenant, r.ID, r.Expected, job.Intent.Owner)
	case "close":
		// Any currently installed member may relay the original owner's signed
		// closure after policy/Task/builder admission has changed.
		book, err = book.CloseBuild(r.Tenant, r.ID, r.Expected, *r.Closure)
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	return p.lifecycleCheckpoint(s, book)
}

type CheckerBuildRequest struct {
	Schema         uint8
	Tenant, ID     string
	Job            [32]byte
	MinimumIndex   uint64
	At             int64
	Start, Recover bool
}
type CheckerBuildPermit struct {
	Schema                                               uint8
	Job, Manifest, Owner, Policy                         [32]byte
	Phase                                                string
	Revision, PolicyRevision, Index, Epoch, RootRevision uint64
	DeadlineUnixMilli                                    int64
	Recovery                                             bool
	Closure                                              *[32]byte `json:",omitempty"`
}

func (p Policy) CheckerBuildPermit(s state.State, caller [32]byte, q CheckerBuildRequest) (CheckerBuildPermit, error) {
	if q.Schema != 1 || q.At <= 0 || q.MinimumIndex == 0 || s.Index() < q.MinimumIndex || q.Start && q.Recover {
		return CheckerBuildPermit{}, access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return CheckerBuildPermit{}, access.ErrDenied
	}
	book, err := p.Lifecycles(s)
	if err != nil {
		return CheckerBuildPermit{}, err
	}
	j, ok := book.BuildJob(q.Tenant, q.ID)
	if !ok || j.Intent.Digest() != q.Job || !p.ownsResource(s, caller, j.Intent.Owner) {
		return CheckerBuildPermit{}, access.ErrDenied
	}
	if !q.Recover {
		if j.Phase == "closed" || q.Start && j.Phase != "dispatched" {
			return CheckerBuildPermit{}, access.ErrDenied
		}
		if _, err := p.checkerBuildContext(s, j.Intent, q.At); err != nil {
			return CheckerBuildPermit{}, err
		}
		if q.At > math.MaxInt64/1000 || q.At*1000 >= j.Intent.DeadlineUnixMilli {
			return CheckerBuildPermit{}, access.ErrDenied
		}
	}
	policy, ok := book.Policy(q.Tenant, j.Intent.Selection.PolicyRevision)
	if !ok {
		return CheckerBuildPermit{}, ErrCatalog
	}
	raw, _ := json.Marshal(policy)
	permit := CheckerBuildPermit{Schema: 1, Job: q.Job, Manifest: j.Intent.Manifest, Owner: j.Intent.Owner, Policy: sha256.Sum256(raw), Phase: j.Phase, Revision: j.Revision, PolicyRevision: policy.Revision, Index: s.Index(), Epoch: s.ModuleEpoch(), RootRevision: s.Object(LifecycleKey).Revision, DeadlineUnixMilli: j.Intent.DeadlineUnixMilli, Recovery: q.Recover}
	if j.Closure != nil {
		hash := j.Closure.Digest()
		permit.Closure = &hash
	}
	return permit, nil
}

func checkerBuildProgramAllowed(b checker.BuildIntent, program checker.TaskProgram) error {
	// A selection may omit cache hits, but can never build interpreted-only
	// sources or widen an alias to an unrelated script with identical bytes.
	compiled := map[[32]byte]bool{}
	refs := map[checker.NamedReference]bool{}
	facts := map[[32]byte]bool{}
	for alias, script := range program.Scripts {
		if !script.Compile {
			continue
		}
		fact, ok := program.Sources[alias]
		if !ok {
			return access.ErrDenied
		}
		compiled[fact.ContentDigest()] = true
		if script.Ref != nil {
			refs[*script.Ref] = true
		} else {
			facts[fact.ContentDigest()] = true
		}
	}
	for _, input := range b.Inputs {
		if !compiled[input.Content] {
			return access.ErrDenied
		}
	}
	for _, ref := range b.Selection.Scripts {
		if !refs[ref] {
			return access.ErrDenied
		}
	}
	for _, fact := range b.Selection.Sources {
		if !facts[fact.ContentDigest()] {
			return access.ErrDenied
		}
	}
	return nil
}

// This is a historical structural join, not a current permission/readiness
// check: policy revocation and Task retirement must preserve original pins.
func validateCheckerBuildParents(apps Apps, book checker.Catalog) error {
	for _, job := range book.BuildJobs() {
		if job.Phase == "closed" {
			continue
		}
		b := job.Intent
		parent, ok := book.Use(b.Tenant, b.AppUseID)
		if !ok || parent.Digest() != b.AppUse {
			return ErrCatalog
		}
		binding, ok := apps.binding(parent.Parent)
		if !ok {
			return ErrCatalog
		}
		use, ok := CheckerBindingUse(binding)
		if !ok || !sameCheckerUse(parent, use) {
			return ErrCatalog
		}
		source, ok := apps.BindingSource(parent.Parent)
		if !ok {
			return ErrCatalog
		}
		n := binding.Needs()
		entry, ok := apps.entries[appKey(n.Use.Tenant, n.Use.App)]
		if !ok {
			return ErrCatalog
		}
		claim, ok := bindingClaim(entry, source.Task)
		var goal deployment.GoalCommand
		var service deployment.ComposeService
		if !ok || canonical([]byte(claim.Command.Value), &goal) != nil || canonical(goal.Config, &service) != nil || service.LifecycleProgram == nil {
			return ErrCatalog
		}
		if service.LifecycleProgram.ValidateCatalog(book) != nil || checkerBuildProgramAllowed(b, *service.LifecycleProgram) != nil {
			return ErrCatalog
		}
	}
	return nil
}
