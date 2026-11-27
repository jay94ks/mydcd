// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"runtime"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

func checkerProgramHash(p checker.TaskProgram) [32]byte {
	raw, _ := json.Marshal(p)
	return sha256.Sum256(raw)
}

func (r *Runtime) checkerTaskProgram(v cluster.View, b deployment.Binding, task deployment.ObjectRef) (*checker.TaskProgram, error) {
	program, _, err := r.checkerTaskProgramCatalog(v, b, task)
	return program, err
}

// The catalog belongs only to this immutable view. Reusing its verified
// decoding within one authority call never retains a grant across calls.
func (r *Runtime) checkerTaskProgramCatalog(v cluster.View, b deployment.Binding, task deployment.ObjectRef) (*checker.TaskProgram, checker.Catalog, error) {
	o := v.State.Object(task.Key)
	goal, err := schema.Decode[deployment.GoalCommand]([]byte(o.Value))
	if err != nil || !o.Present || o.Generation != task.Generation || o.Revision != task.Revision || goal.Kind != "task" || goal.Owner != r.Identity.Public {
		return nil, checker.Catalog{}, checker.ErrPreparation
	}
	service, err := schema.Decode[deployment.ComposeService](goal.Config)
	if err != nil || service.CheckLifecycleNeeds(b.Needs()) != nil {
		return nil, checker.Catalog{}, checker.ErrPreparation
	}
	if service.LifecycleProgram == nil {
		return nil, checker.Catalog{}, nil
	}
	book, err := r.controlPolicy.Lifecycles(v.State)
	if err != nil || service.LifecycleProgram.ValidateCatalog(book) != nil {
		return nil, checker.Catalog{}, checker.ErrPreparation
	}
	return service.LifecycleProgram, book, nil
}

type checkerPreparationProvider struct {
	Node    string
	Key     [32]byte
	Builder bool
}

func (r *Runtime) checkerPreparationProviders(v cluster.View, u checker.Use, p checker.TenantPolicy) ([]checkerPreparationProvider, error) {
	members, err := r.controlPolicy.Members(v.State)
	if err != nil {
		return nil, err
	}
	users, err := r.controlPolicy.Catalog(v.State)
	if err != nil {
		return nil, err
	}
	providers := []checkerPreparationProvider{{Node: u.Node, Key: u.Owner}}
	seen := map[[32]byte]bool{u.Owner: true}
	// Original caches remain in their original owner namespace. They can be
	// read under the retained use via the current node, but cannot build new
	// work with a retired identity.
	for _, entry := range members.Entries {
		for _, transition := range entry.Keys {
			old := transition.Proof.Old
			current, err := identity.ParseKey(entry.CurrentPeer().Key)
			if err == nil && members.WorkKey(current) && members.OwnsResource(current, old) && !seen[old] {
				providers = append(providers, checkerPreparationProvider{Node: entry.Peer.ID, Key: old})
				seen[old] = true
			}
		}
	}
	for _, node := range p.Build.Nodes {
		entry, ok := members.Entry(node)
		if !ok || !membership.FullMember(entry) || users.Authorize(u.Principal, u.Tenant, access.ManageServices, node) != nil {
			continue
		}
		if _, err := users.CheckImage(u.Principal, u.Tenant, node, p.Build.Image); err != nil {
			continue
		}
		key, err := identity.ParseKey(entry.CurrentPeer().Key)
		if err != nil {
			return nil, err
		}
		if key == u.Owner {
			providers[0].Builder = true
			continue
		}
		if !seen[key] {
			providers = append(providers, checkerPreparationProvider{Node: node, Key: key, Builder: true})
			seen[key] = true
		}
	}
	return providers, nil
}

func (r *Runtime) planCheckerCompilation(ctx context.Context, v cluster.View, book checker.Catalog, u checker.Use, program checker.TaskProgram, p checker.TaskPreparation) (checker.TaskCompilePlan, error) {
	current, ok := book.Policy(u.Tenant, 0)
	if !ok {
		return checker.TaskCompilePlan{}, checker.ErrPreparation
	}
	inputs, err := r.checkerSources.TaskCompilations(ctx, program, current, checker.ResolverTarget{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Toolchain: current.Build.Toolchain})
	if err != nil {
		return checker.TaskCompilePlan{}, err
	}
	providers, err := r.checkerPreparationProviders(v, u, current)
	if err != nil {
		return checker.TaskCompilePlan{}, err
	}
	negative := map[[32]byte]map[[32]byte]bool{}
	canBuild := map[[32]byte]bool{}
	plan := checker.TaskCompilePlan{}
	var missing []*checker.Compilation
	var lookupErrors error
	for _, input := range inputs {
		recipe, key := input.Recipe(), input.Key()
		plan.Recipes = append(plan.Recipes, recipe)
		hit := false
		for _, provider := range providers {
			lookup := control.CheckerCacheLookup{Provider: provider.Key, Recipe: recipe}
			q := control.CheckerArtifactRequest{Schema: 1, Tenant: u.Tenant, UseID: u.ID, Use: u.Digest(), Content: recipe.Source, Consumer: u.Owner, MinimumIndex: v.State.Index(), Lookup: &lookup}
			observation, err := r.checkerCache(ctx, q)
			if err != nil {
				if provider.Key == r.Identity.Public {
					return checker.TaskCompilePlan{}, err
				}
				lookupErrors = errors.Join(lookupErrors, err)
				continue // unavailable is NOT a negative cache observation
			}
			canBuild[provider.Key] = provider.Builder && observation.CanBuild
			if !observation.Found {
				if negative[provider.Key] == nil {
					negative[provider.Key] = map[[32]byte]bool{}
				}
				negative[provider.Key][key] = true
				continue
			}
			q.Lookup = nil
			q.Compiled = observation.Fact
			q.MinimumIndex = max(q.MinimumIndex, observation.Index)
			if err = r.receiveCheckerArtifact(ctx, q); err != nil {
				return checker.TaskCompilePlan{}, err
			}
			hit = true
			break
		}
		if !hit {
			missing = append(missing, input)
		}
	}
	if len(plan.Recipes) == 0 {
		return checker.TaskCompilePlan{}, checker.ErrPreparation
	}
	if len(missing) == 0 {
		return plan, nil
	}
	var selected *checkerPreparationProvider
	for i, provider := range providers {
		if !canBuild[provider.Key] {
			continue
		}
		complete := true
		for _, input := range missing {
			if !negative[provider.Key][input.Key()] {
				complete = false
				break
			}
		}
		if complete {
			selected = &providers[i]
			break
		}
	}
	if selected == nil {
		return checker.TaskCompilePlan{}, errors.Join(reconcile.ErrPending, lookupErrors)
	}
	// One frozen deadline/ID/selection; no budget reset when the slot is busy
	// or the original reserve reply is lost.
	batch, err := checker.NewCompileBatch(p.ID(), p.DeadlineUnixMilli, current, missing)
	if err != nil {
		return checker.TaskCompilePlan{}, err
	}
	var wanted []checker.BuildInput
	for _, item := range batch.Items {
		wanted = append(wanted, checker.BuildInput{Content: item.Recipe.Source, Recipe: item.Key})
	}
	selection, err := program.CompileSelection(wanted)
	if err != nil {
		return checker.TaskCompilePlan{}, err
	}
	intent, err := book.PlanBuild(u, selected.Node, selected.Key, selection, batch)
	if err != nil {
		return checker.TaskCompilePlan{}, err
	}
	plan.Build = &intent
	return plan, nil
}

func (r *Runtime) checkerPreparationView(ctx context.Context, b deployment.Binding, task deployment.ObjectRef) (cluster.View, error) {
	permit, err := r.appInputPermit(ctx, control.AppBindingRequest{Task: task, Digest: b.Digest()})
	if err != nil {
		return cluster.View{}, err
	}
	return r.Engine().ReadAtLeast(ctx, permit.CommandIndex)
}

func (r *Runtime) reserveCheckerPreparation(ctx context.Context, b deployment.Binding, task deployment.ObjectRef, p checker.TaskPreparation) error {
	if p.Plan == nil || p.Plan.Build == nil {
		return nil
	}
	v, err := r.checkerPreparationView(ctx, b, task)
	if err != nil {
		return err
	}
	book, err := r.controlPolicy.Lifecycles(v.State)
	if err != nil {
		return err
	}
	intent := p.Plan.Build
	if job, ok := book.BuildJob(p.Tenant, intent.ID); ok {
		if job.Intent.Digest() != intent.Digest() {
			return checker.ErrPreparation
		}
		return nil // same original active/closed job; never reaccept/restart
	}
	if time.Now().UnixMilli() >= p.DeadlineUnixMilli {
		return checker.ErrPreparation
	}
	if _, err := book.ReserveBuild(*intent); err != nil {
		return err
	}
	report := control.CheckerBuildReport{Schema: 1, Cluster: r.controlPolicy.Cluster, Reporter: r.commandIdentity().Public, Tenant: p.Tenant, ID: intent.ID, Action: "reserve", Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.LifecycleKey).Revision, Index: v.State.Index(), At: time.Now().Unix(), Intent: intent}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.CheckerBuildReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "checker-build-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return reconcile.ErrPending
	}
	return nil
}

// Prepared cache bytes are an input prerequisite, never script/Task Ready.
// This read-only check also runs at the native actor's current authority edge.
func (r *Runtime) checkerPreparationReady(ctx context.Context, v cluster.View, u checker.Use, program checker.TaskProgram, p checker.TaskPreparation, compiledPermit ...func(context.Context, checker.CompiledFact) error) error {
	if len(compiledPermit) > 1 || len(compiledPermit) == 1 && compiledPermit[0] == nil {
		return checker.ErrPreparation
	}
	if p.Validate() != nil || p.Plan == nil || p.Cluster != r.controlPolicy.Cluster || p.Owner != r.Identity.Public || p.Tenant != u.Tenant || p.UseID != u.ID || p.Use != u.Digest() || p.Program != checkerProgramHash(program) || p.SDK != checker.CompileSDKDigest() || p.Target != runtime.GOOS+"/"+runtime.GOARCH {
		return checker.ErrPreparation
	}
	if p.Plan.ValidateProgram(program) != nil {
		return checker.ErrPreparation
	}
	book, err := r.controlPolicy.Lifecycles(v.State)
	if err != nil {
		return err
	}
	if p.Plan.Build != nil {
		job, ok := book.BuildJob(p.Tenant, p.Plan.Build.ID)
		if !ok || job.Intent.Digest() != p.Plan.Build.Digest() {
			return checker.ErrPreparation
		}
		if job.Phase != "closed" {
			return reconcile.ErrPending
		}
	}
	for _, recipe := range p.Plan.Recipes {
		fact, data, err := r.checkerSources.CompiledArtifact(ctx, u.Tenant, recipe.Key())
		clear(data)
		if err != nil {
			return errors.Join(checker.ErrPreparation, err)
		}
		q := control.CheckerArtifactRequest{Schema: 1, Tenant: u.Tenant, UseID: u.ID, Use: u.Digest(), Content: recipe.Source, Consumer: u.Owner, MinimumIndex: v.State.Index(), Compiled: &fact}
		if len(compiledPermit) == 1 {
			if err := compiledPermit[0](ctx, fact); err != nil {
				return err
			}
		} else {
			if _, err := r.checkerArtifactPermit(ctx, q); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Runtime) collectCheckerPreparation(ctx context.Context, v cluster.View, u checker.Use, p checker.TaskPreparation) error {
	if p.Plan == nil || p.Plan.Build == nil {
		return nil
	}
	book, err := r.controlPolicy.Lifecycles(v.State)
	if err != nil {
		return err
	}
	job, ok := book.BuildJob(p.Tenant, p.Plan.Build.ID)
	if !ok {
		return reconcile.ErrPending
	}
	if job.Intent.Digest() != p.Plan.Build.Digest() {
		return checker.ErrPreparation
	}
	if job.Phase != "closed" {
		return reconcile.ErrPending
	}
	for _, recipe := range p.Plan.Recipes {
		// Do not demand another source fetch or rebuild after a sealed hit.
		if _, data, err := r.checkerSources.CompiledArtifact(ctx, p.Tenant, recipe.Key()); err == nil {
			clear(data)
			continue
		} else if !errors.Is(err, storage.ErrMissing) || errors.Is(err, checker.ErrSourceStore) {
			return err
		}
		if !slices.ContainsFunc(job.Intent.Inputs, func(input checker.BuildInput) bool { return input.Recipe == recipe.Key() }) {
			return checker.ErrPreparation
		}
		q := control.CheckerArtifactRequest{Schema: 1, Tenant: u.Tenant, UseID: u.ID, Use: u.Digest(), Content: recipe.Source, Consumer: u.Owner, MinimumIndex: v.State.Index(), Lookup: &control.CheckerCacheLookup{Provider: job.Intent.Owner, Recipe: recipe}}
		value, err := r.checkerCache(ctx, q)
		if err != nil {
			return err
		}
		if !value.Found {
			return checker.ErrPreparation
		}
		q.Lookup = nil
		q.Compiled = value.Fact
		q.MinimumIndex = max(q.MinimumIndex, value.Index)
		if err = r.receiveCheckerArtifact(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) prepareAppCheckers(ctx context.Context, v cluster.View, b deployment.Binding, task deployment.ObjectRef) error {
	program, err := r.checkerTaskProgram(v, b, task)
	if err != nil || program == nil {
		return err
	}
	hasCompiled := false
	for _, script := range program.Scripts {
		hasCompiled = hasCompiled || script.Compile
	}
	if !hasCompiled {
		return r.prepareCheckerInputs(ctx, b, v.State.Index())
	}
	u, ok := control.CheckerBindingUse(b)
	if !ok || u.Owner != r.Identity.Public {
		return checker.ErrPreparation
	}
	target := runtime.GOOS + "/" + runtime.GOARCH
	id := checker.TaskCompileID(r.controlPolicy.Cluster, u.Digest())
	p, err := r.checkerSources.TaskPreparation(ctx, u.Tenant, id, false)
	if errors.Is(err, checker.ErrSourceUncertain) {
		p, err = r.checkerSources.TaskPreparation(ctx, u.Tenant, id, true)
	}
	if errors.Is(err, storage.ErrMissing) && !errors.Is(err, checker.ErrPreparation) {
		v, err = r.checkerPreparationView(ctx, b, task)
		if err != nil {
			return err
		}
		book, err := r.controlPolicy.Lifecycles(v.State)
		if err != nil {
			return err
		}
		if _, exists := book.BuildJob(u.Tenant, id); exists {
			return checker.ErrPreparation
		}
		budget := program.Policy.Build.TimeoutMS
		now := time.Now().Unix() * 1000
		if budget <= 0 || budget > math.MaxInt64-now {
			return checker.ErrPreparation
		}
		p, err = r.checkerSources.BeginTaskPreparation(ctx, checker.TaskPreparation{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Use: u.Digest(), Program: checkerProgramHash(*program), SDK: checker.CompileSDKDigest(), Tenant: u.Tenant, UseID: u.ID, Target: target, DeadlineUnixMilli: now + budget})
	}
	if err != nil {
		return err
	}
	if p.Tenant != u.Tenant || p.UseID != u.ID || p.Target != target || p.Use != u.Digest() || p.Program != checkerProgramHash(*program) || p.SDK != checker.CompileSDKDigest() {
		return checker.ErrPreparation
	}
	if p.Plan == nil {
		// An already completed local cache hit needs no compiler budget.
		// Keep the original preparation/deadline; never create a new job here.
		currentView, err := r.checkerPreparationView(ctx, b, task)
		if err != nil {
			return err
		}
		currentBook, err := r.controlPolicy.Lifecycles(currentView.State)
		if err != nil {
			return err
		}
		currentPolicy, ok := currentBook.Policy(u.Tenant, 0)
		if !ok {
			return checker.ErrPreparation
		}
		cached, cacheErr := r.checkerSources.CachedTaskCompilePlan(ctx, *program, currentPolicy, checker.ResolverTarget{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Toolchain: currentPolicy.Build.Toolchain})
		if cacheErr == nil {
			p.Plan = &cached
			p, err = r.checkerSources.SealTaskPreparation(ctx, p)
			if err != nil {
				return err
			}
		} else if time.Now().UnixMilli() >= p.DeadlineUnixMilli {
			return errors.Join(checker.ErrPreparation, cacheErr)
		}
	}
	if p.Plan == nil {
		if time.Now().UnixMilli() >= p.DeadlineUnixMilli {
			return checker.ErrPreparation
		}
		prepare, cancel := context.WithDeadline(ctx, time.UnixMilli(p.DeadlineUnixMilli))
		defer cancel()
		v, err = r.checkerPreparationView(prepare, b, task)
		if err != nil {
			return err
		}
		originals, err := r.controlPolicy.Lifecycles(v.State)
		if err != nil {
			return err
		}
		if _, exists := originals.BuildJob(u.Tenant, p.ID()); exists {
			return checker.ErrPreparation
		}
		if err = r.prepareCheckerInputs(prepare, b, v.State.Index()); err != nil {
			return err
		}
		v, err = r.checkerPreparationView(prepare, b, task)
		if err != nil {
			return err
		}
		book, err := r.controlPolicy.Lifecycles(v.State)
		if err != nil {
			return err
		}
		plan, err := r.planCheckerCompilation(prepare, v, book, u, *program, p)
		if err != nil {
			return err
		}
		if plan.ValidateProgram(*program) != nil {
			return checker.ErrPreparation
		}
		p.Plan = &plan
		p, err = r.checkerSources.SealTaskPreparation(prepare, p)
		if err != nil {
			return err
		}
	}
	if err = r.reserveCheckerPreparation(ctx, b, task, p); err != nil {
		return err
	}
	v, err = r.checkerPreparationView(ctx, b, task)
	if err != nil {
		return err
	}
	if err = r.collectCheckerPreparation(ctx, v, u, p); err != nil {
		return err
	}
	return r.checkerPreparationReady(ctx, v, u, *program, p)
}
