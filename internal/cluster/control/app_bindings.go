// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// AppBindingSource preserves the ORIGINAL task and accepted delegation even
// when a later operation summarizes its execution. It contains public metadata.
type AppBindingSource struct {
	Digest, Command, Plan [32]byte
	Task, Inputs          deployment.ObjectRef
	Operation             string
	Origin                UserOperation
	Sync                  *AppDeliverySync `json:",omitempty"`
}

type AppBindingRelease struct {
	Digest [32]byte
	Proof  deployment.Closure
}

// AdmitAppPatch does not admit arbitrary user patches. The command is a signed
// installed member request; the existing typed reducer derives every row and
// the full validator checks all original references before publication.
func (p Policy) AdmitAppPatch(s state.State, cmd state.Command, keys []string) bool {
	if cmd.Key == MembersKey {
		return p.admitNodeDrainPatch(s, cmd, keys) || p.admitIdentityResourcePatch(s, cmd, keys)
	}

	if cmd.Key == ImageBuildKey {
		return p.admitImageBuildVaultPatch(s, cmd, keys)
	}
	if cmd.Key == ExternalRegistriesKey {
		return p.admitExternalRegistryVaultPatch(s, cmd, keys)
	}
	if cmd.Key == CatalogKey {
		current, err := p.Current(s)
		if err != nil {
			return false
		}
		p = current
		catalog, err := p.Catalog(s)
		if err != nil {
			return false
		}
		if cmd.Kind == state.ModuleReport {
			var report TenantRetirementReport
			if canonical([]byte(cmd.Value), &report) != nil {
				return false
			}
			resolved, err := p.ResolveTenantRetirementReport(s, report.Proof.Owner, []byte(cmd.Value))
			if err != nil || resolved != cmd {
				return false
			}
			for _, key := range keys {
				if key != ResourcesKey && !strings.HasPrefix(key, ResourcesKey+"/") {
					return false
				}
			}
			return true
		}
		operation, err := p.Operation(catalog, cmd, false)
		if err != nil || p.authorizeChange(s, catalog, operation) != nil {
			return false
		}
		shellWrites, shellCode := p.reduceCatalogNodeShellPatch(s, cmd)
		if shellCode != state.Applied {
			return false
		}
		evidence := ""
		if operation.Change.Action == "begin-tenant-retirement" {
			var selection TenantRetirementSelection
			if canonical(operation.Change.Payload, &selection) != nil {
				return false
			}
			evidence = tenantRetirementEvidenceKey(selection.Tenant, selection.Operation)
		}
		for _, key := range keys {
			if key != ResourcesKey && !strings.HasPrefix(key, ResourcesKey+"/") && !(evidence != "" && (key == evidence || strings.HasPrefix(key, evidence+"/"))) && !checkpointPatchKey(shellWrites, NodeShellKey, key) {
				return false
			}
		}
		return true
	}
	if cmd.Key == AppsKey && routeRetirementReportValue([]byte(cmd.Value)) {
		report, err := p.routeRetirementReport(s, cmd)
		if err != nil || report.ResourcesRevision != s.Object(ResourcesKey).Revision {
			return false
		}
		for _, key := range keys {
			if key != ResourcesKey && !strings.HasPrefix(key, ResourcesKey+"/") {
				return false
			}
		}
		return true
	}
	if cmd.Key == RegistriesKey {
		report, err := p.registryReport(s, cmd)
		if err != nil || report.Action != "reserve" && report.Action != "drain" && report.Action != "closed" {
			return false
		}
		for _, key := range keys {
			resource := key == ResourcesKey || strings.HasPrefix(key, ResourcesKey+"/")
			volume := report.Action != "drain" && (key == VolumesKey || strings.HasPrefix(key, VolumesKey+"/"))
			if !resource && !volume {
				return false
			}
		}
		return true
	}
	if cmd.Key == ResourcesKey {
		return p.admitManagedNetworkPatch(s, cmd, keys)
	}
	if cmd.Key == VolumesKey {
		r, err := p.volumeMoveReport(s, cmd)
		if err != nil || r.Kind != "quiesce" && r.Kind != "activate-app" {
			return false
		}
		for _, key := range keys {
			if key != AppsKey && !strings.HasPrefix(key, AppsKey+"/") {
				return false
			}
		}
		return true
	}
	r, err := p.appProgress(s, cmd)
	if err != nil || r.Action != "bind-inputs" && r.Action != "release-inputs" && r.Action != "volume-ready" {
		return false
	}
	for _, key := range keys {
		if r.Action == "volume-ready" && key != VolumesKey && !strings.HasPrefix(key, VolumesKey+"/") {
			return false
		}
		if key != VaultKey && !strings.HasPrefix(key, VaultKey+"/") && key != VolumesKey && !strings.HasPrefix(key, VolumesKey+"/") && key != LifecycleKey && !strings.HasPrefix(key, LifecycleKey+"/") {
			return false
		}
	}
	return true
}

// AppConsumer is stable across task generations; the actual committed task
// generation is a separate field and is protected by the existing core floor.
func AppConsumer(taskKey string) string {
	h := sha256.Sum256([]byte(taskKey))
	return "task-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:]))
}

func (a Apps) Binding(task deployment.ObjectRef) (deployment.Binding, bool) {
	for _, source := range a.sources {
		if source.Task == task {
			return a.binding(source.Digest)
		}
	}
	return deployment.Binding{}, false
}

func (a Apps) BindingSource(digest [32]byte) (AppBindingSource, bool) {
	for _, source := range a.sources {
		if source.Digest == digest {
			raw, _ := json.Marshal(source)
			var owned AppBindingSource
			_ = json.Unmarshal(raw, &owned)
			return owned, true
		}
	}
	return AppBindingSource{}, false
}
func (a Apps) binding(digest [32]byte) (deployment.Binding, bool) {
	for _, b := range a.bindings.Live() {
		if b.Digest() == digest {
			return b, true
		}
	}
	return deployment.Binding{}, false
}
func (a Apps) Bindings() deployment.Bindings {
	raw, _ := a.bindings.Encode()
	b, _ := deployment.DecodeBindings(raw)
	return b
}

func bindingClaim(entry appEntry, ref deployment.ObjectRef) (deployment.Claim, bool) {
	for _, claim := range entry.Inventory.Claims() {
		if claim.Step.Key == ref.Key && claim.Result.Code == state.Applied && claim.Result.Generation == ref.Generation && claim.Result.Revision == ref.Revision {
			return claim, true
		}
	}
	return deployment.Claim{}, false
}

// Structural ownership checks deliberately do not consult current activation
// permission: revocation must not make old references or snapshots disappear.
func (p Policy) validateAppBindingSources(a Apps) error {
	live := a.bindings.Live()
	if a.bindings.Cluster() != p.Cluster || len(a.sources) != len(live) {
		return ErrCatalog
	}
	byDigest := make(map[[32]byte]deployment.Binding, len(live))
	for _, b := range live {
		byDigest[b.Digest()] = b
	}
	seen := map[[32]byte]bool{}
	for i, source := range a.sources {
		b, ok := byDigest[source.Digest]
		if !ok || seen[source.Digest] || i > 0 && a.sources[i-1].Task.Key >= source.Task.Key || source.Plan == ([32]byte{}) || source.Origin.VerifyOriginal(p.Cluster) != nil {
			return ErrCatalog
		}
		seen[source.Digest] = true
		n := b.Needs()
		origin, err := appExecutionOrigin(source.Origin, source.Sync, deployment.AppScope{Cluster: p.Cluster, Tenant: n.Use.Tenant, App: n.Use.App, Deployment: n.Use.Deployment})
		if err != nil || origin.Operation != source.Operation || source.Origin.Session.User != n.Use.User || source.Origin.Session.Key != n.Use.RequesterKey || source.Sync != nil && source.Sync.Plan != source.Plan || source.Task.Generation != n.Generation || n.Consumer != AppConsumer(source.Task.Key) {
			return ErrCatalog
		}
		entry, exists := a.entries[appKey(n.Use.Tenant, n.Use.App)]
		claim, found := bindingClaim(entry, source.Task)
		if !exists || !found || claim.Step.Kind != "task" || claim.Step.Owner != n.Use.NodeKey || claim.Step.Node != n.Use.Node || state.Digest(claim.Command) != source.Command || claim.Command.Actor != origin.Submitter || claim.Command.Epoch != origin.Epoch {
			return ErrCatalog
		}
		var taskGoal deployment.GoalCommand
		var taskService deployment.ComposeService
		if canonical([]byte(claim.Command.Value), &taskGoal) != nil || taskGoal.Kind != "task" || canonical(taskGoal.Config, &taskService) != nil || taskService.CheckVolumeNeeds(n) != nil || taskService.CheckLifecycleNeeds(n) != nil {
			return ErrCatalog
		}
		instance, instanceErr := deployment.TaskInstanceForKey(n.Use.Tenant, n.Use.App, source.Task.Key, taskService)
		resourceID, idErr := deployment.ResourceIDFromKey("task", n.Use.Tenant, n.Use.App, source.Task.Key)
		if instanceErr != nil || idErr != nil || instance.Service != n.Use.Service || instance.Node != n.Use.Node {
			return ErrCatalog
		}
		if instance.Ordinal == 0 && n.Instance != nil || instance.Ordinal != 0 && (n.Instance == nil || *n.Instance != instance) {
			return ErrCatalog
		}
		if source.Inputs.Key != "" {
			input, ok := bindingClaim(entry, source.Inputs)
			var goal deployment.GoalCommand
			if !ok || source.Inputs.Key != deployment.ResourceKey("inputs", n.Use.Tenant, n.Use.App, resourceID) || input.Step.Owner != n.Use.NodeKey || canonical([]byte(input.Command.Value), &goal) != nil || !slices.Contains(goal.Dependencies, source.Task) {
				return ErrCatalog
			}
		} else if source.Inputs != (deployment.ObjectRef{}) || n.HasSources() || len(n.Files) > 0 {
			return ErrCatalog
		}
	}
	return nil
}

func (p Policy) validateAppBindings(a Apps, vault Vault, registry Volumes) error {
	if len(a.sources) == 0 {
		return nil
	}
	for _, b := range a.bindings.Live() {
		for _, grant := range b.Grants() {
			if _, ok := vault.Approvals.Usage(grant); !ok {
				return invariantFailure("grant-usage")
			}
			if _, ok := vault.Trees[grant.Realm]; !ok {
				return invariantFailure("grant-realm")
			}
		}
		for _, pin := range b.Pins() {
			v, ok := registry.entries[pin.Key]
			if !ok || v.State.Scope() != pin.Scope || !slices.ContainsFunc(v.Grants, func(g volumeGrant) bool { return g.Consumer == pin.Consumer && g.Principal == b.Needs().Use.User }) {
				return invariantFailure("pin-grant")
			}
			if ref, fixed := b.Needs().FixedVolumes[pin.Key]; fixed && (!ref.Matches(v.Native) || !ref.MatchesState(v.State)) || !fixed && v.State.Fixed() {
				return invariantFailure("pin-fixed")
			}
		}
	}
	return nil
}

func (p Policy) bindingCapacity(s state.State, n deployment.Needs) (int, error) {
	resources, err := p.Resources(s)
	if err != nil {
		return 0, err
	}
	return bindingCapacity(resources, n)
}

func bindingCapacity(resources Resources, n deployment.Needs) (int, error) {
	g, gok := resources.Quotas.Limit("", n.Use.Node)
	t, tok := resources.Quotas.Limit(n.Use.Tenant, n.Use.Node)
	if !gok || !tok || !resources.Quotas.SameOwner(n.Use.Node, g.Owner, n.Use.NodeKey) || !resources.Quotas.SameOwner(n.Use.Node, t.Owner, n.Use.NodeKey) {
		return 0, access.ErrDenied
	}
	return min(g.MaxConsumers, t.MaxConsumers), nil
}

func (p Policy) authorizeBinding(s state.State, entry appEntry, e deployment.Execution, key string, n deployment.Needs) error {
	c, err := p.Catalog(s)
	if err != nil {
		return access.ErrDenied
	}
	var registry Volumes
	if len(n.FixedVolumes) > 0 {
		registry, err = p.Volumes(s)
		if err != nil {
			return err
		}
	}
	return p.authorizeBindingInView(s, c, registry, entry, e, key, n)
}

// c and registry are checked decodes of this exact immutable s. Sharing them
// within one permit never reuses authority from an earlier call or state.
func (p Policy) authorizeBindingInView(s state.State, c access.Catalog, registry Volumes, entry appEntry, e deployment.Execution, key string, n deployment.Needs) error {
	if p.authorizeAppStep(s, c, entry, e, key) != nil {
		return access.ErrDenied
	}
	return p.authorizeBindingVolumes(s, c, registry, entry, n)
}

func (p Policy) authorizeBindingVolumes(s state.State, c access.Catalog, registry Volumes, entry appEntry, n deployment.Needs) error {
	if len(n.Volumes) > 0 && c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, n.Use.Tenant, access.ManageVolumes, n.Use.Node) != nil {
		return access.ErrDenied
	}
	if len(n.FixedVolumes) > 0 {
		for key, ref := range n.FixedVolumes {
			row, ok := registry.entries[key]
			if !ok || !ref.Matches(row.Native) || !ref.MatchesState(row.State) || p.canUseFixedVolume(s, c, n.Use.User, row) != nil {
				return access.ErrDenied
			}
		}
	}
	return nil
}

func volumeStates(v Volumes) map[string]volumes.State {
	states := make(map[string]volumes.State, len(v.entries))
	for key, entry := range v.entries {
		states[key] = entry.State
	}
	return states
}

func (p Policy) reduceAppBinding(s state.State, r AppProgress, a Apps, entry appEntry, e deployment.Execution) (map[string][]byte, state.Code) {
	vault, err := p.Vault(s)
	if err != nil {
		return nil, state.Invalid
	}
	registry, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	checkers, err := p.Lifecycles(s)
	if err != nil {
		return nil, state.Invalid
	}
	originalCheckerRevision := checkers.Revision()
	var result deployment.Reservation
	var bound deployment.Binding
	if r.Action == "bind-inputs" {
		if _, retiring := entry.Inventory.Retirement(); retiring {
			return nil, state.Forbidden
		}
		if e.Status() == "Paused" || e.Status() == "Stopping" || e.Status() == "Closed" || e.Status() == "Failed" {
			return nil, state.ConditionFailed
		}
		var task deployment.Step
		for _, step := range e.Steps() {
			if step.Key == r.Key && step.Kind == "task" {
				task = step
			}
		}
		stage, ok := e.Stage(r.Key)
		if task.Key == "" || !ok || stage.Command == nil || stage.Result == nil || stage.Result.Code != state.Applied {
			return nil, state.ConditionFailed
		}
		o := s.Object(r.Key)
		if !o.Present || o.Generation != stage.Result.Generation || o.Revision != stage.Result.Revision || o.Value != stage.Command.Value {
			return nil, state.ConditionFailed
		}
		service, idErr := deployment.ResourceIDFromKey("task", r.Tenant, r.App, r.Key)
		if idErr != nil {
			return nil, state.Invalid
		}
		n, err := e.Inputs(service, AppConsumer(r.Key), entry.Origin.Session.Key)
		if err != nil || p.authorizeBinding(s, entry, e, r.Key, n) != nil {
			return nil, state.Forbidden
		}
		source := AppBindingSource{Task: deployment.ObjectRef{Key: r.Key, Generation: stage.Result.Generation, Revision: stage.Result.Revision}, Command: state.Digest(*stage.Command), Operation: r.Operation, Origin: entry.Origin, Sync: entry.Sync}
		for _, claim := range entry.Inventory.Claims() {
			if claim.Step.Key == r.Key {
				source.Plan = claim.Plan
			}
		}
		for _, step := range e.Steps() {
			if step.Kind == "inputs" && step.Key == deployment.ResourceKey("inputs", r.Tenant, r.App, service) {
				input, _ := e.Stage(step.Key)
				if input.Command == nil || input.Result == nil || input.Result.Code != state.Applied || p.authorizeAppStep(s, c, entry, e, step.Key) != nil {
					return nil, state.ConditionFailed
				}
				o := s.Object(step.Key)
				if !o.Present || o.Generation != input.Result.Generation || o.Revision != input.Result.Revision || o.Value != input.Command.Value {
					return nil, state.ConditionFailed
				}
				source.Inputs = deployment.ObjectRef{Key: step.Key, Generation: input.Result.Generation, Revision: input.Result.Revision}
			}
		}
		capacity, err := p.bindingCapacity(s, n)
		if err != nil || capacity < 1 {
			return nil, state.Forbidden
		}
		if _, exists := a.Binding(source.Task); !exists {
			global, tenant := 0, 0
			resources, _ := p.Resources(s)
			g, _ := resources.Quotas.Limit("", n.Use.Node)
			q, _ := resources.Quotas.Limit(n.Use.Tenant, n.Use.Node)
			for _, old := range a.bindings.Live() {
				if old.Needs().Use.Node == n.Use.Node {
					global++
					if old.Needs().Use.Tenant == n.Use.Tenant {
						tenant++
					}
				}
			}
			if global >= g.MaxConsumers || tenant >= q.MaxConsumers {
				return nil, state.ConditionFailed
			}
		}
		shares, err := p.VolumeShares(s)
		if err != nil {
			return nil, state.Invalid
		}
		result, err = a.bindings.Reserve(a.bindings.Revision(), c, vault.Trees, vault.Approvals, volumeStates(registry), []deployment.Needs{n}, int64(r.At), shares.mode)
		if err != nil {
			return nil, state.ConditionFailed
		}
		bound = result.Bindings[0]
		checkers, err = p.reserveCheckerBinding(s, checkers, bound)
		if err != nil {
			return nil, state.ConditionFailed
		}
		for _, pin := range bound.Pins() {
			old := registry.entries[pin.Key]
			if len(result.Volumes[pin.Key].Consumers()) > len(old.State.Consumers()) && len(result.Volumes[pin.Key].Consumers()) > capacity {
				return nil, state.ConditionFailed
			}
		}
		if _, exists := a.Binding(source.Task); !exists {
			source.Digest = bound.Digest()
			a.sources = append(slices.Clone(a.sources), source)
			slices.SortFunc(a.sources, func(a, b AppBindingSource) int { return strings.Compare(a.Task.Key, b.Task.Key) })
		}
	} else {
		var found bool
		bound, found = a.binding(r.Release.Digest)
		if !found || bound.Needs().Use.Tenant != r.Tenant || bound.Needs().Use.App != r.App {
			return nil, state.ConditionFailed
		}
		index := slices.IndexFunc(a.sources, func(source AppBindingSource) bool {
			return source.Digest == r.Release.Digest && source.Task.Key == r.Key
		})
		if index < 0 || !p.validBindingClosure(entry, a.sources[index], *r.Observation, r.At) {
			return nil, state.ConditionFailed
		}
		result, err = a.bindings.Release(a.bindings.Revision(), bound, vault.Approvals, volumeStates(registry), r.Release.Proof)
		if err != nil {
			return nil, state.ConditionFailed
		}
		if use, has := CheckerBindingUse(bound); has {
			checkers, err = checkers.Release(use)
			if err != nil {
				return nil, state.ConditionFailed
			}
		}
		a.sources = slices.Delete(slices.Clone(a.sources), index, index+1)
	}

	a.bindings = result.Inventory
	writes, code := p.appsCheckpoint(s, a)
	if code != state.Applied {
		return nil, code
	}
	merge := func(other map[string][]byte, code state.Code) bool {
		if code != state.Applied {
			return false
		}
		for k, v := range other {
			writes[k] = v
		}
		return true
	}
	if checkers.Revision() != originalCheckerRevision {
		if !merge(p.lifecycleCheckpoint(s, checkers)) {
			return nil, state.Invalid
		}
	}
	if result.Approvals.Revision() != vault.Approvals.Revision() {
		vault.Approvals = result.Approvals
		if !merge(p.vaultCheckpoint(s, vault)) {
			return nil, state.Invalid
		}
	}
	changed := false
	for key, next := range result.Volumes {
		row := registry.entries[key]
		if row.State.Revision() == next.Revision() {
			continue
		}
		changed = true
		row.State = next
		var grants []volumeGrant
		for _, consumer := range next.Consumers() {
			prior := slices.IndexFunc(row.Grants, func(g volumeGrant) bool { return g.Consumer == consumer })
			if prior >= 0 {
				grants = append(grants, row.Grants[prior])
			} else if slices.ContainsFunc(bound.Pins(), func(pin deployment.VolumePin) bool { return pin.Key == key && pin.Consumer == consumer }) {
				grants = append(grants, volumeGrant{consumer, bound.Needs().Use.User})
			} else {
				return nil, state.Invalid
			}
		}
		row.Grants = grants
		registry.entries[key] = row
	}
	if changed && !merge(p.volumeCheckpoint(s, registry)) {
		return nil, state.Invalid
	}
	return writes, state.Applied
}

func (p Policy) validBindingClosure(entry appEntry, source AppBindingSource, o deployment.Observation, at uint64) bool {
	claim, ok := bindingClaim(entry, source.Task)
	if !ok || o.Cluster != p.Cluster || o.Key != source.Task.Key || o.Command != source.Command || o.Plan != source.Plan || o.Operation != source.Operation || o.Owner != claim.Step.Owner || o.Revision != source.Task.Revision || o.Generation != source.Task.Generation || !o.Stopped || !o.Gone || !o.Released || o.Retained || o.Pins != 0 || o.Sequence == 0 || o.At == 0 || o.At > at || o.Native == "" || len(o.Native) > 256 || strings.ContainsAny(o.Native, "\x00\r\n") || !ed25519.Verify(o.Owner[:], deployment.ObservationBytes(o), o.Signature) {
		return false
	}
	old := claim.Observation
	if old == nil {
		return true
	}
	if o.Sequence == old.Sequence {
		left, _ := json.Marshal(old)
		right, _ := json.Marshal(o)
		return bytes.Equal(left, right)
	}
	return old.Native == o.Native && o.Sequence > old.Sequence && o.At >= old.At
}

type AppBindingRequest struct {
	Task   deployment.ObjectRef
	Digest [32]byte
	At     int64
}
type AppBindingPermit struct {
	Task, Inputs deployment.ObjectRef
	Binding      json.RawMessage
	MaxConsumers int
	ReadSet      [32]byte
	CommandIndex uint64
}

type AppInputRead struct {
	Realm    string
	Plan     secrets.UsePlan
	Profiles []secrets.WriteProfile
}

func (p Policy) bindingReads(s state.State, v Vault, c access.Catalog, b deployment.Binding, at int64) ([]AppInputRead, error) {
	return p.bindingGrantReads(s, v, c, b.ProjectionGrants(), at)
}

func (p Policy) bindingGrantReads(s state.State, v Vault, c access.Catalog, grants []secrets.Grant, at int64) ([]AppInputRead, error) {
	var reads []AppInputRead
	for _, g := range grants {
		plan, err := v.Approvals.ReadSet(c, v.Trees[g.Realm], g, at)
		if err != nil {
			return nil, err
		}
		profiles, err := p.inputProfiles(s, v.Trees[g.Realm], plan)
		if err != nil {
			return nil, err
		}
		reads = append(reads, AppInputRead{Realm: g.Realm, Plan: plan, Profiles: profiles})
	}
	return reads, nil
}

// Metadata validation shared by planning and the real bound input reader. This
// does not fetch a value, acquire a consumer, or assert backend availability.
func (p Policy) inputProfiles(s state.State, tree secrets.Tree, plan secrets.UsePlan) ([]secrets.WriteProfile, error) {
	members, err := p.Members(s)
	if err != nil {
		return nil, err
	}
	var profiles []secrets.WriteProfile
	seen := map[string]bool{}
	for _, leaf := range plan.Leaves {
		if leaf.Reference.Profile == secrets.BuiltinProfile && !builtinHeld(members, tree, leaf.Reference) {
			return nil, access.ErrDenied
		}
		if seen[leaf.Reference.Profile] {
			continue
		}
		seen[leaf.Reference.Profile] = true
		profile, ok := tree.WriteProfile(leaf.Reference.Profile)
		if !ok || !profile.Enabled || !profile.Values {
			return nil, access.ErrDenied
		}
		if profile.Builtin() {
			profiles = append(profiles, profile)
			continue
		}
		entry, exists := members.Entry(profile.Node)
		// Keep the original profile in the read-set. Only its exact node's
		// installed current key may serve it after a committed rotation.
		if !exists || !members.OwnsResource(mustCurrentPeer(entry), profile.Key) {
			return nil, access.ErrDenied
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

// AppBindingPermit is a current owner-only quorum read for provider reads,
// projection and NEW activation. Original running resources/closure never need
// to turn a revoked permission into a fresh permission.
func (p Policy) AppBindingPermit(s state.State, caller [32]byte, request AppBindingRequest) (AppBindingPermit, error) {
	if request.At < 0 {
		return AppBindingPermit{}, access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(caller) {
		return AppBindingPermit{}, access.ErrDenied
	}
	a, err := p.readOnlyApps(s)
	if err != nil {
		return AppBindingPermit{}, err
	}
	return p.appBindingPermitFromApps(s, caller, request, a)
}

// a is a read-only decoded view of the exact checkpoint in s. Decoding may be
// reused, but current catalog/move validation and every authority check below
// still run on this call, including delegated remote targets. Never mutate a.
func (p Policy) appBindingPermitFromApps(s state.State, caller [32]byte, request AppBindingRequest, a Apps) (AppBindingPermit, error) {
	if request.At < 0 {
		return AppBindingPermit{}, access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(caller) {
		return AppBindingPermit{}, access.ErrDenied
	}
	b, ok := a.Binding(request.Task)
	if !ok || b.Digest() != request.Digest || !p.ownsResource(s, caller, b.Needs().Use.NodeKey) {
		return AppBindingPermit{}, access.ErrDenied
	}
	n := b.Needs()
	entry := a.entries[appKey(n.Use.Tenant, n.Use.App)]
	if retirement, retiring := entry.Inventory.Retirement(); retiring && !retirement.Preserves(request.Task.Key) {
		return AppBindingPermit{}, access.ErrDenied
	}
	e, ok := entry.Inventory.Execution()
	if !ok || e.Status() == "Stopping" || e.Status() == "Closed" {
		return AppBindingPermit{}, access.ErrDenied
	}
	original, held := e.HeldExecution(request.Task.Key)
	if !held && (e.Status() == "Paused" || e.Status() == "Failed") {
		return AppBindingPermit{}, access.ErrDenied
	}
	var source AppBindingSource
	for _, row := range a.sources {
		if row.Digest == request.Digest {
			source = row
		}
	}
	o := s.Object(source.Task.Key)
	claim, found := bindingClaim(entry, source.Task)
	if !found || claim.Removed || !o.Present || o.Generation != source.Task.Generation || o.Revision != source.Task.Revision || o.Value != claim.Command.Value || claim.Observation != nil && claim.Observation.Released {
		return AppBindingPermit{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil || c.AuthorizeAccepted(source.Origin.Session, p.Cluster, source.Origin.At, n.Use.Tenant, access.Deploy, n.Use.Node) != nil || len(n.Volumes) > 0 && c.AuthorizeAccepted(source.Origin.Session, p.Cluster, source.Origin.At, n.Use.Tenant, access.ManageVolumes, n.Use.Node) != nil {
		return AppBindingPermit{}, access.ErrDenied
	}
	registry, err := p.Volumes(s)
	if err != nil {
		return AppBindingPermit{}, access.ErrDenied
	}
	if held {
		stage, _ := e.Stage(source.Task.Key)
		if stage.Previous.Result.Revision != source.Task.Revision || stage.Previous.Result.Generation != source.Task.Generation || stage.Previous.Command != claim.Command {
			return AppBindingPermit{}, access.ErrDenied
		}
		accepted := entry
		accepted.Origin, accepted.Sync = source.Origin, source.Sync
		if p.authorizeAppSourceStep(s, c, accepted, original, source.Task.Key) != nil || p.authorizeBindingVolumes(s, c, registry, accepted, n) != nil {
			return AppBindingPermit{}, access.ErrDenied
		}
	} else if p.authorizeBindingInView(s, c, registry, entry, e, source.Task.Key, n) != nil {
		return AppBindingPermit{}, access.ErrDenied
	}
	if source.Inputs.Key != "" {
		if retirement, retiring := entry.Inventory.Retirement(); retiring && !retirement.Preserves(source.Inputs.Key) {
			return AppBindingPermit{}, access.ErrDenied
		}
		input, ok := bindingClaim(entry, source.Inputs)
		o := s.Object(source.Inputs.Key)
		if !ok || input.Removed || !o.Present || o.Generation != source.Inputs.Generation || o.Revision != source.Inputs.Revision || o.Value != input.Command.Value || input.Observation != nil && input.Observation.Released {
			return AppBindingPermit{}, access.ErrDenied
		}
	}
	vault, err := p.Vault(s)
	if err != nil {
		return AppBindingPermit{}, err
	}
	if b.Check(a.bindings, c, vault.Trees, vault.Approvals, volumeStates(registry), request.At) != nil {
		return AppBindingPermit{}, access.ErrDenied
	}
	resources, err := p.Resources(s)
	if err != nil {
		return AppBindingPermit{}, access.ErrDenied
	}
	capacity, err := bindingCapacity(resources, n)
	if err != nil || capacity < 1 {
		return AppBindingPermit{}, access.ErrDenied
	}
	// A borrowed management bridge retains the reference pin as well as the
	// task's native pin. Check the same current shared view at the actual Start
	// authority edge, including after a quota shrink.
	var taskGoal deployment.GoalCommand
	if canonical([]byte(s.Object(source.Task.Key).Value), &taskGoal) != nil {
		return AppBindingPermit{}, access.ErrDenied
	}
	if source.Sync != nil && source.Sync.Local != nil {
		var service deployment.ComposeService
		if source.Sync.verify(source.Origin, entry.Inventory.Scope()) != nil || canonical(taskGoal.Config, &service) != nil || p.authorizeLocalNeeds(s, c, source.Sync.Local, n, service) != nil {
			return AppBindingPermit{}, access.ErrDenied
		}
	}
	var projection *ResourceProjection
	for _, dep := range taskGoal.Dependencies {
		if !strings.HasPrefix(dep.Key, "network/reference/") {
			continue
		}
		if projection == nil {
			current, err := p.projectResources(s, resources, a, registry)
			if err != nil || admitIngressConsumers(current, current.Goals[source.Task.Key]) != nil {
				return AppBindingPermit{}, access.ErrDenied
			}
			projection = &current
		}
		if checkCurrentNetworkReference(p.Cluster, s, *projection, projection.Goals[dep.Key]) != nil {
			return AppBindingPermit{}, access.ErrDenied
		}
	}
	raw, err := b.Encode()
	if err != nil {
		return AppBindingPermit{}, err
	}
	reads, err := p.bindingReads(s, vault, c, b, request.At)
	if err != nil {
		return AppBindingPermit{}, err
	}
	readBytes, _ := json.Marshal(reads)
	return AppBindingPermit{Task: source.Task, Inputs: source.Inputs, Binding: raw, MaxConsumers: capacity, ReadSet: sha256.Sum256(readBytes), CommandIndex: s.Index()}, nil
}

// AppInputReads uses a locally committed replica only if it contains the exact
// public read-set already authorized by the current owner-only quorum permit.
func (p Policy) AppInputReads(s state.State, caller [32]byte, request AppBindingRequest, permit AppBindingPermit) ([]AppInputRead, error) {
	local, err := p.AppBindingPermit(s, caller, request)
	if err != nil || s.Index() < permit.CommandIndex || local.Task != permit.Task || local.Inputs != permit.Inputs || local.ReadSet != permit.ReadSet || !bytes.Equal(local.Binding, permit.Binding) {
		return nil, access.ErrDenied
	}
	a, err := p.Apps(s)
	if err != nil {
		return nil, err
	}
	b, ok := a.Binding(request.Task)
	if !ok {
		return nil, access.ErrDenied
	}
	v, err := p.Vault(s)
	if err != nil {
		return nil, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, err
	}
	return p.bindingReads(s, v, c, b, request.At)
}

func (p Policy) MaterializeAppInputs(s state.State, caller [32]byte, request AppBindingRequest, permit AppBindingPermit, values []deployment.Fetched, maxBytes int) (deployment.Stage, error) {
	if _, err := p.AppInputReads(s, caller, request, permit); err != nil {
		return deployment.Stage{}, err
	}
	a, err := p.Apps(s)
	if err != nil {
		return deployment.Stage{}, err
	}
	b, ok := a.Binding(request.Task)
	if !ok {
		return deployment.Stage{}, access.ErrDenied
	}
	v, err := p.Vault(s)
	if err != nil {
		return deployment.Stage{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return deployment.Stage{}, err
	}
	volumes, err := p.Volumes(s)
	if err != nil {
		return deployment.Stage{}, err
	}
	return b.Materialize(a.bindings, c, v.Trees, v.Approvals, volumeStates(volumes), request.At, values, maxBytes)
}

// AppInputClosure verifies only the original owner's task termination. It is
// intentionally independent of current activation authority and quorum; the
// projection journal still must prove its own pins0 and actual file Gone.
func (p Policy) AppInputClosure(s state.State, caller [32]byte, request AppBindingRequest, observation deployment.Observation) (AppBindingSource, error) {
	a, err := p.Apps(s)
	if err != nil {
		return AppBindingSource{}, err
	}
	b, ok := a.Binding(request.Task)
	source, found := a.BindingSource(request.Digest)
	if !ok || !found || b.Digest() != request.Digest || source.Task != request.Task || !p.ownsResource(s, caller, b.Needs().Use.NodeKey) || request.At < 0 || !p.validBindingClosure(a.entries[appKey(b.Needs().Use.Tenant, b.Needs().Use.App)], source, observation, uint64(request.At)) {
		return AppBindingSource{}, access.ErrDenied
	}
	return source, nil
}

// builtinHeld is true when a published builtin revision has a holder that is
// a current voter: someone can still serve it.
func builtinHeld(members membership.Directory, tree secrets.Tree, r secrets.Reference) bool {
	h, ok := tree.BuiltinHolding(secrets.ValueWrite, r.Object, r.Revision)
	if !ok {
		return false
	}
	for _, v := range h.Holders {
		if members.VoterKey(v) {
			return true
		}
	}
	return false
}
