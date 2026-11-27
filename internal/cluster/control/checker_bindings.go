// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

func CheckerBindingUse(b deployment.Binding) (checker.Use, bool) {
	n := b.Needs()
	if n.Lifecycle == nil {
		return checker.Use{}, false
	}
	parent := b.Digest()
	id := sha256.Sum256(append([]byte("sfc-checker-binding-use-1\x00"), parent[:]...))
	selection := n.Lifecycle.Clone()
	return checker.Use{Tenant: n.Use.Tenant, ID: hex.EncodeToString(id[:]), Kind: "app-binding", Principal: n.Use.User, Node: n.Use.Node, Owner: n.Use.NodeKey, Parent: parent, PolicyRevision: selection.PolicyRevision, Scripts: selection.Scripts, Sources: selection.Sources}, true
}

func sameCheckerUse(a, b checker.Use) bool { return a.Digest() == b.Digest() }

func validateCheckerBindings(apps Apps, book checker.Catalog) error {
	for _, entry := range apps.entries {
		if execution, ok := entry.Inventory.Execution(); ok {
			if execution.Blueprint().ValidateLifecycleCatalog(book) != nil {
				return ErrCatalog
			}
		}
		for _, claim := range entry.Inventory.Claims() {
			if claim.Step.Kind != "task" {
				continue
			}
			var goal deployment.GoalCommand
			var service deployment.ComposeService
			if json.Unmarshal([]byte(claim.Command.Value), &goal) != nil || json.Unmarshal(goal.Config, &service) != nil {
				return ErrCatalog
			}
			if service.LifecycleProgram != nil {
				program := service.LifecycleProgram
				scope := entry.Inventory.Scope()
				selection, err := program.Selection()
				instance, identityErr := deployment.TaskInstanceForKey(scope.Tenant, scope.App, claim.Step.Key, service)
				if program.ValidateCatalog(book) != nil || program.Cluster != scope.Cluster || program.Tenant != scope.Tenant || identityErr != nil || instance.Service != program.Service || instance.Node != claim.Step.Node || err != nil || (selection == nil) != (service.LifecycleSources == nil) || selection != nil && !selection.Equal(*service.LifecycleSources) {
					return ErrCatalog
				}
			} else if service.LifecycleSources != nil {
				return ErrCatalog
			}
		}
	}
	expected := map[[32]byte]checker.Use{}
	for _, b := range apps.bindings.Live() {
		u, ok := CheckerBindingUse(b)
		if !ok {
			continue
		}
		actual, found := book.Use(u.Tenant, u.ID)
		if !found || !sameCheckerUse(actual, u) {
			return ErrCatalog
		}
		expected[u.Digest()] = u
	}
	for _, u := range book.Uses() {
		if u.Kind == "app-binding" {
			if _, ok := expected[u.Digest()]; !ok {
				return ErrCatalog
			}
		}
	}
	return validateCheckerBuildParents(apps, book)
}

func (p Policy) reserveCheckerBinding(s state.State, book checker.Catalog, b deployment.Binding) (checker.Catalog, error) {
	u, ok := CheckerBindingUse(b)
	if !ok {
		return book, nil
	}
	if old, exists := book.Use(u.Tenant, u.ID); exists {
		if !sameCheckerUse(old, u) {
			return book, access.ErrDenied
		}
		return book, nil
	}
	users, err := p.Catalog(s)
	if err != nil || users.Authorize(u.Principal, u.Tenant, access.ManageServices, u.Node) != nil {
		return book, access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(u.Owner) {
		return book, access.ErrDenied
	}
	if !p.resourceNodeOwner(s, u.Node, u.Owner, true) {
		return book, access.ErrDenied
	}
	if _, ok := book.AdmissionPolicy(u.Tenant, u.PolicyRevision); !ok {
		return book, access.ErrDenied
	}
	for _, f := range u.Sources {
		if p.currentResourceKey(s, f.Owner, true) == ([32]byte{}) {
			return book, access.ErrDenied
		}
	}
	for _, ref := range u.Scripts {
		record, found := book.Script(u.Tenant, ref.Name)
		if !found {
			return book, access.ErrDenied
		}
		found = false
		for _, v := range record.Versions {
			if v.Revision == ref.Revision && p.currentResourceKey(s, v.Source.Owner, true) != ([32]byte{}) {
				found = true
				break
			}
		}
		if !found {
			return book, access.ErrDenied
		}
	}
	return book.Reserve(u)
}

// CheckerArtifactRequest identifies bytes or a recipe-scoped cache lookup
// under an already accepted use.
// Peer identity/current parent remain mandatory; this is not a bearer token.
type CheckerArtifactRequest struct {
	Schema        uint8
	Tenant, UseID string
	Use, Content  [32]byte
	Consumer      [32]byte
	Module        *checker.ModulePin    `json:",omitempty"`
	Compiled      *checker.CompiledFact `json:",omitempty"`
	Lookup        *CheckerCacheLookup   `json:",omitempty"`
	MinimumIndex  uint64
	At            int64
}
type CheckerCacheLookup struct {
	Provider [32]byte
	Recipe   checker.CompileRecipe
}

func (q CheckerCacheLookup) Clone() CheckerCacheLookup {
	q.Recipe.Flags = slices.Clone(q.Recipe.Flags)
	return q
}

type CheckerArtifactPermit struct {
	Schema              uint8
	Use, Parent         [32]byte
	Tenant, UseID, Node string
	Consumer            [32]byte
	Source              checker.SourceFact
	Policy              checker.TenantPolicy
	Index               uint64
	Compiled            *checker.CompiledFact `json:",omitempty"`
	Lookup              *CheckerCacheLookup   `json:",omitempty"`
}

func (p CheckerArtifactPermit) Provider() [32]byte {
	if p.Lookup != nil {
		return p.Lookup.Provider
	}
	if p.Compiled != nil {
		return p.Compiled.Owner
	}
	return p.Source.Owner
}

func (p Policy) CheckerArtifactPermit(s state.State, caller [32]byte, q CheckerArtifactRequest) (CheckerArtifactPermit, error) {
	if q.Schema != 1 || q.At < 0 || q.MinimumIndex == 0 || s.Index() < q.MinimumIndex || q.Consumer == ([32]byte{}) || q.Content == ([32]byte{}) || q.Module != nil && q.Compiled != nil || q.Lookup != nil && (q.Module != nil || q.Compiled != nil) {
		return CheckerArtifactPermit{}, access.ErrDenied
	}
	book, err := p.Lifecycles(s)
	if err != nil {
		return CheckerArtifactPermit{}, err
	}
	u, ok := book.Use(q.Tenant, q.UseID)
	if !ok || u.Digest() != q.Use || u.Owner != q.Consumer {
		return CheckerArtifactPermit{}, access.ErrDenied
	}
	var program *checker.TaskProgram
	if u.Kind == "build-job" {
		job, ok := book.BuildJob(u.Tenant, u.ID)
		if q.Compiled != nil || q.Lookup != nil || !ok || job.Phase == "closed" || job.Intent.Digest() != u.Parent {
			return CheckerArtifactPermit{}, access.ErrDenied
		}
		if _, err := p.checkerBuildContext(s, job.Intent, q.At); err != nil {
			return CheckerArtifactPermit{}, err
		}
	} else if u.Kind == "app-binding" {
		apps, err := p.readOnlyApps(s)
		if err != nil {
			return CheckerArtifactPermit{}, err
		}
		b, ok := apps.binding(u.Parent)
		if !ok {
			return CheckerArtifactPermit{}, access.ErrDenied
		}
		want, ok := CheckerBindingUse(b)
		if !ok || !sameCheckerUse(want, u) {
			return CheckerArtifactPermit{}, access.ErrDenied
		}
		var task deployment.ObjectRef
		for _, source := range apps.sources {
			if source.Digest == u.Parent {
				task = source.Task
				break
			}
		}
		if _, err := p.AppBindingPermit(s, p.resourceCallerForNode(s, u.Node, u.Owner), AppBindingRequest{Task: task, Digest: u.Parent, At: q.At}); err != nil {
			return CheckerArtifactPermit{}, err
		}
		if q.Compiled != nil || q.Lookup != nil {
			var goal deployment.GoalCommand
			var service deployment.ComposeService
			if canonical([]byte(s.Object(task.Key).Value), &goal) != nil || canonical(goal.Config, &service) != nil || service.LifecycleProgram == nil || service.LifecycleProgram.ValidateCatalog(book) != nil {
				return CheckerArtifactPermit{}, access.ErrDenied
			}
			program = service.LifecycleProgram
		}
	} else {
		return CheckerArtifactPermit{}, access.ErrDenied
	}
	fact, policy, err := book.SourceForUse(u, q.Content)
	if err != nil {
		return CheckerArtifactPermit{}, access.ErrDenied
	}
	provider := fact.Owner
	if q.Lookup != nil {
		if q.Lookup.Provider == ([32]byte{}) || checkerRecipeProgramAllowed(program, policy, q.Content, q.Lookup.Recipe) != nil {
			return CheckerArtifactPermit{}, access.ErrDenied
		}
		provider = q.Lookup.Provider
	}
	if q.Compiled != nil {
		if ValidateCheckerCompiledMetadata(book, program, policy, q.Content, *q.Compiled) != nil {
			return CheckerArtifactPermit{}, access.ErrDenied
		}
		provider = q.Compiled.Owner
	}
	if !p.ownsResource(s, caller, q.Consumer) && !p.ownsResource(s, caller, provider) {
		return CheckerArtifactPermit{}, access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(caller) || p.currentResourceKey(s, q.Consumer, true) == ([32]byte{}) || p.currentResourceKey(s, provider, true) == ([32]byte{}) {
		return CheckerArtifactPermit{}, access.ErrDenied
	}
	if !p.resourceNodeOwner(s, u.Node, u.Owner, true) {
		return CheckerArtifactPermit{}, access.ErrDenied
	}
	if q.Module != nil {
		found := false
		for _, pin := range fact.Modules {
			if pin == *q.Module {
				found = true
				break
			}
		}
		if !found || q.Module.Length > checker.MaxModuleBytes {
			return CheckerArtifactPermit{}, access.ErrDenied
		}
	}
	permit := CheckerArtifactPermit{Schema: 1, Use: u.Digest(), Parent: u.Parent, Tenant: u.Tenant, UseID: u.ID, Node: u.Node, Consumer: u.Owner, Source: fact, Policy: policy, Index: s.Index()}
	if q.Compiled != nil {
		copy := q.Compiled.Clone()
		permit.Compiled = &copy
	}
	if q.Lookup != nil {
		copy := q.Lookup.Clone()
		permit.Lookup = &copy
	}
	return permit, nil
}

// ValidateCheckerCompiledMetadata checks the frozen compiled program, current
// policy and committed build provenance. It issues no permission: callers must
// independently authorize the current Task/use, member pair and actual effect.
func ValidateCheckerCompiledMetadata(book checker.Catalog, program *checker.TaskProgram, current checker.TenantPolicy, content [32]byte, fact checker.CompiledFact) error {
	if program == nil || fact.Verify() != nil || fact.Build.Cluster != book.Cluster() || fact.Build.Recipe.Tenant != program.Tenant || fact.Build.Recipe.Source != content || book.CompiledOrigin(fact.Build) != nil {
		return access.ErrDenied
	}
	return checkerRecipeProgramAllowed(program, current, content, fact.Build.Recipe)
}

func checkerRecipeProgramAllowed(program *checker.TaskProgram, current checker.TenantPolicy, content [32]byte, r checker.CompileRecipe) error {
	if program == nil || r.Validate() != nil || r.Tenant != program.Tenant || r.Source != content {
		return access.ErrDenied
	}
	target := r.GOOS + "/" + r.GOARCH
	currentImage, currentErr := access.PinImage(current.Build.Image)
	originalImage, originalErr := access.PinImage(program.Policy.Build.Image)
	if !current.Enabled || current.Tenant != program.Tenant || currentErr != nil || originalErr != nil || currentImage.Reference != r.Image || current.Build.Toolchain != r.Toolchain || !slices.Contains(current.Build.Targets, target) || originalImage.Reference != r.Image || program.Policy.Build.Toolchain != r.Toolchain || !slices.Contains(program.Policy.Build.Targets, target) {
		return access.ErrDenied
	}
	for alias, script := range program.Scripts {
		if source, ok := program.Sources[alias]; ok && script.Compile && source.ContentDigest() == content {
			return nil
		}
	}
	return access.ErrDenied
}

func (a CheckerArtifactPermit) Equal(b CheckerArtifactPermit) bool {
	a.Index, b.Index = 0, 0
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
