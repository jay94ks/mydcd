// SPDX-License-Identifier: Apache-2.0

package control

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// AppPlanRequest is an authenticated read-only request. Large reply artifacts
// are paged with a fixed digest; changing current policy cannot mix two plans.
type AppPlanRequest struct {
	Standalone                *StandaloneDefinition `json:",omitempty"`
	SourceEnvelope            bool                  `json:",omitempty"` // User stream framing only; cleared after authenticated body decode
	PrepareSources            bool                  `json:",omitempty"`
	SourceProvider            *[32]byte             `json:",omitempty"`
	Move                      *AppMovePlanRequest   `json:",omitempty"`
	Document                  []byte
	Project, Deployment, Node string
	Part                      int
	Digest                    [32]byte
	External                  map[string]map[string]deployment.NetworkBinding `json:",omitempty"`
	Diff                      bool                                            `json:",omitempty"`
	CheckerSources            map[string]checker.SourceFact                   `json:",omitempty"`
}
type AppPlanPart struct {
	Digest [32]byte
	Length int
	Part   int
	Data   []byte
}

// AppDiff is a read-only comparison against the same committed inventory used
// by Begin. A diff neither reserves resources nor authorizes a later mutation.
type AppDiff struct {
	Schema                          uint8
	Tenant, App, Deployment         string
	RootRevision, InventoryRevision uint64
	Plan                            [32]byte
	Changes                         []deployment.Change
	SecretEnvRequiresNewGeneration  []string                    `json:",omitempty"`
	Replacement                     *deployment.ReplacementPlan `json:",omitempty"`
	// IgnoredAutomationRoutes: "ROUTE HOSTPREFIX" of ingress routes at or
	// under /.well-known/acme-challenge; certificate automation keeps that
	// path for registered-domain hosts, so they are ignored there (warning).
	IgnoredAutomationRoutes []string `json:",omitempty"`
}

func DecodeAppDiff(raw []byte) (AppDiff, error) {
	var d AppDiff
	if len(raw) > deployment.ArtifactMaxBytes || canonical(raw, &d) != nil || d.Schema != 1 || d.Tenant == "" || d.App == "" || d.Deployment == "" || d.Plan == ([32]byte{}) {
		return AppDiff{}, ErrCatalog
	}
	if d.Replacement != nil && !d.Replacement.Valid(d.Tenant, d.App) {
		return AppDiff{}, ErrCatalog
	}
	return d, nil
}

func (p Policy) PlanApp(s state.State, session access.Session, at int64, tenant string, r AppPlanRequest) (AppPlanPart, error) {
	if len(r.Document) > deployment.ArtifactPartBytes || r.Part < 0 {
		return AppPlanPart{}, ErrCatalog
	}
	raw, err := p.AppPlanArtifact(s, session, at, tenant, r)
	if err != nil {
		return AppPlanPart{}, err
	}
	digest := sha256.Sum256(raw)
	if r.Part >= (len(raw)+deployment.ArtifactPartBytes-1)/deployment.ArtifactPartBytes {
		return AppPlanPart{}, ErrCatalog
	}
	start := r.Part * deployment.ArtifactPartBytes
	return AppPlanPart{digest, len(raw), r.Part, raw[start:min(len(raw), start+deployment.ArtifactPartBytes)]}, nil
}

// AppPlanArtifact compiles a single authenticated read snapshot. Stream adapters
// may supply a complete bounded document after authenticating its digest/EOF;
// ordinary PlanApp retains its original per-frame input budget.
func (p Policy) AppPlanArtifact(s state.State, session access.Session, at int64, tenant string, r AppPlanRequest) ([]byte, error) {
	current, err := p.Current(s)
	if err != nil {
		return nil, err
	}
	p = current
	if r.SourceEnvelope || r.Move != nil || len(r.Document) == 0 || len(r.Document) > deployment.ArtifactMaxBytes || r.Part < 0 {
		return nil, ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Deploy, "") != nil {
		return nil, access.ErrDenied
	}
	parse := deployment.ParseApp
	if r.Standalone != nil {
		parse = deployment.ParseStandalone
	}
	input, err := parse(r.Document)
	if err != nil {
		return nil, err
	}
	ctx, err := p.AppPlanning(s, session.User, tenant)
	if err != nil {
		return nil, err
	}
	ctx.Project, ctx.Deployment, ctx.DefaultNode, ctx.ExternalNetworks = r.Project, r.Deployment, r.Node, r.External
	ctx.CheckerSources = r.CheckerSources
	if r.PrepareSources {
		if r.Diff || len(r.CheckerSources) != 0 || r.SourceProvider == nil {
			return nil, ErrCatalog
		}
		if !ctx.Features["lifecycle"] {
			return nil, &deployment.InputError{Code: "FEATURE_UNAVAILABLE", Path: "lifecycle"}
		}
		if input.MyDC.Tenant != "" && input.MyDC.Tenant != tenant {
			return nil, access.ErrDenied
		}
		input.MyDC.Tenant = tenant
		if _, err := input.ResolveLifecycle(ctx.Checkers); err != nil {
			return nil, err
		}
		program, _, err := input.LifecycleProgram()
		if err != nil {
			return nil, err
		}
		requirements := AppSourcePlan{Schema: 1, Cluster: p.Cluster, User: session.User, Tenant: tenant,
			Document: sha256.Sum256(r.Document), Sources: map[string]checker.SourceDescriptor{}}
		for alias, script := range program.Scripts {
			if script.Ref != nil {
				continue
			}
			d, err := script.Descriptor(tenant)
			if err != nil {
				return nil, err
			}
			if _, err := p.LifecycleSourcePermit(s, *r.SourceProvider, LifecycleSourcePermitRequest{Session: session, Source: d, At: at}); err != nil {
				return nil, err
			}
			requirements.Sources[alias] = d
		}
		return json.Marshal(requirements)
	}
	if r.SourceProvider != nil {
		return nil, ErrCatalog
	}
	var plan deployment.Blueprint
	if r.Standalone != nil {
		apps, e := p.readOnlyApps(s)
		if e != nil {
			return nil, e
		}
		if scope, found := apps.StandaloneScope(tenant, r.Standalone.Name); found {
			ctx.Project = scope
		} else {
			ctx.Project = deployment.StandaloneScopeName(tenant, r.Standalone.Name)
		}
		plan, err = deployment.CompileStandaloneDocument(r.Document, r.Standalone.Name, c, ctx, r.Standalone.Mode)
	} else {
		// An update keeps the app's deployment; a new app's is its name.
		if name := cmp.Or(input.Name, r.Project); ctx.Deployment == "" && name != "" {
			apps, e := p.readOnlyApps(s)
			if e != nil {
				return nil, e
			}
			if entry, exists := apps.entries[appKey(tenant, name)]; exists && entry.Standalone == nil {
				ctx.Deployment = entry.Inventory.Scope().Deployment
			}
		}
		plan, err = deployment.CompileAppDocument(r.Document, c, ctx)
	}
	if err == nil {
		apps, e := p.readOnlyApps(s)
		if e != nil {
			return nil, e
		}
		if entry, exists := apps.entries[appKey(tenant, plan.Scope().App)]; exists && (entry.Standalone == nil) != (r.Standalone == nil) {
			return nil, access.ErrConflict
		}
	}
	if err != nil {
		return nil, err
	}
	if err := p.admitIngressBlueprint(s, plan); err != nil {
		return nil, err
	}
	if r.Standalone != nil {
		node := r.Node
		for _, step := range plan.Steps() {
			if step.Kind == "task" {
				node = step.Node
			}
		}
		if _, e := r.Standalone.metadata(tenant, session.User, node, at); e != nil {
			return nil, e
		}
		apps, e := p.readOnlyApps(s)
		if e != nil {
			return nil, e
		}
		if _, _, exists := apps.standalone(tenant, r.Standalone.Name); !exists {
			if e = standaloneQuota(apps, tenant, session.User, node, r.Standalone.Lifetime); e != nil {
				return nil, e
			}
		}
	}
	if err := p.imageCacheBlueprintAvailable(s, plan); err != nil && !r.Diff {
		return nil, err
	}
	for _, step := range plan.Steps() {
		if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, step.Action(), step.Node) != nil {
			return nil, access.ErrDenied
		}
	}
	if r.Standalone != nil {
		apps, err := p.readOnlyApps(s)
		if err != nil {
			return nil, err
		}
		if err := admitAppVolumeConsumers(plan, session.Key, ctx.Volumes, apps); err != nil {
			return nil, err
		}
	}
	raw, err := plan.Encode()
	if err != nil {
		return nil, err
	}
	if r.Diff {
		apps, err := p.Apps(s)
		if err != nil {
			return nil, err
		}
		scope := plan.Scope()
		i, exists := apps.Inventory(tenant, scope.App)
		var revision uint64
		if exists {
			revision = i.Revision()
		} else {
			i, err = deployment.NewInventory(p.Cluster, tenant, scope.App, scope.Deployment)
			if err != nil {
				return nil, err
			}
		}
		changes, err := i.Changes(plan, false)
		if err != nil {
			return nil, err
		}
		replacement, err := i.ReplacementPlan(plan, false)
		if err != nil {
			return nil, err
		}
		raw, err = json.Marshal(AppDiff{Schema: 1, Tenant: tenant, App: scope.App, Deployment: scope.Deployment, RootRevision: s.Object(AppsKey).Revision, InventoryRevision: revision, Plan: plan.Digest(), Changes: changes, SecretEnvRequiresNewGeneration: plan.SecretEnvironmentServices(), Replacement: replacement, IgnoredAutomationRoutes: plan.AutomationPathRoutes()})
		if err != nil {
			return nil, err
		}
	}
	if len(raw) == 0 || len(raw) > deployment.ArtifactMaxBytes {
		return nil, ErrCatalog
	}
	digest := sha256.Sum256(raw)
	if r.Digest != ([32]byte{}) && r.Digest != digest {
		return nil, access.ErrConflict
	}
	return raw, nil
}
