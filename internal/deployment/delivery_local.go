// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
)

// LocalServicesDocument is the separately accepted local source of services.
// Original Git bytes and accepted Running inputs are never edited in place.
type LocalServicesDocument struct {
	Revision uint64
	Actor    string
	Digest   [32]byte
	Body     []byte
}

func ownLocalServices(d *LocalServicesDocument) *LocalServicesDocument {
	if d == nil {
		return nil
	}
	n := *d
	n.Body = bytes.Clone(d.Body)
	return &n
}

func localServicesInput(d *LocalServicesDocument) (Compose, error) {
	if d == nil || d.Revision == 0 || !identifier(d.Actor) || len(d.Body) == 0 || len(d.Body) > ArtifactMaxBytes || sha256.Sum256(d.Body) != d.Digest {
		return Compose{}, ErrInputs
	}
	c, err := ParseApp(d.Body)
	if err != nil {
		return Compose{}, err
	}
	// Only new service declarations and references are contributed. No local
	// app root may reconfigure the registered source or the Git app's policy.
	if c.Sfc.Delivery != nil || c.Sfc.Ingress != nil || c.Sfc.Vault != nil || c.Sfc.Routing != nil || len(c.Sfc.Nodes) != 0 || len(c.Sfc.Registries) != 0 {
		return Compose{}, inputError("CD_LOCAL_SERVICES_ONLY", "x-sfc")
	}
	for name, n := range c.Networks {
		if !n.External {
			return Compose{}, inputError("MANAGED_NETWORK_REFERENCE_REQUIRED", name)
		}
	}
	for name, v := range c.Volumes {
		if !v.External {
			return Compose{}, inputError("CD_LOCAL_VOLUME_REFERENCE_REQUIRED", name)
		}
	}
	for name, s := range c.Secrets {
		if s.File != "" {
			return Compose{}, inputError("INLINE_SECRET_FORBIDDEN", name)
		}
	}
	if c.Sfc.Lifecycle != nil && len(c.Sfc.Lifecycle.Checks) != 0 {
		return Compose{}, inputError("CD_LOCAL_GLOBAL_CHECK_FORBIDDEN", "x-sfc.lifecycle.checks")
	}
	return c, nil
}

func mergeLocalAliases[T any](target map[string]T, additions map[string]T) (map[string]T, error) {
	if len(additions) == 0 {
		return target, nil
	}
	if target == nil {
		target = map[string]T{}
	}
	for name, value := range additions {
		if old, exists := target[name]; exists && !bytes.Equal(goal(old), goal(value)) {
			return nil, inputError("CD_LOCAL_ALIAS_CONFLICT", name)
		}
		target[name] = value
	}
	return target, nil
}

func mergeLocalServices(input Compose, local *LocalServicesDocument, scope AppScope) (Compose, error) {
	if local == nil {
		return input, nil
	}
	addition, err := localServicesInput(local)
	if err != nil {
		return Compose{}, err
	}
	if scope.App == "" {
		scope.App = input.Name
	}
	if scope.Tenant == "" {
		scope.Tenant = input.Sfc.Tenant
	}
	if scope.Deployment == "" {
		scope.Deployment = input.Sfc.Deployment
	}
	for _, pair := range [][2]string{{addition.Name, scope.App}, {addition.Sfc.Tenant, scope.Tenant}, {addition.Sfc.Deployment, scope.Deployment}} {
		if pair[0] != "" && pair[1] != "" && pair[0] != pair[1] {
			return Compose{}, inputError("CD_LOCAL_SCOPE_CONFLICT", "scope")
		}
	}
	// Own the source's entire model before extending maps. Artifact cache
	// readers and historical candidates must never acquire the new services.
	raw, err := json.Marshal(input)
	var merged Compose
	if err != nil || json.Unmarshal(raw, &merged) != nil {
		return Compose{}, ErrInputs
	}
	if merged.Services == nil {
		merged.Services = map[string]ComposeService{}
	}
	for name, service := range addition.Services {
		if _, exists := merged.Services[name]; exists {
			return Compose{}, inputError("CD_LOCAL_SERVICE_NAME_CONFLICT", name)
		}
		for dependency := range service.DependsOn {
			if _, local := addition.Services[dependency]; !local {
				return Compose{}, inputError("CD_LOCAL_GIT_DEPENDENCY_FORBIDDEN", dependency)
			}
		}
		merged.Services[name] = service
	}
	merged.Networks, err = mergeLocalAliases(merged.Networks, addition.Networks)
	if err == nil {
		merged.Volumes, err = mergeLocalAliases(merged.Volumes, addition.Volumes)
	}
	if err == nil {
		merged.Secrets, err = mergeLocalAliases(merged.Secrets, addition.Secrets)
	}
	if err != nil {
		return Compose{}, err
	}
	if declaration := addition.Sfc.Lifecycle; declaration != nil {
		if merged.Sfc.Lifecycle == nil {
			merged.Sfc.Lifecycle = &LifecycleDeclaration{Optimizer: declaration.Optimizer}
		}
		l := merged.Sfc.Lifecycle
		if declaration.Optimizer != nil && !bytes.Equal(goal(declaration.Optimizer), goal(l.Optimizer)) {
			return Compose{}, inputError("CD_LOCAL_OPTIMIZER_CONFLICT", "lifecycle")
		}
		l.Scripts, err = mergeLocalAliases(l.Scripts, declaration.Scripts)
		if err == nil {
			l.Templates, err = mergeLocalAliases(l.Templates, declaration.Templates)
		}
		if err != nil {
			return Compose{}, err
		}
	}
	if err = merged.validate(); err != nil {
		return Compose{}, err
	}
	return merged, nil
}

func (d Delivery) LocalServices() *LocalServicesDocument { return ownLocalServices(d.d.LocalServices) }
func (d Delivery) LocalRevision() uint64                 { return d.d.LocalRevision }

func (d Delivery) localConflict() bool {
	return d.d.SourceError == "name-conflict" || d.d.SourceError == "alias-conflict"
}

// PutLocalServices changes only the future effective candidate. Normal sync
// still owns original retirement, reservations and native execution. Empty
// body explicitly clears all local additions; it does not stop them itself.
func (d Delivery) PutLocalServices(expected, previous uint64, c access.Catalog, ctx PlanningContext, actor string, body []byte) (Delivery, error) {
	if expected != d.Revision() || previous != d.d.LocalRevision || d.d.LocalRevision == ^uint64(0) || !d.scope(c, ctx) || !d.overrideIdle() || d.d.Candidate == nil || d.d.Candidate.Plan.InputKind != "app" || c.Authorize(actor, d.d.Inventory.Tenant, access.Deploy, "") != nil {
		return d, ErrInputs
	}
	if d.d.LocalServices == nil && len(body) == 0 || d.d.LocalServices != nil && bytes.Equal(d.d.LocalServices.Body, body) {
		return d, nil
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.d.LocalRevision++
	n.d.LocalServices = nil
	if len(body) != 0 {
		n.d.LocalServices = &LocalServicesDocument{Revision: n.d.LocalRevision, Actor: actor, Digest: sha256.Sum256(body), Body: bytes.Clone(body)}
		if _, err = localServicesInput(n.d.LocalServices); err != nil {
			return d, err
		}
	}
	candidate, err := n.compile(c, ctx, n.d.Candidate.Artifact)
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Candidate, n.d.Approval = &candidate, nil
	return n, nil
}
