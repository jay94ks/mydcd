// SPDX-License-Identifier: Apache-2.0

package control

import (
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// ContainerRead carries a current user ceiling to the exact native owner. It is
// transient read input, not a new management operation or persistent grant.
type ContainerRead struct {
	Session access.Session
	Query   containerops.Query
	Target  containerops.Target
}

func (p Policy) ContainerTarget(s state.State, session access.Session, at int64, tenant string, q containerops.Query) (containerops.Target, error) {
	if q.Validate() != nil {
		return containerops.Target{}, access.ErrDenied
	}
	target, err := p.containerSelectionTarget(s, session, at, tenant, q.Selection)
	if err == nil && q.Kind == "inspect" {
		// A read-only native snapshot can show a new process incarnation and
		// drift without accepting it as lifecycle Start/Exit/fence evidence.
		target.StartedAt = ""
	}
	return target, err
}

// Shared lookup for finite observations and explicit container-operation plans.
// It resolves a logical owned Task, never an arbitrary Docker container ID.
func (p Policy) containerSelectionTarget(s state.State, session access.Session, at int64, tenant string, selection containerops.Selection) (containerops.Target, error) {
	deny := func() (containerops.Target, error) { return containerops.Target{}, access.ErrDenied }
	var err error
	p, err = p.Current(s)
	if err != nil || tenant == "" || !selection.Valid() {
		return deny()
	}
	catalog, err := p.Catalog(s)
	if err != nil || catalog.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, "") != nil {
		return deny()
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return containerops.Target{}, err
	}
	scope := selection.App
	if selection.Standalone != "" {
		var ok bool
		scope, ok = apps.StandaloneScope(tenant, selection.Standalone)
		if !ok {
			return containerops.Target{}, containerops.ErrTarget
		}
	} else if apps.IsStandalone(tenant, scope) {
		return deny()
	}
	var selected containerops.Target
	for _, source := range apps.sources {
		bound, ok := apps.Binding(source.Task)
		if !ok {
			continue
		}
		use := bound.Needs().Use
		if use.Tenant != tenant || use.App != scope || selection.Service != "" && use.Service != selection.Service || selection.Instance != "" && selection.Instance != source.Task.Key {
			continue
		}
		object := s.Object(source.Task.Key)
		if !object.Present || object.Generation != source.Task.Generation || object.Revision != source.Task.Revision {
			continue
		}
		var goal deployment.GoalCommand
		if canonical([]byte(object.Value), &goal) != nil || goal.Kind != "task" || goal.Cluster != p.Cluster || goal.Tenant != tenant || goal.App != use.App || goal.Node != use.Node || goal.Owner != use.NodeKey || !p.resourceNodeOwner(s, use.Node, use.NodeKey, true) {
			continue
		}
		if catalog.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, goal.Node) != nil {
			return deny()
		}
		claim, ok := apps.Claim(tenant, use.App, source.Task)
		if !ok || claim.Removed {
			continue
		}
		target := containerops.Target{Standalone: selection.Standalone, Cluster: p.Cluster, Owner: use.NodeKey, Binding: bound.Digest(), Tenant: tenant, App: use.App, Service: use.Service, Node: goal.Node, Instance: source.Task.Key, Generation: source.Task.Generation, Revision: source.Task.Revision, NativeID: claim.Native}
		if claim.Observation != nil {
			if claim.Observation.Native != "" {
				target.NativeID = claim.Observation.Native
			}
			if claim.Observation.StartedAt > 0 {
				target.StartedAt = time.Unix(0, claim.Observation.StartedAt).UTC().Format(time.RFC3339Nano)
			}
		}
		if !target.Valid() {
			return containerops.Target{}, containerops.ErrTarget
		}
		if selected.Instance != "" && selected != target {
			return containerops.Target{}, containerops.ErrTarget
		}
		selected = target
	}
	if selected.Instance == "" {
		return containerops.Target{}, containerops.ErrTarget
	}
	return selected, nil
}

func (p Policy) ContainerReadPermit(s state.State, caller [32]byte, read ContainerRead, at int64) (uint64, error) {
	if !read.Target.Valid() || !p.ownsResource(s, caller, read.Target.Owner) {
		return 0, access.ErrDenied
	}
	current, err := p.ContainerTarget(s, read.Session, at, read.Target.Tenant, read.Query)
	if err != nil || !current.Matches(read.Target) {
		return 0, access.ErrDenied
	}
	return s.Index(), nil
}
