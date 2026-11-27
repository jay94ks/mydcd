// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
)

// These are transient quorum queries, not replicated terminal data or another
// operation log. Only the exact owner can ask for a live/status permit.
type ContainerSessionPlan struct {
	Session   access.Session
	Tenant    string
	Selection containerops.Selection
	Spec      containerops.SessionSpec
}

type ContainerSessionPermit struct {
	Session  access.Session
	Original access.Session
	Intent   containerops.SessionIntent
	Status   bool
}

func (p Policy) ContainerSessionTarget(s state.State, q ContainerSessionPlan, at int64) (containerops.Target, error) {
	if q.Spec.Validate() != nil || q.Spec.Query != nil && q.Spec.Query.Selection != q.Selection {
		return containerops.Target{}, access.ErrDenied
	}
	t, err := p.containerSelectionTarget(s, q.Session, at, q.Tenant, q.Selection)
	if err != nil || t.NativeID == "" || t.StartedAt == "" {
		return containerops.Target{}, containerops.ErrTarget
	}
	if q.Spec.Kind == "exec" || q.Spec.Kind == "attach" {
		if q.Spec.Kind == "attach" && t.Standalone == "" {
			return containerops.Target{}, access.ErrDenied
		}
		p, err = p.Current(s)
		if err != nil {
			return containerops.Target{}, err
		}
		apps, ae := p.readOnlyApps(s)
		if ae != nil {
			return containerops.Target{}, ae
		}
		entry := apps.entries[appKey(q.Tenant, t.App)]
		catalog, err := p.Catalog(s)
		if !standaloneActivationAllowed(entry, at) || !standaloneActor(catalog, entry, q.Session.User) {
			return containerops.Target{}, access.ErrDenied
		}
		if err != nil || catalog.OperationAllowed(q.Session, "container-exec") != nil || catalog.AuthorizeSession(q.Session, p.Cluster, p.Issuer(q.Session.Issuer), at, q.Tenant, access.Deploy, t.Node) != nil {
			return containerops.Target{}, access.ErrDenied
		}
	}
	return t, nil
}

// ContainerSessionSelection keeps the signed native target's owner kind and
// exact Task. A standalone public rename changes neither its scope nor native.
func (p Policy) ContainerSessionSelection(s state.State, target containerops.Target) (containerops.Selection, error) {
	selection := containerops.Selection{App: target.App, Service: target.Service, Instance: target.Instance}
	if target.Standalone != "" {
		apps, err := p.readOnlyApps(s)
		if err != nil {
			return containerops.Selection{}, err
		}
		name, ok := apps.StandaloneName(target.Tenant, target.App)
		if !ok {
			return containerops.Selection{}, access.ErrDenied
		}
		selection.Standalone, selection.App = name, ""
	}
	if !selection.Valid() {
		return containerops.Selection{}, access.ErrDenied
	}
	return selection, nil
}

func (p Policy) ContainerSessionPermit(s state.State, caller [32]byte, q ContainerSessionPermit, at int64) (uint64, error) {
	i := q.Intent
	if i.Verify(q.Original.Key) != nil || access.VerifyOriginalSession(q.Original, p.Cluster, i.At) != nil || i.Session != access.ExactSessionDigest(q.Original) || i.User != q.Original.User || i.Target.Cluster != p.Cluster || !p.ownsResource(s, caller, i.Target.Owner) || q.Session.User != i.User {
		return 0, access.ErrDenied
	}
	var err error
	p, err = p.Current(s)
	if err != nil {
		return 0, err
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return 0, access.ErrDenied
	}
	if q.Status {
		if i.Spec.Kind != "exec" {
			return 0, access.ErrDenied
		}
		catalog, err := p.Catalog(s)
		if err != nil || catalog.AuthorizeSessionCleanup(q.Session, p.Cluster, p.Issuer(q.Session.Issuer), at, i.Target.Tenant, access.Read) != nil || catalog.AuthorizeSessionCleanup(q.Session, p.Cluster, p.Issuer(q.Session.Issuer), at, i.Target.Tenant, access.Deploy) != nil {
			return 0, access.ErrDenied
		}
		return s.Index(), nil
	}
	if access.ExactSessionDigest(q.Session) != i.Session {
		return 0, access.ErrDenied
	}
	selection, err := p.ContainerSessionSelection(s, i.Target)
	if err != nil {
		return 0, err
	}
	resolvedSpec := i.Spec
	if i.Spec.Query != nil {
		// Initial ambiguity is checked at resolve. A live session never
		// selects again when another instance appears: keep its exact Task.
		query := *i.Spec.Query
		query.Selection = selection
		resolvedSpec.Query = &query
	}
	t, err := p.ContainerSessionTarget(s, ContainerSessionPlan{Session: q.Session, Tenant: i.Target.Tenant, Selection: selection, Spec: resolvedSpec}, at)
	if err != nil || !t.Matches(i.Target) {
		return 0, access.ErrDenied
	}
	return s.Index(), nil
}
