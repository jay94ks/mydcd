// SPDX-License-Identifier: Apache-2.0

package control

import (
	"net/netip"
	"sort"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/servicecall"
)

type ServiceCallRead struct {
	Session access.Session
	Tenant  string
	Request servicecall.Request
	Target  servicecall.Target
	Epoch   uint64
}

func (p Policy) ServiceCallTarget(s state.State, session access.Session, at int64, tenant string, q servicecall.Request, preferred [32]byte) (servicecall.Target, error) {
	var out servicecall.Target
	var err error
	p, err = p.Current(s)
	if err != nil {
		return out, err
	}
	if !validID(tenant) || !q.Valid() {
		return out, access.ErrInvalid
	}
	c, err := p.Catalog(s)
	if err != nil || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.CallService, "") != nil || c.OperationAllowed(session, "service-call") != nil {
		return out, access.ErrDenied
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return out, err
	}
	members, err := p.Members(s)
	if err != nil {
		return out, err
	}
	var candidates []servicecall.Target
	for _, source := range apps.sources {
		bound, ok := apps.Binding(source.Task)
		if !ok {
			continue
		}
		use := bound.Needs().Use
		if use.Tenant != tenant || use.App != q.App || use.Service != q.Service {
			continue
		}
		object := s.Object(source.Task.Key)
		var goal deployment.GoalCommand
		if !object.Present || object.Generation != source.Task.Generation || object.Revision != source.Task.Revision || canonical([]byte(object.Value), &goal) != nil || goal.Kind != "task" || goal.Cluster != p.Cluster || goal.Tenant != tenant || goal.App != q.App || goal.Node != use.Node || goal.Owner != use.NodeKey || !members.WorkKey(goal.Owner) || goal.Lifecycle != nil && goal.Lifecycle.Drain {
			continue
		}
		if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.CallService, goal.Node) != nil {
			continue
		}
		claim, ok := apps.Claim(tenant, q.App, source.Task)
		if !ok || claim.Removed || claim.Observation == nil {
			continue
		}
		observed := claim.Observation
		if !observed.Applied || !observed.Healthy || observed.Released || observed.Stopped || observed.Gone || observed.Exit != nil || at <= 0 || !observed.Live(uint64(at)) {
			continue
		}
		var service deployment.ComposeService
		if canonical(goal.Config, &service) != nil || len(service.Networks) != 1 {
			continue
		}
		var address netip.Addr
		for _, network := range service.Networks {
			address, _ = netip.ParseAddr(network.IPv4)
			if !address.IsValid() {
				address, _ = netip.ParseAddr(network.IPv6)
			}
		}
		native := observed.Native
		if native == "" {
			native = claim.Native
		}
		target := servicecall.Target{Container: containerops.Target{Cluster: p.Cluster, Owner: goal.Owner, Binding: bound.Digest(), Tenant: tenant, App: q.App, Service: q.Service, Node: goal.Node, Instance: source.Task.Key, Generation: source.Task.Generation, Revision: source.Task.Revision, NativeID: native}, Address: address, Port: uint16(q.Port)}
		if observed.StartedAt > 0 {
			target.Container.StartedAt = time.Unix(0, observed.StartedAt).UTC().Format(time.RFC3339Nano)
		}
		if target.Valid() {
			candidates = append(candidates, target)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if (a.Container.Owner == preferred) != (b.Container.Owner == preferred) {
			return a.Container.Owner == preferred
		}
		if a.Container.Node != b.Container.Node {
			return a.Container.Node < b.Container.Node
		}
		return a.Container.Instance < b.Container.Instance
	})
	if len(candidates) > 0 {
		out = candidates[0]
	}
	return out, nil
}
func (p Policy) ServiceCallPermit(s state.State, caller [32]byte, read ServiceCallRead, at int64) (uint64, error) {
	if !read.Target.Valid() || caller != read.Target.Container.Owner || read.Epoch != s.ModuleEpoch() {
		return 0, access.ErrDenied
	}
	current, err := p.ServiceCallTarget(s, read.Session, at, read.Tenant, read.Request, caller)
	if err != nil || current != read.Target {
		return 0, access.ErrDenied
	}
	return s.Index(), nil
}
