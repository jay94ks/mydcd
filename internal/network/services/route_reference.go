// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// RouteReference is shared coordination policy, never native Applied/Observed.
// Each side owns one original instance covering both endpoint pools.
type RouteReference struct {
	Policy              tenancy.Route
	Side                string
	Source, Destination Source
}

// RouteNativeBinding is an immutable dependency on the original managed
// Bridge source. It grants no permission to recreate or adopt that source.
type RouteNativeBinding struct {
	Key                  string
	Generation, Revision uint64
	Spec                 [32]byte
}

func (c ReferenceConsumer) RouteNativeKey() string {
	if c.Route == nil {
		return ""
	}
	return routeNativeKey(c)
}

func validRouteNativeBinding(local Source, binding RouteNativeBinding) bool {
	identity, err := tenancy.ParseSourceIdentity(binding.Key)
	return err == nil && identity.Kind == "bridge" && identity.Tenant == local.Tenant && identity.Node == local.Node && identity.MemberID() == local.Network && binding.Generation > 0 && binding.Revision >= binding.Generation && binding.Spec != ([32]byte{})
}

func ownRouteReference(r RouteReference) RouteReference {
	r.Policy.Ports = slices.Clone(r.Policy.Ports)
	r.Policy.Approvals = slices.Clone(r.Policy.Approvals)
	r.Policy.Closures = slices.Clone(r.Policy.Closures)
	for i := range r.Policy.Closures {
		r.Policy.Closures[i].Signature = slices.Clone(r.Policy.Closures[i].Signature)
	}
	return r
}
func routeScope(r RouteReference) string {
	return "route/" + r.Policy.Source.Tenant + "/" + r.Policy.ID + "/" + r.Side + "/" + fullPool(routeLocal(r))
}
func routeLocal(r RouteReference) Source {
	if r.Side == r.Policy.Source.Tenant {
		return r.Source
	}
	return r.Destination
}
func routeHash(r RouteReference) [32]byte {
	raw, _ := json.Marshal(r)
	return sha256.Sum256(append([]byte("mydc-route-instance-1\x00"), raw...))
}
func sourceMatchesBinding(s Source, b tenancy.Binding) bool {
	return s.Tenant == b.Tenant && s.Network == b.Network && s.Node == b.Node && s.Owner == b.Owner && s.NetworkGeneration == b.Generation && s.Prefix == b.Prefix
}
func sourceForBinding(n tenancy.Networks, b tenancy.Binding) (Source, bool) {
	now, e := n.Bind(b.Tenant, b.Network, b.Prefix)
	if e != nil || now != b {
		return Source{}, false
	}
	v, _ := n.Network(b.Tenant, b.Network)
	for _, p := range v.Pools {
		if p.Prefix == b.Prefix {
			return Source{n.Cluster(), v.Tenant, v.ID, p.ID, v.Node, v.Owner, v.Generation, p.Prefix, p.Gateway, p.MTU}, true
		}
	}
	return Source{}, false
}
func validRouteReference(c ReferenceConsumer) bool {
	r := c.Route
	if r == nil || tenancy.ValidateRoute(r.Policy) != nil || r.Policy.Phase != tenancy.Active || r.Side != r.Policy.Source.Tenant && r.Side != r.Policy.Destination.Tenant || len(c.Members) != 2 {
		return false
	}
	if c.Native != nil && !validRouteNativeBinding(c.Local, *c.Native) {
		return false
	}
	if !validReferenceSource(r.Source, c.Local.Cluster) || !validReferenceSource(r.Destination, c.Local.Cluster) || !sourceMatchesBinding(r.Source, r.Policy.Source) || !sourceMatchesBinding(r.Destination, r.Policy.Destination) || c.Local != routeLocal(*r) || c.Scope != routeScope(*r) || c.Name != r.Policy.ID || c.DesiredSource != r.Policy.Revision || c.DesiredHash != routeHash(*r) || c.Serial != 0 {
		return false
	}
	for _, m := range c.Members {
		if m.Since != c.Generation || m.Source != r.Source && m.Source != r.Destination {
			return false
		}
	}
	return consumerCovers(c, r.Source, 0) && consumerCovers(c, r.Destination, 0)
}
func (a Authority) GrantRouteInstance(c access.Catalog, n tenancy.Networks, actor, sourceTenant, id, side string, expected uint64, native ...RouteNativeBinding) (Authority, ReferenceConsumer, error) {
	p, ok := n.Route(sourceTenant, id)
	if !ok || n.Cluster() != a.cluster || !n.RouteAuthorized(c, sourceTenant, id) || side != p.Source.Tenant && side != p.Destination.Tenant {
		return a, ReferenceConsumer{}, ErrLease
	}
	src, x := sourceForBinding(n, p.Source)
	dst, y := sourceForBinding(n, p.Destination)
	r := RouteReference{Policy: p, Side: side, Source: src, Destination: dst}
	local := routeLocal(r)
	if !x || !y || len(native) > 1 || c.Authorize(actor, side, access.ManageRoutes, local.Node) != nil {
		return a, ReferenceConsumer{}, ErrLease
	}
	var binding *RouteNativeBinding
	if len(native) == 1 {
		if !validRouteNativeBinding(local, native[0]) {
			return a, ReferenceConsumer{}, ErrLease
		}
		copy := native[0]
		binding = &copy
	}
	// Verify coverage against the original Book; no independent route allocator.
	for _, s := range []Source{src, dst} {
		pool, held := a.referencePool(fullPool(s))
		if !held || pool.Owner != poolOwner(s) || pool.Prefix != s.Prefix || pool.Gateway != s.Gateway || pool.MTU != s.MTU || pool.Draining {
			return a, ReferenceConsumer{}, ErrLease
		}
	}
	want := ReferenceConsumer{Scope: routeScope(r), Name: p.ID, Local: local, Route: &r, Native: binding, DesiredSource: p.Revision, DesiredHash: routeHash(r), Members: []ReferenceMember{{Source: src}, {Source: dst}}}
	if old, exists := a.references.Consumers[a.references.Scopes[want.Scope]]; exists && old.Closed == nil {
		if (old.Native == nil) != (binding == nil) || old.Native != nil && *old.Native != *binding {
			return a, ReferenceConsumer{}, ErrLease
		}
	}
	return a.grantReference(want, expected, false)
}

func (a Authority) RouteReferenceGeneration(n tenancy.Networks, sourceTenant, id, side string) (uint64, error) {
	p, found := n.Route(sourceTenant, id)
	if !found || side != p.Source.Tenant && side != p.Destination.Tenant {
		return 0, ErrLease
	}
	source, x := sourceForBinding(n, p.Source)
	destination, y := sourceForBinding(n, p.Destination)
	if !x || !y {
		return 0, ErrLease
	}
	want := RouteReference{Policy: p, Side: side, Source: source, Destination: destination}
	return a.references.Floors[routeScope(want)], nil
}

// RouteReferences returns owned historical and live coordination records. A
// policy withdrawal does not imply that either owner's original native is gone.
func (a Authority) RouteReferences() []ReferenceConsumer {
	var out []ReferenceConsumer
	for _, ref := range a.references.Consumers {
		if ref.Route != nil {
			out = append(out, ownReferenceConsumer(ref))
		}
	}
	slices.SortFunc(out, func(a, b ReferenceConsumer) int {
		return strings.Compare(a.Scope+"/"+generationText(a.Generation), b.Scope+"/"+generationText(b.Generation))
	})
	return out
}

func (a Authority) CurrentRouteReference(id [32]byte) bool {
	ref, found := a.references.Consumers[id]
	return found && ref.Route != nil && ref.Closed == nil && a.references.Scopes[ref.Scope] == id
}
func referenceNeed(c ReferenceConsumer) ReferenceNeed {
	return ReferenceNeed{c.ID, c.Generation, c.Lifetime, c.Local.Owner}
}

// ObserveRouteRetired joins the original instance's permanent native closure
// and bilateral policy retirement in ONE enclosing FSM candidate transaction.
// Calling the bare policy catalog is not the route runtime completion path.
func (a Authority) ObserveRouteRetired(n tenancy.Networks, closed ReferenceClose, p tenancy.RouteClosure, now int64) (Authority, tenancy.Networks, error) {
	c, known := a.references.Consumers[closed.Consumer]
	if known && c.RouteClosed != nil {
		if n.Cluster() != a.cluster || now <= 0 || closed.At > now || c.Closed == nil || !sameRouteRetirementProofs(*c.Closed, *c.RouteClosed, closed, p) {
			return a, n, ErrLease
		}
		return a, n, nil
	}
	r, ok := n.Route(p.SourceTenant, p.Route)
	if !known || !ok || n.Cluster() != a.cluster || c.Route == nil || c.Route.Policy.Source.Tenant != p.SourceTenant || c.Route.Policy.ID != p.Route || c.Route.Policy.Generation != r.Generation || c.Route.Side != p.Tenant || a.references.Scopes[c.Scope] != c.ID || closed.Target != ([32]byte{}) || closed.Epoch != 0 || closed.Owner != p.Owner || closed.Native != routeNativeKey(c) {
		return a, n, ErrLease
	}
	if c.Closed != nil && !sameRouteRetirementProofs(*c.Closed, p, closed, p) {
		return a, n, ErrLease
	}
	if ValidateRouteRetirement(c, closed, p) != nil {
		return a, n, ErrLease
	}
	next, e := a.ObserveReferenceClose(closed, now)
	if e != nil {
		return a, n, e
	}
	net, e := n.ObserveRetired(p)
	if e != nil {
		return a, n, e
	}
	if next.revision == a.revision {
		// Legacy whole-close metadata can only be joined while its exact
		// revoking policy still exists; never mutate the original map in place.
		next, e = next.clone()
		if e != nil {
			return a, n, e
		}
	}
	consumer := next.references.Consumers[c.ID]
	proof := p
	proof.Signature = slices.Clone(p.Signature)
	consumer.RouteClosed = &proof
	next.references.Consumers[c.ID] = ownReferenceConsumer(consumer)
	return next, net, nil
}

func validRouteClosed(c ReferenceConsumer, proof tenancy.RouteClosure) bool {
	if c.Route == nil || c.Closed == nil || c.Closed.Target != ([32]byte{}) || c.Closed.Epoch != 0 || c.Closed.Native != routeNativeKey(c) || proof.Tenant != c.Route.Side || proof.Owner != c.Local.Owner || proof.Revision <= c.DesiredSource {
		return false
	}
	original := c.Route.Policy
	original.Phase, original.Revision = tenancy.Revoking, proof.Revision
	return tenancy.VerifyRouteClosure(c.Local.Cluster, original, proof)
}

// ValidateRouteRetirement verifies the immutable pair without consulting a
// current account grant or a newer policy which reused the original name.
func ValidateRouteRetirement(ref ReferenceConsumer, closed ReferenceClose, policy tenancy.RouteClosure) error {
	if !validReferenceClose(ref.Local.Cluster, ref, closed) {
		return ErrLease
	}
	ref.Closed = &closed
	if !validRouteClosed(ref, policy) {
		return ErrLease
	}
	return nil
}

func sameRouteRetirementProofs(a ReferenceClose, b tenancy.RouteClosure, c ReferenceClose, d tenancy.RouteClosure) bool {
	first, _ := json.Marshal([]any{a, b})
	second, _ := json.Marshal([]any{c, d})
	return string(first) == string(second)
}

// Keep the lifetime type in this boundary explicit: local flow pins are NOT
// these shared instance pins, even though both use the existing A3 primitive.
func sameReference(a, b ReferenceNeed) bool { return a == b && a.Lifetime != (reconcile.Lease{}) }

func (a Authority) referencePool(id string) (network.Pool, bool) {
	for _, p := range a.book.Checkpoint().Pools {
		if p.ID == id {
			return p, true
		}
	}
	return network.Pool{}, false
}
