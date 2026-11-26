// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/workload"
)

// NodeLimit is committed policy. Empty Tenant means the whole node; each
// nonempty tenant also needs its own limit. Zero capacity grants no capacity.
type NodeLimit struct {
	Tenant, Node          string
	Owner                 [32]byte
	Revision              uint64
	Capacity              workload.Resources
	Networks              uint64
	MaxConsumers          int `json:",omitempty"`
	PacketQueuePackets    int `json:",omitempty"`
	PacketQueueBytes      int `json:",omitempty"`
	MaxIngressInstances   int `json:",omitempty"`
	MaxIngressListeners   int `json:",omitempty"`
	MaxIngressRequests    int `json:",omitempty"`
	MaxIngressConnections int `json:",omitempty"`
	IngressBufferBytes    int `json:",omitempty"`
}

// Packet limits bound each owned TUN; the committed Networks limit bounds
// their node/tenant count. Zero grants no packet queue capacity.
func validPacketLimit(v NodeLimit) bool {
	return v.PacketQueuePackets >= 0 && v.PacketQueuePackets <= 65536 && v.PacketQueueBytes >= 0 && v.PacketQueueBytes <= 64<<20 && (v.PacketQueuePackets == 0) == (v.PacketQueueBytes == 0)
}

// Reservation owns desired budget, not a claim that a native task exists. Its
// generation identifies this budget slot. A native consumer must retain this
// original reference while binding its own goal/journal/pins, and return it only
// after their positive terminal proof. Native task generations are separate.
type Reservation struct {
	Key, Tenant, Node    string
	Owner                [32]byte
	Generation, Revision uint64
	Need                 workload.Resources
	Draining             bool
	ManagedRegistry      bool `json:",omitempty"`
}
type ReservationClosure struct {
	Schema                                     uint8
	Cluster                                    [32]byte
	Key, Node                                  string
	Owner                                      [32]byte
	Generation, DrainRevision                  uint64
	NativeGone                                 bool
	PendingNative, PendingRefs, PendingWriters uint64
	Signature                                  []byte
}

func ReservationClosureBytes(p ReservationClosure) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("mydc-resource-budget-closure-1\x00"), raw...)
}

type Quotas struct {
	ownerRotations []OwnerRotation
	ownerKeys      map[[32]byte]OwnerRotation
	cluster        [32]byte
	revision       uint64
	limits         map[string]NodeLimit
	reservations   map[string]Reservation
}

func NewQuotas(cluster [32]byte) (Quotas, error) {
	if cluster == ([32]byte{}) {
		return Quotas{}, ErrPolicy
	}
	return Quotas{ownerKeys: map[[32]byte]OwnerRotation{}, cluster: cluster, limits: map[string]NodeLimit{}, reservations: map[string]Reservation{}}, nil
}
func quotaKey(tenant, node string) string { return tenant + "/" + node }
func (q Quotas) Revision() uint64         { return q.revision }
func (q Quotas) Cluster() [32]byte        { return q.cluster }
func (q Quotas) Limit(tenant, node string) (NodeLimit, bool) {
	v, ok := q.limits[quotaKey(tenant, node)]
	return v, ok
}
func (q Quotas) Reservation(id string) (Reservation, bool) { v, ok := q.reservations[id]; return v, ok }
func (q Quotas) Limits() []NodeLimit {
	var out []NodeLimit
	for _, v := range q.limits {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b NodeLimit) int {
		return strings.Compare(quotaKey(a.Tenant, a.Node), quotaKey(b.Tenant, b.Node))
	})
	return out
}
func (q Quotas) Reservations() []Reservation {
	var out []Reservation
	for _, v := range q.reservations {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b Reservation) int { return strings.Compare(a.Key, b.Key) })
	return out
}
func validReservation(r Reservation) bool {
	p := strings.Split(r.Key, "/")
	if len(p) != 5 && len(p) != 7 || p[0] != "workload" || p[1] != "task" && p[1] != "registry" && p[1] != "imagebuild" && p[1] != "imagebuild-cache-prune" {
		return false
	}
	if len(p) == 7 {
		ordinal, err := strconv.ParseUint(strings.TrimPrefix(p[6], "r"), 10, 32)
		if p[1] != "task" || p[5] != r.Node || err != nil || ordinal == 0 || ordinal > 128 || p[6] != "r"+strconv.FormatUint(ordinal, 10) {
			return false
		}
	}
	if (p[1] == "imagebuild" || p[1] == "imagebuild-cache-prune") && (len(p) != 5 || p[4] != "builder" || r.ManagedRegistry) {
		return false
	}
	return (!r.ManagedRegistry || p[1] == "registry" && p[4] == "server") && p[2] == r.Tenant && validID(p[2]) && validID(p[3]) && validID(p[4]) && validID(r.Node) && r.Owner != ([32]byte{}) && r.Generation > 0 && r.Revision >= r.Generation && r.Need.CPU > 0 && r.Need.Memory > 0
}
func (q Quotas) clone() (Quotas, error) {
	if q.cluster == ([32]byte{}) || q.limits == nil || q.reservations == nil || q.revision == ^uint64(0) {
		return q, ErrPolicy
	}
	n, _ := NewQuotas(q.cluster)
	n.revision = q.revision + 1
	n.ownerRotations = q.OwnerRotations()
	for key, row := range q.ownerKeys {
		n.ownerKeys[key] = row
	}
	for k, v := range q.limits {
		n.limits[k] = v
	}
	for k, v := range q.reservations {
		n.reservations[k] = v
	}
	return n, nil
}

// Usage counts desired reservations, including every Draining/unknown resource.
func (q Quotas) Usage(tenant, node string) (workload.Resources, error) {
	var total workload.Resources
	for _, v := range q.reservations {
		if v.Node != node || tenant != "" && v.Tenant != tenant {
			continue
		}
		if v.Need.CPU > ^uint64(0)-total.CPU || v.Need.Memory > ^uint64(0)-total.Memory {
			return total, ErrPolicy
		}
		total.CPU += v.Need.CPU
		total.Memory += v.Need.Memory
	}
	return total, nil
}
func (n Networks) ReservedCount(tenant, node string) uint64 {
	var count uint64
	for _, v := range n.networks {
		if v.Node == node && (tenant == "" || v.Tenant == tenant) {
			count++
		}
	}
	for _, v := range n.changes {
		if changeActive(v) && v.Target.Node == node && (tenant == "" || v.Target.Tenant == tenant) {
			count++
		}
	}
	return count
}
func (q Quotas) Set(c access.Catalog, actor string, expected uint64, v NodeLimit, networks Networks) (Quotas, error) {
	if !c.SystemAllowed(actor) {
		return q, access.ErrDenied
	}
	if networks.cluster != q.cluster || !validID(v.Node) || v.Tenant != "" && !validID(v.Tenant) || v.Owner == ([32]byte{}) || v.Revision != 0 || v.Networks > maxNetworks || v.MaxConsumers < 0 || v.MaxConsumers > 65536 || !validPacketLimit(v) || !validIngressLimit(v) {
		return q, ErrPolicy
	}
	if v.Tenant != "" {
		t, ok := c.Tenant(v.Tenant)
		if !ok || t.Phase != access.TenantActive {
			return q, access.ErrDenied
		}
	}
	old, exists := q.Limit(v.Tenant, v.Node)
	if old.Revision != expected || !exists && len(q.limits) >= 8192 {
		return q, access.ErrConflict
	}
	used, err := q.Usage(v.Tenant, v.Node)
	held := networks.ReservedCount(v.Tenant, v.Node)
	if err != nil || used.CPU > v.Capacity.CPU || used.Memory > v.Capacity.Memory || held > v.Networks || exists && old.Owner != v.Owner && (used != (workload.Resources{}) || held != 0) {
		return q, ErrPolicy
	}
	if v.Tenant != "" {
		global, ok := q.Limit("", v.Node)
		if !ok || global.Owner != v.Owner || v.Capacity.CPU > global.Capacity.CPU || v.Capacity.Memory > global.Capacity.Memory || v.Networks > global.Networks || v.MaxConsumers > global.MaxConsumers || v.PacketQueuePackets > global.PacketQueuePackets || v.PacketQueueBytes > global.PacketQueueBytes || v.MaxIngressInstances > global.MaxIngressInstances || v.MaxIngressListeners > global.MaxIngressListeners || v.MaxIngressRequests > global.MaxIngressRequests || v.MaxIngressConnections > global.MaxIngressConnections || v.IngressBufferBytes > global.IngressBufferBytes {
			return q, ErrPolicy
		}
	}
	n, err := q.clone()
	if err != nil {
		return q, err
	}
	v.Revision = n.revision
	n.limits[quotaKey(v.Tenant, v.Node)] = v
	return n, nil
}
func (q Quotas) AdmitNetwork(c access.Catalog, actor, tenant, node string, owner [32]byte, n Networks) error {
	if tenant == "" || c.Authorize(actor, tenant, access.ManageNetwork, node) != nil {
		return access.ErrDenied
	}
	return q.admitScopes(tenant, node, owner, n)
}

// quotaScopes: a tenant network counts against the server-wide limit and its
// tenant's; a system network (no tenant) against the server-wide one only.
func quotaScopes(tenant string) []string {
	if tenant == "" {
		return []string{""}
	}
	return []string{"", tenant}
}

func (q Quotas) admitScopes(tenant, node string, owner [32]byte, n Networks) error {
	if n.cluster != q.cluster {
		return ErrPolicy
	}
	for _, scope := range quotaScopes(tenant) {
		limit, ok := q.Limit(scope, node)
		if !ok || limit.Owner != owner || n.ReservedCount(scope, node) >= limit.Networks {
			return ErrPolicy
		}
	}
	return nil
}
func (q Quotas) Reserve(c access.Catalog, actor string, expected uint64, r Reservation) (Quotas, error) {
	return q.reserve(c, actor, expected, r, access.Deploy, "workload/task/", false)
}

// ReserveRegistry shares the same node/tenant budget and immutable slot core.
// It is an internal server consumer, never a synthetic container Task.
func (q Quotas) ReserveRegistry(c access.Catalog, actor string, expected uint64, r Reservation) (Quotas, error) {
	return q.reserve(c, actor, expected, r, access.ManageRegistry, "workload/registry/", true)
}
func (q Quotas) reserve(c access.Catalog, actor string, expected uint64, r Reservation, action access.Action, prefix string, managedRegistry bool) (Quotas, error) {
	if c.Authorize(actor, r.Tenant, action, r.Node) != nil {
		return q, access.ErrDenied
	}
	if expected != q.revision {
		return q, access.ErrConflict
	}
	if !strings.HasPrefix(r.Key, prefix) || r.ManagedRegistry || r.Generation != 0 || r.Revision != 0 || r.Draining || len(q.reservations) >= 16384 {
		return q, ErrPolicy
	}
	if _, exists := q.reservations[r.Key]; exists {
		return q, access.ErrConflict
	}
	r.Generation, r.Revision = q.revision+1, q.revision+1
	r.ManagedRegistry = managedRegistry
	if !validReservation(r) {
		return q, ErrPolicy
	}
	for _, scope := range []string{"", r.Tenant} {
		limit, ok := q.Limit(scope, r.Node)
		used, err := q.Usage(scope, r.Node)
		if !ok || limit.Owner != r.Owner || err != nil || used.CPU > limit.Capacity.CPU || used.Memory > limit.Capacity.Memory || r.Need.CPU > limit.Capacity.CPU-used.CPU || r.Need.Memory > limit.Capacity.Memory-used.Memory {
			return q, ErrPolicy
		}
	}
	n, err := q.clone()
	if err != nil {
		return q, err
	}
	n.reservations[r.Key] = r
	return n, nil
}
func (q Quotas) Drain(c access.Catalog, actor, key string, expected uint64) (Quotas, error) {
	r, ok := q.reservations[key]
	if !ok || r.Revision != expected {
		return q, access.ErrConflict
	}
	action := access.Deploy
	if r.ManagedRegistry {
		action = access.ManageRegistry
	}
	if c.AuthorizeCleanup(actor, r.Tenant, action) != nil {
		return q, access.ErrDenied
	}
	return q.drainOriginal(r)
}

// DrainRegistryOwner is only called after the adapter authenticates the exact
// installed owner and accepted registry parent. Revocation cannot erase its pin.
func (q Quotas) DrainRegistryOwner(key string, owner [32]byte, generation uint64) (Quotas, error) {
	r, ok := q.reservations[key]
	if !ok || !r.ManagedRegistry || r.Owner != owner || r.Generation != generation {
		return q, ErrPolicy
	}
	return q.drainOriginal(r)
}
func (q Quotas) drainOriginal(r Reservation) (Quotas, error) {
	if r.Draining {
		return q, nil
	}
	n, err := q.clone()
	if err != nil {
		return q, err
	}
	r.Draining, r.Revision = true, n.revision
	n.reservations[r.Key] = r
	return n, nil
}
func (q Quotas) Release(c access.Catalog, actor string, p ReservationClosure) (Quotas, error) {
	r, ok := q.reservations[p.Key]
	if !ok {
		return q, access.ErrConflict
	}
	action := access.Deploy
	if r.ManagedRegistry {
		action = access.ManageRegistry
	}
	if c.AuthorizeCleanup(actor, r.Tenant, action) != nil {
		return q, access.ErrDenied
	}
	return q.releaseOriginal(p, r)
}

// ReleaseRegistryOwner still requires the exact signed native closure. It is
// not exposed as an unprivileged metadata release operation.
func (q Quotas) ReleaseRegistryOwner(p ReservationClosure) (Quotas, error) {
	r, ok := q.reservations[p.Key]
	if !ok || !r.ManagedRegistry {
		return q, ErrPolicy
	}
	return q.releaseOriginal(p, r)
}
func (q Quotas) releaseOriginal(p ReservationClosure, r Reservation) (Quotas, error) {
	if err := ValidateReservationClosure(q.cluster, r, p); err != nil {
		return q, err
	}
	n, err := q.clone()
	if err != nil {
		return q, err
	}
	delete(n.reservations, p.Key)
	return n, nil
}

// ValidateReservationClosure is shared by current release and retained source
// history. Verification does not mutate a reservation or grant native absence.
func ValidateReservationClosure(cluster [32]byte, r Reservation, p ReservationClosure) error {
	if cluster == ([32]byte{}) || !validReservation(r) || !r.Draining || p.Schema != 1 || p.Cluster != cluster || p.Key != r.Key || p.Node != r.Node || p.Owner != r.Owner || p.Generation != r.Generation || p.DrainRevision != r.Revision || !p.NativeGone || p.PendingNative != 0 || p.PendingRefs != 0 || p.PendingWriters != 0 || !ed25519.Verify(ed25519.PublicKey(r.Owner[:]), ReservationClosureBytes(p), p.Signature) {
		return ErrPolicy
	}
	return nil
}

type quotaSnapshot struct {
	Schema         uint8
	Cluster        [32]byte
	Revision       uint64
	Limits         []NodeLimit
	Reservations   []Reservation
	OwnerRotations []OwnerRotation `json:",omitempty"`
}

func (q Quotas) Encode() ([]byte, error) {
	if !q.validateOwnerRotations() || q.cluster == ([32]byte{}) || q.limits == nil || q.reservations == nil || len(q.limits) > 8192 || len(q.reservations) > 16384 {
		return nil, ErrPolicy
	}
	totals := map[string]workload.Resources{}
	for k, v := range q.reservations {
		if k != v.Key || !validReservation(v) || v.Revision > q.revision {
			return nil, ErrPolicy
		}
		for _, scope := range []string{"", v.Tenant} {
			key := quotaKey(scope, v.Node)
			limit, ok := q.limits[key]
			sum := totals[key]
			if !ok || !q.SameOwner(v.Node, limit.Owner, v.Owner) || v.Need.CPU > ^uint64(0)-sum.CPU || v.Need.Memory > ^uint64(0)-sum.Memory {
				return nil, ErrPolicy
			}
			sum.CPU += v.Need.CPU
			sum.Memory += v.Need.Memory
			totals[key] = sum
		}
	}
	for k, v := range q.limits {
		if k != quotaKey(v.Tenant, v.Node) || !validID(v.Node) || v.Tenant != "" && !validID(v.Tenant) || v.Owner == ([32]byte{}) || v.Revision == 0 || v.Revision > q.revision || v.Networks > maxNetworks || v.MaxConsumers < 0 || v.MaxConsumers > 65536 || !validPacketLimit(v) || !validIngressLimit(v) {
			return nil, ErrPolicy
		}
		used := totals[k]
		if used.CPU > v.Capacity.CPU || used.Memory > v.Capacity.Memory {
			return nil, ErrPolicy
		}
	}
	return json.Marshal(quotaSnapshot{1, q.cluster, q.revision, q.Limits(), q.Reservations(), q.OwnerRotations()})
}
func DecodeQuotas(raw []byte) (Quotas, error) {
	var s quotaSnapshot
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 32<<20 || d.Decode(&s) != nil || s.Schema != 1 || len(s.Limits) > 8192 || len(s.Reservations) > 16384 {
		return Quotas{}, ErrPolicy
	}
	q, err := NewQuotas(s.Cluster)
	if err != nil {
		return q, err
	}
	q.revision = s.Revision
	q.ownerRotations = s.OwnerRotations
	for _, row := range s.OwnerRotations {
		if _, exists := q.ownerKeys[row.Old]; exists {
			return q, ErrPolicy
		}
		q.ownerKeys[row.Old] = row
	}
	for _, v := range s.Limits {
		k := quotaKey(v.Tenant, v.Node)
		if _, dup := q.limits[k]; dup {
			return q, ErrPolicy
		}
		q.limits[k] = v
	}
	for _, v := range s.Reservations {
		if _, dup := q.reservations[v.Key]; dup {
			return q, ErrPolicy
		}
		q.reservations[v.Key] = v
	}
	expected, err := q.Encode()
	if err != nil || !bytes.Equal(raw, expected) {
		return q, ErrPolicy
	}
	return q, nil
}
func (q Quotas) ValidateNetworks(n Networks) error {
	if n.cluster != q.cluster {
		return ErrPolicy
	}
	counts := map[string]uint64{}
	add := func(v Network) error {
		for _, scope := range quotaScopes(v.Tenant) {
			key := quotaKey(scope, v.Node)
			limit, ok := q.limits[key]
			if !ok || !q.SameOwner(v.Node, limit.Owner, v.Owner) || counts[key] >= limit.Networks {
				return ErrPolicy
			}
			counts[key]++
		}
		return nil
	}
	for _, v := range n.networks {
		if err := add(v); err != nil {
			return err
		}
	}
	for _, v := range n.changes {
		if changeActive(v) {
			if err := add(v.Target); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateTenants joins the complete shared network graph to its current tenant
// authority. Disabled/retiring tenants retain owned resources for settlement.
func (n Networks) ValidateTenants(c access.Catalog) error {
	for _, v := range n.networks {
		if v.System {
			continue // cluster-owned, no tenant
		}
		t, ok := c.Tenant(v.Tenant)
		if !ok || t.Phase == access.TenantDeleted {
			return ErrPolicy
		}
	}
	for _, v := range n.changes {
		if changeActive(v) && !v.Target.System {
			t, ok := c.Tenant(v.Target.Tenant)
			if !ok || t.Phase == access.TenantDeleted {
				return ErrPolicy
			}
		}
	}
	return nil
}

func validIngressLimit(v NodeLimit) bool {
	return v.MaxIngressInstances >= 0 && v.MaxIngressInstances <= 128 && v.MaxIngressListeners >= 0 && v.MaxIngressListeners <= 256 && v.MaxIngressRequests >= 0 && v.MaxIngressRequests <= 65536 && v.MaxIngressConnections >= 0 && v.MaxIngressConnections <= 65536 && v.IngressBufferBytes >= 0 && v.IngressBufferBytes <= 256<<20
}
