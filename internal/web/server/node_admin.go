// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/workload"
)

// Server storage roots (UI-14) and workspace server limits (UI-16). Every
// change here is a system-administrator action of sfcd; the daemon only
// builds the payload and, for limits, carries over the fields the screen
// does not edit. sfcd decides.

// cpuUnit is workload.Resources.CPU per core (the task recipe hands
// Capacity.CPU to Docker as NanoCPUs).
const cpuUnit = 1e9

var storageIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// storageTenants sorts and de-duplicates a tenant list (nodestorage wants it
// sorted and unique).
func storageTenants(ts []string) ([]string, error) {
	out := []string{}
	for _, t := range ts {
		if !storageIDRE.MatchString(t) {
			return nil, invalid("tenants: workspace ids")
		}
		out = append(out, t)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func validCapacity(n uint64) error {
	if n > nodestorage.MaxCapacityBytes {
		return invalid("capacityBytes: 0 (no limit) or a byte count up to 2^60")
	}
	return nil
}

// POST /nodes/{node}/storage {opId, id, path, tenants[], allTenants?, capacityBytes?}
// → add-node-storage (Expected 0; sfcd fills the node key).
func (s *Server) handleAddNodeStorage(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID          string   `json:"opId"`
		ID            string   `json:"id"`
		Path          string   `json:"path"`
		Tenants       []string `json:"tenants"`
		AllTenants    bool     `json:"allTenants"`
		CapacityBytes uint64   `json:"capacityBytes"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	node := r.PathValue("node")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if !storageIDRE.MatchString(req.ID) {
			return "", nil, 0, "", invalid("id: lowercase letters, digits and -, starting with a letter (at most 63)")
		}
		if nodestorage.ValidateRootPath(req.Path) != nil {
			return "", nil, 0, "", invalid("path: an absolute, clean path other than /")
		}
		if err := validCapacity(req.CapacityBytes); err != nil {
			return "", nil, 0, "", err
		}
		tenants, err := storageTenants(req.Tenants)
		if err != nil {
			return "", nil, 0, "", err
		}
		if req.AllTenants && len(tenants) != 0 {
			return "", nil, 0, "", invalid("allTenants and tenants cannot be used together")
		}
		d := nodestorage.Definition{Node: node, ID: req.ID, Path: req.Path, Tenants: tenants, AllTenants: req.AllTenants, CapacityBytes: req.CapacityBytes}
		return sfc.ActionAddNodeStorage, d, 0, "storage/" + node + "/" + req.ID, nil
	})
}

// PATCH /nodes/{node}/storage/{id} {opId, addTenants[], removeTenants[],
// allTenants?, capacityBytes?, expected} → set-node-storage-policy. Only what
// changes is sent; expected is the root's revision. capacityBytes 0 = no limit.
func (s *Server) handleSetNodeStoragePolicy(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID          string   `json:"opId"`
		AddTenants    []string `json:"addTenants"`
		RemoveTenants []string `json:"removeTenants"`
		AllTenants    *bool    `json:"allTenants"`
		CapacityBytes *uint64  `json:"capacityBytes"`
		Expected      uint64   `json:"expected"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	node, id := r.PathValue("node"), r.PathValue("id")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if req.CapacityBytes != nil {
			if err := validCapacity(*req.CapacityBytes); err != nil {
				return "", nil, 0, "", err
			}
		}
		add, err := storageTenants(req.AddTenants)
		if err != nil {
			return "", nil, 0, "", err
		}
		remove, err := storageTenants(req.RemoveTenants)
		if err != nil {
			return "", nil, 0, "", err
		}
		if len(add) == 0 && len(remove) == 0 && req.AllTenants == nil && req.CapacityBytes == nil {
			return "", nil, 0, "", invalid("nothing to change")
		}
		q := control.NodeStoragePolicy{Node: node, ID: id, AddTenants: add, RemoveTenants: remove, AllTenants: req.AllTenants, CapacityBytes: req.CapacityBytes}
		return sfc.ActionSetNodeStoragePolicy, q, req.Expected, "storage/" + node + "/" + id, nil
	})
}

// POST /nodes/{node}/storage/{id}/drain {opId, expected} → drain-node-storage.
// DELETE /nodes/{node}/storage/{id} (or POST …/remove) {opId, expected}
// → remove-node-storage.
func (s *Server) handleNodeStorageSelection(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID     string `json:"opId"`
			Expected uint64 `json:"expected"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		node, id := r.PathValue("node"), r.PathValue("id")
		// the digest covers the action, so DELETE and POST …/remove with
		// one opId and body are the same change
		body := struct {
			Action string
			Req    any
		}{action, req}
		s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
			return action, control.NodeStorageSelection{Node: node, ID: id}, req.Expected, "storage/" + node + "/" + id, nil
		})
	}
}

// limitMax is the node-wide ceiling sent with 422 limit-over-node.
type limitMax struct {
	CPUs        float64 `json:"cpus"`
	MemoryBytes uint64  `json:"memoryBytes"`
}

type limitOverErr struct{ max limitMax }

func (e *limitOverErr) Error() string { return "limit-over-node" }

// PUT /t/{t}/limits/{node} {opId, cpus, memoryBytes, expected}
// → set-node-quota (tenancy.NodeLimit; Expected is the tenant limit's
// revision, 0 for a new one). The other fields of the limit are kept, a new
// limit takes them from the node-wide limit, and each is held at most the
// node-wide value (Quotas.Set's rule).
func (s *Server) handleSetTenantLimit(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID        string  `json:"opId"`
		CPUs        float64 `json:"cpus"`
		MemoryBytes uint64  `json:"memoryBytes"`
		Expected    uint64  `json:"expected"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, node := r.PathValue("t"), r.PathValue("node")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if math.IsNaN(req.CPUs) || req.CPUs < 0 || req.CPUs > 1e6 {
			return "", nil, 0, "", invalid("cpus: cores, 0 or more (decimals allowed)")
		}
		cpu := uint64(math.Round(req.CPUs * cpuUnit))
		global, err := nodeLimits(ctx, c, "")
		if err != nil {
			return "", nil, 0, "", err
		}
		g, ok := global[node]
		if !ok {
			return "", nil, 0, "", &limitOverErr{}
		}
		if cpu > uint64(math.Round(g.CPUs*cpuUnit)) || req.MemoryBytes > g.MemoryBytes {
			return "", nil, 0, "", &limitOverErr{limitMax{g.CPUs, g.MemoryBytes}}
		}
		base := g
		mine, err := nodeLimits(ctx, c, tenant)
		if err != nil {
			return "", nil, 0, "", err
		}
		if cur, ok := mine[node]; ok {
			base = cur
		}
		v := tenancy.NodeLimit{Tenant: tenant, Node: node, Capacity: workload.Resources{CPU: cpu, Memory: req.MemoryBytes},
			Networks:              min(base.Networks, g.Networks),
			MaxConsumers:          min(base.MaxConsumers, g.MaxConsumers),
			PacketQueuePackets:    min(base.PacketQueuePackets, g.PacketQueuePackets),
			PacketQueueBytes:      min(base.PacketQueueBytes, g.PacketQueueBytes),
			MaxIngressInstances:   min(base.MaxIngressInstances, g.MaxIngressInstances),
			MaxIngressListeners:   min(base.MaxIngressListeners, g.MaxIngressListeners),
			MaxIngressRequests:    min(base.MaxIngressRequests, g.MaxIngressRequests),
			MaxIngressConnections: min(base.MaxIngressConnections, g.MaxIngressConnections),
			IngressBufferBytes:    min(base.IngressBufferBytes, g.IngressBufferBytes),
		}
		// packet limits are both zero or both set (validPacketLimit)
		if v.PacketQueuePackets == 0 || v.PacketQueueBytes == 0 {
			v.PacketQueuePackets, v.PacketQueueBytes = 0, 0
		}
		return sfc.ActionSetNodeQuota, v, req.Expected, "limit/" + node, nil
	})
}

// nodeLimits reads the limits of one tenant ("" = the node-wide ones) by
// node. A tenant page never holds the node-wide limits; reading them is
// system-administrator only.
func nodeLimits(ctx context.Context, c sfc.Conn, tenant string) (map[string]sfc.NodeLimit, error) {
	out := map[string]sfc.NodeLimit{}
	after := ""
	for {
		p, err := screenResources(ctx, c, tenant, after)
		if err != nil {
			return nil, err
		}
		for _, e := range p.Items {
			if e.Limit != nil && e.Tenant == tenant {
				out[e.Limit.Node] = *e.Limit
			}
		}
		if p.Next == "" {
			return out, nil
		}
		after = p.Next
	}
}

// limitRow is a tenant limit row with the node-wide ceiling, when the caller
// may read it. The added fields come first: camelJSON keeps the first name.
type limitRow struct {
	NodeCPUs        *float64 `json:"nodeCpus,omitempty"`
	NodeMemoryBytes *uint64  `json:"nodeMemoryBytes,omitempty"`
	sfc.NodeLimit
}

type resourceRow struct {
	Limit *limitRow `json:"limit,omitempty"`
	// Bridge is a virtual bridge row with this tenant's state (UI-5D).
	Bridge *bridgeRow `json:"bridge,omitempty"`
	sfc.ResourceEntry
}

// bridgeRow: State is open, closing, waiting-me or waiting-peer for the
// page's tenant (bridgeState).
type bridgeRow struct {
	State string `json:"state"`
	sfc.Bridge
}

// resourceRows adds nodeCpus/nodeMemoryBytes to the limit rows of a tenant
// resources page. Without the node-wide limits (not an administrator, or
// sfcd could not answer) the rows go out as they are.
func resourceRows(ctx context.Context, c sfc.Conn, tenant string, items []sfc.ResourceEntry) []resourceRow {
	var global map[string]sfc.NodeLimit
	if tenant != "" && slices.ContainsFunc(items, func(e sfc.ResourceEntry) bool { return e.Limit != nil }) {
		global, _ = nodeLimits(ctx, c, "")
	}
	out := make([]resourceRow, 0, len(items))
	for _, e := range items {
		row := resourceRow{ResourceEntry: e}
		if e.Bridge != nil {
			row.Bridge = &bridgeRow{State: bridgeState(tenant, e.Bridge), Bridge: *e.Bridge}
		}
		if e.Limit != nil {
			row.Limit = &limitRow{NodeLimit: *e.Limit}
			if g, ok := global[e.Limit.Node]; ok {
				row.Limit.NodeCPUs, row.Limit.NodeMemoryBytes = &g.CPUs, &g.MemoryBytes
			}
		}
		out = append(out, row)
	}
	return out
}

// storageRow is a node-storage root row for the screen with the count of
// fixed volumes registered on it (from the volume list), when known.
// attested: the node reported the root's filesystem (Attestation), only
// then can fixed volumes be made on it; closed: after a drain the node
// reported the root closed (Closed), remove needs it.
type storageRow struct {
	Node    string   `json:"node"`
	ID      string   `json:"id"`
	Path    string   `json:"path"`
	Tenants []string `json:"tenants"`
	// AllTenants: every workspace may use it (tenants is then empty).
	AllTenants bool `json:"allTenants"`
	// CapacityBytes: most bytes its fixed volumes may reserve; 0 = no limit.
	CapacityBytes uint64 `json:"capacityBytes"`
	// Default: the root the server registered for itself (id "default").
	Default bool `json:"default"`
	// ArchiveDefault: the server's default Volume archive location
	// (set-node-archive-default); store left out of an archive goes here.
	ArchiveDefault bool   `json:"archiveDefault"`
	Generation     uint64 `json:"generation"`
	Revision       uint64 `json:"revision"`
	Draining       bool   `json:"draining"`
	Attested       bool   `json:"attested"`
	Closed         bool   `json:"closed"`
	Volumes        *int   `json:"volumes,omitempty"`
}

func newStorageRow(r sfc.StorageRoot) storageRow {
	d := r.Definition
	return storageRow{Node: d.Node, ID: d.ID, Path: d.Path, Tenants: append([]string{}, d.Tenants...), AllTenants: d.AllTenants, CapacityBytes: d.CapacityBytes, Default: d.ID == nodestorage.DefaultRootID,
		Generation: r.Generation, Revision: r.Revision, Draining: r.Draining, ArchiveDefault: r.ArchiveDefault, Attested: r.Attestation != nil, Closed: r.Closed != nil}
}

func storageRows(ctx context.Context, c sfc.Conn, items []sfc.StorageRoot) []storageRow {
	var counts map[string]int
	if len(items) > 0 {
		counts = map[string]int{}
		after := ""
		for i := 0; ; i++ {
			if i == incidentMaxPages {
				counts = nil // too many pages: leave the count out
				break
			}
			p, err := volumePage(ctx, c, "", after)
			if err != nil {
				counts = nil
				break
			}
			for _, v := range p.Items {
				if v.Kind == "fixed" {
					counts[v.Node+"/"+v.Storage]++
				}
			}
			if p.Next == "" {
				break
			}
			after = p.Next
		}
	}
	out := make([]storageRow, 0, len(items))
	for _, r := range items {
		row := newStorageRow(r)
		if counts != nil {
			n := counts[row.Node+"/"+row.ID]
			row.Volumes = &n
		}
		out = append(out, row)
	}
	return out
}

// tenantStorageRow is a storage root a tenant may place fixed volumes on
// (REQ-30 tenant-storage), with the count of the tenant's own fixed volumes
// there when known. sfcd leaves out the path and the other tenants.
type tenantStorageRow struct {
	Volumes *int `json:"volumes,omitempty"`
	control.TenantStorageRoot
}

func tenantStorageRows(ctx context.Context, c sfc.Conn, tenant string, items []control.TenantStorageRoot) []tenantStorageRow {
	var counts map[string]int
	if len(items) > 0 {
		counts = map[string]int{}
		after := ""
		for i := 0; ; i++ {
			if i == incidentMaxPages {
				counts = nil // too many pages: leave the count out
				break
			}
			p, err := volumePage(ctx, c, tenant, after)
			if err != nil {
				counts = nil
				break
			}
			for _, v := range p.Items {
				if v.Kind == "fixed" {
					counts[v.Node+"/"+v.Storage]++
				}
			}
			if p.Next == "" {
				break
			}
			after = p.Next
		}
	}
	out := make([]tenantStorageRow, 0, len(items))
	for _, r := range items {
		row := tenantStorageRow{TenantStorageRoot: r}
		if counts != nil {
			n := counts[r.Node+"/"+r.ID]
			row.Volumes = &n
		}
		out = append(out, row)
	}
	return out
}

// writeLimitOver answers 422 limit-over-node with the node-wide ceiling.
func writeLimitOver(w http.ResponseWriter, err error) bool {
	var lo *limitOverErr
	if !errors.As(err, &lo) {
		return false
	}
	msg := "the server has no node-wide limit"
	if lo.max != (limitMax{}) {
		msg = fmt.Sprintf("at most %g cores and %d bytes on this server", lo.max.CPUs, lo.max.MemoryBytes)
	}
	writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]any{"code": "limit-over-node", "message": msg, "max": lo.max}})
	return true
}

// POST /ledger/rotate {opId, expected} → rotate-ledger (LedgerWindow
// {NextEpoch: expected+1}; Expected is the current ledger epoch, GET /nodes
// ledgerEpoch). sfcd applies it only while no work is in progress
// (storageQuiescent); otherwise, and for a stale epoch, the op fails with
// condition-failed.
func (s *Server) handleRotateLedger(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if req.Expected == 0 || req.Expected == math.MaxUint64 {
			return "", nil, 0, "", invalid("expected: the current ledger epoch (1 or more)")
		}
		return sfc.ActionRotateLedger, control.LedgerWindow{NextEpoch: req.Expected + 1}, req.Expected, "ledger", nil
	})
}

// retirementView is sfcd's tenant-retirement shaped for the screen: the
// tenant's revision (Expected of begin and finish), phase and retirement
// operation from Status.Tenant, remaining targets as "kind/id", and ready:
// every owner reported closed and nothing remains, so
// finish-tenant-retirement can apply.
type retirementView struct {
	Tenant                                                string `json:"tenant"`
	Retiring                                              bool   `json:"retiring"`
	Ready                                                 bool   `json:"ready"`
	Revision                                              uint64 `json:"revision"`
	Phase                                                 string `json:"phase"`
	Operation                                             string `json:"operation"`
	Index                                                 uint64 `json:"index"`
	RootRevision                                          uint64 `json:"rootRevision"`
	TargetCount, OwnerCount, ClosedOwners, RemainingCount int
	Remaining                                             []string `json:"remaining"`
	Next                                                  string   `json:"next,omitempty"`
}

func retirementOperation(v sfc.TenantRetirement) string {
	if v.Tenant.Retirement == nil {
		return ""
	}
	return v.Tenant.Retirement.Operation
}

func newRetirementView(v sfc.TenantRetirement) retirementView {
	out := retirementView{Tenant: v.Tenant.ID, Retiring: v.Tenant.Phase == access.TenantRetiring, Revision: v.Tenant.Revision,
		Phase: string(v.Tenant.Phase), Operation: retirementOperation(v), Index: v.Index, RootRevision: v.RootRevision,
		TargetCount: v.TargetCount, OwnerCount: v.OwnerCount, ClosedOwners: v.ClosedOwners, RemainingCount: v.RemainingCount,
		Remaining: make([]string, 0, len(v.Remaining)), Next: v.Next}
	for _, t := range v.Remaining {
		out.Remaining = append(out.Remaining, t.Kind+"/"+t.ID)
	}
	out.Ready = out.Retiring && out.Operation != "" && v.ClosedOwners == v.OwnerCount && v.RemainingCount == 0
	return out
}

// POST /tenants/{t}/retire {opId, expected} → begin-tenant-retirement; the
// retirement operation ID is "retire-" + opId, so a repeated opId is the same
// retirement. POST /tenants/{t}/retire/finish {opId, expected}
// → finish-tenant-retirement with the operation of the current retirement.
// Expected is the tenant revision (GET /tenants/{t}/retirement revision).
func (s *Server) handleTenantRetire(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID     string `json:"opId"`
			Expected uint64 `json:"expected"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		tenant := r.PathValue("t")
		body := struct {
			Action string
			Req    any
		}{action, req}
		s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
			sel := control.TenantRetirementSelection{Tenant: tenant, Operation: "retire-" + req.OpID}
			if action == sfc.ActionFinishTenantRetirement {
				st, err := c.TenantRetirement(ctx, tenant, "")
				if err != nil {
					return "", nil, 0, "", err
				}
				if retirementOperation(st) == "" {
					return "", nil, 0, "", &httpErr{http.StatusConflict, "not-retiring", "the workspace is not being retired"}
				}
				sel.Operation = retirementOperation(st)
			}
			return action, sel, req.Expected, "tenant/" + tenant, nil
		})
	}
}

// storageSpaceView: node-storage-space for the screen. generation is the
// root generation the sample was taken for.
type storageSpaceView struct {
	Node          string `json:"node"`
	ID            string `json:"id"`
	Generation    uint64 `json:"generation"`
	Total         uint64 `json:"total"`
	Free          uint64 `json:"free"`
	Available     uint64 `json:"available"`
	ObservedIndex uint64 `json:"observedIndex"`
}
