// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/netip"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/workload"
)

// Built-in registries (UI-80 '내장 저장소'): the `registries` rows with the
// CLI's status, and put/start/stop/delete-registry with record CAS
// (Expected = the row's revision, 0 for a new ID). sfcd checks the
// definition, the Volume and the node permissions; the web fills defaults
// for a new definition and keeps the stored values on an edit.

type registryLimits struct {
	Metadata         registry.MetadataLimits `json:"metadata"`
	Blobs            registry.BlobLimits     `json:"blobs"`
	Budget           workload.Resources      `json:"budget"`
	MaxRequests      int                     `json:"maxRequests"`
	MaxHeaderBytes   int                     `json:"maxHeaderBytes"`
	RequestTimeoutMS uint64                  `json:"requestTimeoutMS"`
	TokenSeconds     uint64                  `json:"tokenSeconds"`
}

func limitsOf(s registry.Specification) registryLimits {
	return registryLimits{s.Metadata, s.Blobs, s.Budget, s.MaxRequests, s.MaxHeaderBytes, s.RequestTimeoutMS, s.TokenSeconds}
}

func (l registryLimits) apply(s *registry.Specification) {
	s.Metadata, s.Blobs, s.Budget, s.MaxRequests, s.MaxHeaderBytes, s.RequestTimeoutMS, s.TokenSeconds = l.Metadata, l.Blobs, l.Budget, l.MaxRequests, l.MaxHeaderBytes, l.RequestTimeoutMS, l.TokenSeconds
}

// defaultRegistryLimits: a new definition's limits; blob storage defaults
// to the Volume's capacity.
func defaultRegistryLimits(capacity uint64) registryLimits {
	total := int64(50 << 30)
	if capacity > 0 {
		total = int64(capacity)
	}
	return registryLimits{
		Metadata: registry.MetadataLimits{ManifestBytes: 4 << 20, Records: 4096, TotalBytes: 64 << 20},
		Blobs:    registry.BlobLimits{BlobBytes: min(4<<30, total), TotalBytes: total, Records: 16384},
		Budget:   workload.Resources{CPU: cpuUnit, Memory: 256 << 20}, MaxRequests: 64, MaxHeaderBytes: 16 << 10,
		RequestTimeoutMS: 60000, TokenSeconds: 300,
	}
}

type registryRow struct {
	registryView
	Status string         `json:"status"`
	Limits registryLimits `json:"limits"`
}

// GET /t/{t}/registries?after= → {items:[{tenant, id, name, endpoint,
// revision, generation, active, repositories, node, address, certificate,
// volume, enabled, deleted, draining, observedAt, status, limits}], next,
// revision, asOf}.
func (s *Server) handleRegistries(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (listPage, error) {
		p, err := c.Registries(ctx, r.PathValue("t"), r.URL.Query().Get("after"))
		if err != nil {
			return listPage{}, err
		}
		rows := []registryRow{}
		for _, r := range p.Items {
			v := registryViewOf(r)
			rows = append(rows, registryRow{v, v.status(), limitsOf(v.Spec)})
		}
		return s.page(rows, p.Next, p.RootRevision), nil
	})
}

func findRegistry(ctx context.Context, c sfc.Conn, tenant, id string) (*registryView, error) {
	after := ""
	for {
		p, err := c.Registries(ctx, tenant, after)
		if err != nil {
			return nil, err
		}
		for i := range p.Items {
			if p.Items[i].Spec.ID == id {
				v := registryViewOf(p.Items[i])
				return &v, nil
			}
		}
		if p.Next == "" {
			return nil, nil
		}
		after = p.Next
	}
}

// PUT /t/{t}/registries/{id} {opId, node?, authority?, address?,
// certificate?, volume?, enabled?, limits?, expected?} → put-registry.
// A new ID needs authority, certificate and volume (a retained fixed
// Volume of the workspace; node defaults to its server, address to
// 0.0.0.0:<authority port>, limits to defaults). An edit keeps every field
// it does not send and may not change the volume.
func (s *Server) handlePutRegistry(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID      string          `json:"opId"`
		Node      string          `json:"node,omitempty"`
		Authority string          `json:"authority,omitempty"`
		Address   string          `json:"address,omitempty"`
		Volume    string          `json:"volume,omitempty"`
		Enabled   *bool           `json:"enabled,omitempty"`
		Limits    *registryLimits `json:"limits,omitempty"`
		Expected  uint64          `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		cur, err := findRegistry(ctx, c, tenant, id)
		if err != nil {
			return "", nil, 0, "", err
		}
		var spec registry.Specification
		var rev uint64
		switch {
		case cur != nil && cur.Deleted:
			return "", nil, 0, "", &httpErr{http.StatusConflict, "deleted", "this registry ID was deleted; use another ID"}
		case cur != nil:
			spec, rev = cur.Spec, cur.Revision
			if req.Volume != "" && req.Volume != spec.Volume.ID {
				return "", nil, 0, "", invalid("volume: a registry keeps its Volume")
			}
		default:
			if req.Authority == "" || req.Volume == "" {
				return "", nil, 0, "", invalid("a new registry needs authority and volume")
			}
			v, err := findVolume(ctx, c, tenant, req.Volume, "")
			if err != nil {
				return "", nil, 0, "", err
			}
			spec = registry.Specification{Schema: 1, Tenant: tenant, ID: id, Node: v.Node, Volume: v.Scope, Enabled: true}
			defaultRegistryLimits(v.CapacityBytes).apply(&spec)
		}
		if req.Node != "" {
			spec.Node = req.Node
		}
		if req.Authority != "" {
			spec.Authority = req.Authority
		}
		if req.Enabled != nil {
			spec.Enabled = *req.Enabled
		}
		if req.Limits != nil {
			req.Limits.apply(&spec)
		}
		switch {
		case req.Address != "":
			spec.Address = req.Address
		case cur == nil:
			spec.Address = "0.0.0.0:" + authorityPort(spec.Authority)
		}
		if spec.Validate(spec.Volume.Cluster) != nil {
			return "", nil, 0, "", invalid("the registry definition is not valid: authority host[:port] matching the address port, address IP:port, certificate name, limits in range")
		}
		return sfc.ActionPutRegistry, control.RegistryPut{Spec: spec}, expectedOr(req.Expected, rev), "registry/" + id, nil
	})
}

func authorityPort(a string) string {
	if ap, err := netip.ParseAddrPort(a); err == nil {
		return ap.String()[strings.LastIndexByte(ap.String(), ':')+1:]
	}
	if i := strings.LastIndexByte(a, ':'); i >= 0 && !strings.Contains(a[i:], "]") {
		return a[i+1:]
	}
	return "443"
}

var registryActions = map[string]string{"start": sfc.ActionStartRegistry, "stop": sfc.ActionStopRegistry, "delete": sfc.ActionDeleteRegistry}

// POST /t/{t}/registries/{id}/{start|stop|delete} {opId, expected?}.
// stop and delete keep the Volume's data; delete needs a stopped registry
// (409 not-stopped).
func (s *Server) handleRegistryAction(verb string) func(http.ResponseWriter, *http.Request, *webSession) {
	action := registryActions[verb]
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID     string `json:"opId"`
			Expected uint64 `json:"expected,omitempty"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		tenant, id := r.PathValue("t"), r.PathValue("id")
		body := struct {
			Action string
			Req    any
		}{action, req}
		s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
			cur, err := findRegistry(ctx, c, tenant, id)
			if err != nil {
				return "", nil, 0, "", err
			}
			if cur == nil || cur.Deleted {
				return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such registry"}
			}
			if action == sfc.ActionDeleteRegistry && (cur.Enabled || cur.Active) {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "not-stopped", "stop the registry and wait until it is stopped"}
			}
			return action, control.RegistrySelection{Tenant: tenant, ID: id}, expectedOr(req.Expected, cur.Revision), "registry/" + id, nil
		})
	}
}
