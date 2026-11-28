// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// The management change screen (UI-A1) builds a `sfcli manage apply` change
// from controls. GET /ops/actions lists every action sfcd accepts with its
// payload fields (control.InputActions); POST /ops/actions/{action}/base
// reads the current target and its revision for Expected. The change itself
// goes through POST /ops like any other.

// opAction is one row of GET /ops/actions.
type opAction struct {
	Action   string               `json:"action"`
	Key      string               `json:"key"`
	Category string               `json:"category"`
	Offer    string               `json:"offer"` // here / no
	Base     string               `json:"base"`  // zero / current / input
	Fields   []control.InputField `json:"fields"`
}

// noOffer: steps of a longer protocol, or changes that need what a form
// cannot hold (a fresh key's proof, a password, file bytes, an open shell).
// They are listed but not sent from this screen.
var noOffer = []string{
	"put-app-part", "begin-app-upload", "abort-app-upload",
	"begin-build-zip-upload", "put-build-zip-part", "abort-build-zip-upload", "upload-build-zip",
	"vault-prepare-write", "vault-dispatch-write", "vault-observe-write", "vault-publish-write", "vault-abandon-write", "vault-rotate-writes", "vault-commit-approval",
	"volume-file-put", "volume-file-list", "volume-file-get", "volume-file-delete",
	"open-node-shell", "issue-initial-credential", "release-reservation",
	// The backup key is used only in the CLI (backup design D2-b).
	"cluster-backup",
}

// zeroBase: creates, checked against Expected 0.
var zeroBase = []string{"create-tenant", "add-node-storage"}

func actionCategory(action, key string) string {
	switch key {
	case "access":
		switch {
		case action == "set-node-cli-policy":
			return "nodes"
		case strings.HasPrefix(action, "volume-file-"):
			return "storage"
		case strings.Contains(action, "tenant") || action == "set-nodes" || action == "set-membership" || action == "set-trust":
			return "tenants"
		}
		return "users"
	case "members", "storage", "raft-maintenance", "cluster-backups", "tunnel-reconnects", "node-storage", "firewall":
		return "nodes"
	case "resources":
		if action == "set-node-quota" || strings.HasSuffix(action, "reservation") || action == "reserve-task" {
			return "reservations"
		}
		return "networks"
	case "volumes", "volume-shares":
		return "storage"
	case "apps":
		return "apps"
	case "registries", "external-registries", "registry-maintenance", "image-cache":
		return "registry"
	case "image-builds":
		return "builds"
	case "vault":
		return "vault"
	case "checker-lifecycle":
		return "checks"
	case "node-shell":
		return "shell"
	case "certificates":
		return "certificates"
	case "ingress-management":
		return "ingress"
	}
	return "other"
}

// GET /api/v1/ops/actions
func (s *Server) handleOpActions(w http.ResponseWriter, r *http.Request, ws *webSession) {
	items := []opAction{}
	for _, a := range control.InputActions() {
		v := opAction{Action: a.Action, Key: a.Key, Category: actionCategory(a.Action, a.Key), Offer: "here", Base: "input", Fields: a.Fields}
		if slices.Contains(noOffer, a.Action) {
			v.Offer = "no"
		}
		if slices.Contains(zeroBase, a.Action) {
			v.Base = "zero"
		} else if _, ok := baseReaders[a.Action]; ok {
			v.Base = "current"
		}
		items = append(items, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// opBase is POST /ops/actions/{action}/base's answer: Expected for the
// change and the target as sfcd shows it now (nil when not found).
type opBase struct {
	Expected uint64 `json:"expected"`
	Found    bool   `json:"found"`
	Current  any    `json:"current,omitempty"`
}

type basePayload map[string]json.RawMessage

func (p basePayload) str(name string) string {
	var v string
	_ = json.Unmarshal(p[name], &v)
	return v
}

type baseReader func(ctx context.Context, c sfc.Conn, p basePayload) (opBase, error)

// baseReaders read, for each supported action, the revision sfcd compares
// its Expected with (the same one the dedicated screens use).
var baseReaders = map[string]baseReader{
	"put-user":           userBase("ID"),
	"set-account-scope":  userBase("User"),
	"disable-credential": userBase("User"),
	"add-credential":     userBase("User"), // a system administrator's addition: no proof
	"revoke-session":     userBase("User"),
	"set-cluster-firewall": func(ctx context.Context, c sfc.Conn, _ basePayload) (opBase, error) {
		v, err := c.ClusterFirewall(ctx)
		if err != nil {
			return opBase{}, err
		}
		return opBase{Expected: v.Firewall.Revision, Found: true, Current: newClusterFirewallView(v.Firewall)}, nil
	},
	"set-membership": func(ctx context.Context, c sfc.Conn, p basePayload) (opBase, error) {
		tenant, user := p.str("Tenant"), p.str("User")
		return findBase(func(after string) ([]sfc.TenantMember, string, error) {
			pg, err := c.TenantMembers(ctx, tenant, after)
			return pg.Items, pg.Next, err
		}, func(m sfc.TenantMember) (bool, uint64) { return m.User == user && !m.Implicit, m.Revision })
	},
	"set-nodes": tenantBase,
	"set-trust": tenantBase,
	"set-node-cli-policy": func(ctx context.Context, c sfc.Conn, p basePayload) (opBase, error) {
		v, err := c.NodeCLIPolicy(ctx)
		return opBase{Expected: v.Revision, Found: true, Current: v}, err
	},
	"set-node-quota": func(ctx context.Context, c sfc.Conn, p basePayload) (opBase, error) {
		tenant, node := p.str("Tenant"), p.str("Node")
		return findBase(resourcePages(ctx, c, tenant, nil), func(e sfc.ResourceEntry) (bool, uint64) {
			if e.Limit == nil || e.Tenant != tenant || e.Limit.Node != node {
				return false, 0
			}
			return true, e.Limit.Revision
		})
	},
	"set-node-shell-policy": nodeShellBase,
	"set-node-shell-node":   nodeShellBase,
	"set-node-shell-grant":  nodeShellBase,
	"create-tun-network":    networksBase,
	"join-tun-network":      networksBase,
	"set-network-toggle":    networksBase,
	"drain-network": func(ctx context.Context, c sfc.Conn, p basePayload) (opBase, error) {
		tenant, id := p.str("Tenant"), p.str("ID")
		return findBase(resourcePages(ctx, c, tenant, nil), func(e sfc.ResourceEntry) (bool, uint64) {
			if e.Network == nil || e.Tenant != tenant {
				return false, 0
			}
			for _, m := range e.Network.Members {
				if m.ID == id {
					return true, m.Revision
				}
			}
			return false, 0
		})
	},
	"configure-network-dns": func(ctx context.Context, c sfc.Conn, p basePayload) (opBase, error) {
		tenant, name := p.str("Tenant"), p.str("Network")
		b, err := findBase(resourcePages(ctx, c, tenant, nil), func(e sfc.ResourceEntry) (bool, uint64) {
			if e.Network == nil || e.Tenant != tenant || e.Network.Name != name {
				return false, 0
			}
			if e.Network.DNS == nil {
				return true, 0
			}
			return true, e.Network.DNS.Revision
		})
		return b, err
	},
	"set-node-storage-policy":  storageBase,
	"set-node-archive-default": storageBase,
	"drain-node-storage":       storageBase,
	"remove-node-storage":      storageBase,
}

func userBase(field string) baseReader {
	return func(ctx context.Context, c sfc.Conn, p basePayload) (opBase, error) {
		id := p.str(field)
		return findBase(func(after string) ([]sfc.PublicUser, string, error) {
			pg, err := c.Users(ctx, after)
			return pg.Items, pg.Next, err
		}, func(u sfc.PublicUser) (bool, uint64) { return u.ID == id, u.Revision })
	}
}

func tenantBase(ctx context.Context, c sfc.Conn, p basePayload) (opBase, error) {
	id := p.str("Tenant")
	return findBase(func(string) ([]sfc.TenantView, string, error) {
		v, err := c.Tenants(ctx)
		return v, "", err
	}, func(t sfc.TenantView) (bool, uint64) { return t.ID == id, t.Revision })
}

func nodeShellBase(ctx context.Context, c sfc.Conn, p basePayload) (opBase, error) {
	v, err := c.NodeShellPolicy(ctx)
	return opBase{Expected: v.Revision, Found: true, Current: v}, err
}

// networksBase: creates, joins and toggles are checked against the
// Networks collection revision; Current is the named network.
func networksBase(ctx context.Context, c sfc.Conn, p basePayload) (opBase, error) {
	tenant, name := p.str("Tenant"), p.str("Name")
	var collection uint64
	b, err := findBase(resourcePages(ctx, c, tenant, &collection), func(e sfc.ResourceEntry) (bool, uint64) {
		return e.Network != nil && e.Tenant == tenant && e.Network.Name == name, 0
	})
	b.Expected = collection
	return b, err
}

func storageBase(ctx context.Context, c sfc.Conn, p basePayload) (opBase, error) {
	node, id := p.str("Node"), p.str("ID")
	return findBase(func(after string) ([]sfc.StorageRoot, string, error) {
		pg, err := c.NodeStorage(ctx, node, after)
		return pg.Items, pg.Next, err
	}, func(r sfc.StorageRoot) (bool, uint64) { return r.Definition.ID == id, r.Revision })
}

// resourcePages pages a tenant's resources; collection, when given, gets
// the Networks collection revision.
func resourcePages(ctx context.Context, c sfc.Conn, tenant string, collection *uint64) func(string) ([]sfc.ResourceEntry, string, error) {
	return func(after string) ([]sfc.ResourceEntry, string, error) {
		pg, err := screenResources(ctx, c, tenant, after)
		if collection != nil && err == nil {
			*collection = pg.Collection
		}
		return pg.Items, pg.Next, err
	}
}

// findBase pages until match finds the target; not found is Expected 0.
func findBase[T any](page func(after string) ([]T, string, error), match func(T) (bool, uint64)) (opBase, error) {
	after := ""
	for {
		items, next, err := page(after)
		if err != nil {
			return opBase{}, err
		}
		for _, it := range items {
			if ok, rev := match(it); ok {
				return opBase{Expected: rev, Found: true, Current: it}, nil
			}
		}
		if next == "" {
			return opBase{}, nil
		}
		after = next
	}
}

// POST /api/v1/ops/actions/{action}/base {payload}
func (s *Server) handleOpActionBase(w http.ResponseWriter, r *http.Request, ws *webSession) {
	action := r.PathValue("action")
	read, ok := baseReaders[action]
	if !ok {
		if _, known := control.InputActionType(action); !known {
			writeError(w, http.StatusNotFound, "not-found", "no such action")
			return
		}
		writeError(w, http.StatusUnprocessableEntity, "unsupported", "this action's base revision is entered by hand")
		return
	}
	var req struct {
		Payload basePayload `json:"payload"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var out opBase
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		out, err = read(ctx, c, req.Payload)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
