// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Creating shared tenant resources (UI-50, UI-60/61, the Vault screen). The
// browser sends plain fields; the daemon builds the real mydcd payload,
// checks it with the product's own input decoder (control.InputChange) and
// sends it as one original operation of the caller: sign → store → send.
// Authority is mydcd's (TM(Network) / TM(Volumes) / Vault manage).
//
// The opId makes a create idempotent. The stored op keeps the digest of the
// browser body, so the same opId with the same body returns that op even
// after the collection revision moved, and with another body is 409.

// sharedCreate is the common path. build runs on the caller's connection
// and returns the action, the payload, Expected and the op target.
func (s *Server) sharedCreate(w http.ResponseWriter, r *http.Request, ws *webSession, opID string, body any,
	build func(ctx context.Context, c mydc.Conn, sess mydc.Session) (action string, payload any, expected uint64, target string, err error)) {
	s.sharedCreateHold(w, r, ws, opID, body, build, nil)
}

// rootedPayload: a payload whose plan names the root revision to sign with
// (registry maintenance plans give the maintenance root, as userauth
// picks per command key).
type rootedPayload struct {
	payload any
	root    uint64
}

// holdFunc decides, for a signed original not yet sent, whether to keep it
// in web bbolt instead of sending it now (it then fills o's job fields and
// state); false sends it as usual.
type holdFunc func(ctx context.Context, c mydc.Conn, o *store.Op, op mydc.SignedOp) (bool, error)

// sharedCreateHold is sharedCreate with a hold step between signing and
// sending (build-secret approvals).
func (s *Server) sharedCreateHold(w http.ResponseWriter, r *http.Request, ws *webSession, opID string, body any,
	build func(ctx context.Context, c mydc.Conn, sess mydc.Session) (action string, payload any, expected uint64, target string, err error), hold holdFunc) {
	tenant := r.PathValue("t")
	if !uuidRE.MatchString(opID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
		return
	}
	reason, err := opReasonOf(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	raw, _ := json.Marshal(struct {
		Path   string
		Body   any
		Reason *store.OpReason `json:",omitempty"`
	}{r.URL.Path, body, reason})
	sum := sha256.Sum256(raw)
	dg := hex.EncodeToString(sum[:])
	if old, err := s.opt.Store.GetOp(ws.user.ID, opID); err == nil {
		if old.Digest != dg {
			writeError(w, http.StatusConflict, "op-conflict", "this opId was already used for a different change")
			return
		}
		writeJSON(w, opStatus(old), map[string]any{"op": viewOp(old)})
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	ctx, cancel := s.callCtx(r)
	defer cancel()
	var o *store.Op
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		sess, ok := c.Session()
		if !ok {
			return &mydc.Error{Code: mydc.CodeNotLoggedIn, Method: "session"}
		}
		action, payload, expected, target, err := build(ctx, c, sess)
		if err != nil {
			return err
		}
		var planRoot uint64
		if rp, ok := payload.(rootedPayload); ok {
			payload, planRoot = rp.payload, rp.root
		}
		p, _ := json.Marshal(payload)
		ch := mydc.Change{Schema: 1, Action: action, Principal: ws.user.ID, Expected: expected, Payload: p}
		if !mockAction(action) {
			doc, _ := json.Marshal(control.ChangeDocument{Schema: 1, Action: action, Expected: expected, Payload: p})
			if ch, err = control.InputChange(doc, ws.user.ID); err != nil {
				return &httpErr{http.StatusUnprocessableEntity, "invalid", action + ": the values do not make a valid request"}
			}
		}
		who, err := c.Whoami(ctx)
		if err != nil {
			return err
		}
		o = &store.Op{ID: opID, User: ws.user.ID, Username: ws.user.Username, Action: action, Tenant: tenant, Target: target, Digest: dg, Reason: reason}
		root := who.RootFor(action)
		if planRoot != 0 {
			root = planRoot
		}
		var existing *store.Op
		if hold == nil {
			existing, err = s.sendStored(ctx, c, o, ch, root)
		} else {
			existing, err = s.prepareHold(ctx, c, o, ch, root, hold)
		}
		if err != nil {
			return err
		}
		if existing != nil {
			if existing.Digest != dg {
				return &httpErr{http.StatusConflict, "op-conflict", "this opId was already used for a different change"}
			}
			o = existing
		}
		return nil
	})
	if err == nil {
		s.log.Info("create", "user", ws.user.Username, "action", o.Action, "tenant", tenant, "target", o.Target, "op", o.ID, "state", o.State)
		writeJSON(w, opStatus(o), map[string]any{"op": viewOp(o)})
		return
	}
	s.writeOpOutcome(w, ws, nil, 0, err)
}

// mockAction reports an action the product input decoder
// (control.InputChange) cannot check, so mydcd's result decides: one mydcd
// does not have yet (REQ mock), or one mydcd takes only through its own
// typed command (the certificate store's delete/disable, built here as
// control.CertificateSelection).
func mockAction(action string) bool {
	switch action {
	case mydc.ActionDeleteCertificate, mydc.ActionDisableCertificate:
		return true
	case mydc.ActionSetAccountScope, mydc.ActionCordonNode, mydc.ActionUncordonNode, mydc.ActionPruneNodeImages,
		mydc.ActionDrainNode, mydc.ActionDemoteNode, mydc.ActionRotateNodeIdentity, mydc.ActionForceRemoveNode,
		mydc.ActionIngressBlock, mydc.ActionIngressUnblock, mydc.ActionIngressBlockExtend,
		mydc.ActionSetNodeGateways, mydc.ActionSetIngressBalance, mydc.ActionDrainIngress, mydc.ActionUndrainIngress,
		mydc.ActionRaftCompact,
		mydc.ActionSetNodeShellPolicy, mydc.ActionSetNodeShellNode, mydc.ActionSetNodeShellGrant, mydc.ActionCloseNodeShell:
		return true
	}
	return false
}

func invalid(msg string) error { return &httpErr{http.StatusUnprocessableEntity, "invalid", msg} }

func validName(s string) bool { return certNameRE.MatchString(s) }

// netPool is one server's address pool "main": an IPv4 network (at most
// /29), its gateway (default the first host) and the MTU.
func netPool(cidr, gateway string, mtu int) (tenancy.Subnet, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() > 29 {
		return tenancy.Subnet{}, invalid("cidr: an IPv4 network such as 10.40.0.0/24 (at most /29)")
	}
	gw := prefix.Addr().Next()
	if gateway != "" {
		if gw, err = netip.ParseAddr(gateway); err != nil || !prefix.Contains(gw) || gw == prefix.Addr() {
			return tenancy.Subnet{}, invalid("gateway must be a host address inside cidr")
		}
	}
	return tenancy.Subnet{ID: "main", Prefix: prefix, Gateway: gw, MTU: mtu}, nil
}

// POST /t/{t}/networks: a network (Expected is Networks.Revision).
//
//	{opId, kind?:"bridge", name, node, cidr, gateway?, mtu?}
//	  → create-network: a bridge network on one server
//	{opId, kind:"tun", name, members:[{node, cidr, gateway?, tunnel?}], tunnelCidr?, mtu?}
//	  → create-tun-network: one network across servers. Each server has its
//	    own pool and a tunnel host address outside every pool, given as
//	    members[].tunnel or handed out in order from tunnelCidr.
func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request, ws *webSession) {
	type member struct {
		Node    string `json:"node"`
		CIDR    string `json:"cidr"`
		Gateway string `json:"gateway,omitempty"`
		Tunnel  string `json:"tunnel,omitempty"`
	}
	var req struct {
		OpID       string   `json:"opId"`
		Kind       string   `json:"kind,omitempty"`
		Name       string   `json:"name"`
		Node       string   `json:"node,omitempty"`
		CIDR       string   `json:"cidr,omitempty"`
		Gateway    string   `json:"gateway,omitempty"`
		MTU        int      `json:"mtu,omitempty"`
		Members    []member `json:"members,omitempty"`
		TunnelCIDR string   `json:"tunnelCidr,omitempty"`
		// Toggles: tun network toggles to turn on or off, by name
		// (tenancy.NetworkToggles; "local": kept on one server).
		Toggles map[string]bool `json:"toggles,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant := r.PathValue("t")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		if !validName(req.Name) {
			return "", nil, 0, "", invalid("name: lowercase letters, digits and '-'")
		}
		mtu := req.MTU
		if mtu == 0 {
			mtu = 1500
		}
		if mtu < 1280 || mtu > 9000 {
			return "", nil, 0, "", invalid("mtu: 1280..9000")
		}
		var action string
		var payload any
		switch req.Kind {
		case "", "bridge":
			if !validName(req.Node) || len(req.Members) != 0 || req.TunnelCIDR != "" {
				return "", nil, 0, "", invalid("a bridge network has one node (lowercase letters, digits and '-') and no members")
			}
			pool, err := netPool(req.CIDR, req.Gateway, mtu)
			if err != nil {
				return "", nil, 0, "", err
			}
			action, payload = mydc.ActionCreateNetwork, tenancy.Network{Tenant: tenant, ID: req.Name, Node: req.Node, Pools: []tenancy.Subnet{pool}}
		case "tun":
			d, err := tunDefinition(tenant, req.Name, mtu, req.TunnelCIDR, func(yield func(node, cidr, gateway, tunnel string) error) error {
				if req.Node != "" || req.CIDR != "" || len(req.Members) == 0 || len(req.Members) > 32 {
					return invalid("a tun network has 1..32 members and no top-level node or cidr")
				}
				for _, m := range req.Members {
					if err := yield(m.Node, m.CIDR, m.Gateway, m.Tunnel); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return "", nil, 0, "", err
			}
			for _, t := range tenancy.NetworkToggles() {
				on := req.Toggles[string(t)]
				if !tenancy.ToggleAllowed(t, on, len(d.Members)) {
					return "", nil, 0, "", invalid(fmt.Sprintf("toggles.%s: %v is not allowed with %d servers", t, on, len(d.Members)))
				}
				if on {
					d.Toggles = append(d.Toggles, t)
				}
			}
			for name := range req.Toggles {
				if !slices.Contains(tenancy.NetworkToggles(), tenancy.NetworkToggle(name)) {
					return "", nil, 0, "", invalid(fmt.Sprintf("toggles: one of %v", tenancy.NetworkToggles()))
				}
			}
			action, payload = mydc.ActionCreateTUNNetwork, d
		default:
			return "", nil, 0, "", invalid(`kind: "bridge" or "tun"`)
		}
		p, err := c.Resources(ctx, tenant, "")
		if err != nil {
			return "", nil, 0, "", err
		}
		return action, payload, p.Collection, req.Name, nil
	})
}

// tunDefinition builds create-tun-network's payload. Owners are left for
// mydcd to fill from each server; the gateway mode is mydcd's default.
func tunDefinition(tenant, name string, mtu int, tunnelCIDR string, members func(yield func(node, cidr, gateway, tunnel string) error) error) (tenancy.TUNDefinition, error) {
	d := tenancy.TUNDefinition{Tenant: tenant, Name: name}
	var tunnels netip.Prefix
	if tunnelCIDR != "" {
		var err error
		if tunnels, err = netip.ParsePrefix(tunnelCIDR); err != nil || !tunnels.Addr().Is4() || tunnels != tunnels.Masked() || tunnels.Bits() > 30 {
			return d, invalid("tunnelCidr: an IPv4 network such as 10.255.40.0/24 (at most /30)")
		}
	}
	next := tunnels.Addr()
	seen := map[string]bool{}
	var used []netip.Addr
	err := members(func(node, cidr, gateway, tunnel string) error {
		if !validName(node) || seen[node] {
			return invalid("members[].node: distinct server names (lowercase letters, digits and '-')")
		}
		seen[node] = true
		pool, err := netPool(cidr, gateway, mtu)
		if err != nil {
			return err
		}
		var addr netip.Addr
		switch {
		case tunnel != "":
			if addr, err = netip.ParseAddr(tunnel); err != nil || !addr.Is4() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
				return invalid("members[].tunnel: an IPv4 host address such as 10.255.40.1")
			}
		case tunnelCIDR != "":
			next = next.Next()
			last := netipLast(tunnels)
			if !tunnels.Contains(next) || next == last {
				return invalid("tunnelCidr has too few addresses for the members")
			}
			addr = next
		default:
			return invalid("each member needs a tunnel address: members[].tunnel or tunnelCidr")
		}
		if slices.Contains(used, addr) {
			return invalid("tunnel addresses must differ")
		}
		used = append(used, addr)
		d.Members = append(d.Members, tenancy.TUNNode{Node: node, Pools: []tenancy.Subnet{pool}, Addresses: []netip.Prefix{netip.PrefixFrom(addr, 32)}})
		return nil
	})
	if err != nil {
		return d, err
	}
	for i, a := range d.Members {
		for j, b := range d.Members {
			if b.Pools[0].Prefix.Contains(a.Addresses[0].Addr()) || i < j && a.Pools[0].Prefix.Overlaps(b.Pools[0].Prefix) {
				return d, invalid("member pools must not overlap each other or any tunnel address")
			}
		}
	}
	return d, nil
}

// netipLast is the last address of an IPv4 prefix (its broadcast).
func netipLast(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= 1<<(32-p.Bits()) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// POST /t/{t}/networks/{name}/dns {opId, zone, upstreams?, ttl?, negativeTtl?,
// reverse?, enabled?, expected?}: configure-network-dns, a full policy
// replacement. mydcd runs managed DNS only on tun networks. expected is the
// row's DNS.Revision (0 the first time). Limits are fixed web defaults.
func (s *Server) handleNetworkDNS(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID        string    `json:"opId"`
		Zone        string    `json:"zone"`
		Upstreams   *[]string `json:"upstreams,omitempty"`
		TTL         *uint32   `json:"ttl,omitempty"`
		NegativeTTL *uint32   `json:"negativeTtl,omitempty"`
		Reverse     *bool     `json:"reverse,omitempty"`
		Enabled     *bool     `json:"enabled,omitempty"`
		Expected    uint64    `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, name := r.PathValue("t"), r.PathValue("name")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		if !validName(name) {
			return "", nil, 0, "", invalid("network name")
		}
		zone, err := services.Domain(req.Zone)
		if err != nil || len(zone) > 200 {
			return "", nil, 0, "", invalid("zone: a domain name such as shop.internal")
		}
		// start from the current policy, so fields the request leaves out
		// (and the ones the screen never sets) stay as they are
		p := services.ManagedDNSPolicy{TTL: 30, NegativeTTL: 5, Transports: []string{"udp", "tcp"}, Upstreams: []netip.AddrPort{},
			MaxQueries: 64, MaxCacheEntries: 512, MaxResponseBytes: 4096, MaxConnections: 64, RequestTimeoutMS: 5000}
		n, _, err := findNetwork(ctx, c, tenant, name)
		if err != nil {
			return "", nil, 0, "", err
		}
		if n.DNS != nil && n.DNS.Policy.Transports != nil {
			p = n.DNS.Policy
		}
		p.Zone, p.Enabled = zone, req.Enabled == nil || *req.Enabled
		if req.Reverse != nil {
			p.Reverse = *req.Reverse
		}
		if req.TTL != nil {
			p.TTL = *req.TTL
			if req.NegativeTTL == nil {
				p.NegativeTTL = min(p.NegativeTTL, p.TTL)
			}
		}
		if req.NegativeTTL != nil {
			p.NegativeTTL = *req.NegativeTTL
		}
		if p.TTL == 0 || p.TTL > 3600 || p.NegativeTTL == 0 || p.NegativeTTL > p.TTL {
			return "", nil, 0, "", invalid("ttl: 1..3600, negativeTtl: 1..ttl")
		}
		if req.Upstreams != nil {
			if len(*req.Upstreams) > 4 {
				return "", nil, 0, "", invalid("upstreams: at most 4")
			}
			p.Upstreams = []netip.AddrPort{}
			for _, u := range *req.Upstreams {
				ap, err := netip.ParseAddrPort(u)
				if err != nil {
					a, aerr := netip.ParseAddr(u)
					if aerr != nil {
						return "", nil, 0, "", invalid("upstreams: addresses such as 1.1.1.1 or 1.1.1.1:53")
					}
					ap = netip.AddrPortFrom(a, 53)
				}
				p.Upstreams = append(p.Upstreams, ap)
			}
		}
		d := services.ManagedDNSDefinition{Schema: 1, Tenant: tenant, Network: name, Policy: p}
		return mydc.ActionConfigureNetworkDNS, d, req.Expected, name, nil
	})
}

// POST /t/{t}/volumes: a data store.
//
//	{opId, kind:"managed", name, app, node, uid, gid, mode?(octal text), capacityBytes?}
//	  → begin-volume-create in the app's namespace (the server makes the directory)
//	{opId, kind:"fixed", name, node, storage, path, capacityBytes?, rootGeneration?}
//	  → register-fixed-volume: an existing directory under an approved
//	    storage root of the server (data is never created or deleted)
func (s *Server) handleCreateVolume(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID           string `json:"opId"`
		Kind           string `json:"kind"`
		Name           string `json:"name"`
		App            string `json:"app,omitempty"`
		Node           string `json:"node"`
		UID            uint32 `json:"uid,omitempty"`
		GID            uint32 `json:"gid,omitempty"`
		Mode           string `json:"mode,omitempty"`
		Storage        string `json:"storage,omitempty"`
		Path           string `json:"path,omitempty"`
		CapacityBytes  uint64 `json:"capacityBytes,omitempty"`
		RootGeneration uint64 `json:"rootGeneration,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant := r.PathValue("t")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, sess mydc.Session) (string, any, uint64, string, error) {
		if !validName(req.Name) || !validName(req.Node) {
			return "", nil, 0, "", invalid("name and node: lowercase letters, digits and '-'")
		}
		if req.CapacityBytes > 1<<40 {
			return "", nil, 0, "", invalid("capacityBytes: at most 1 TiB")
		}
		scope := volumes.Scope{Cluster: sess.Cluster, Tenant: tenant, ID: req.Name, Generation: 1}
		switch req.Kind {
		case "managed":
			if !validName(req.App) {
				return "", nil, 0, "", invalid("app: the app namespace the data store belongs to")
			}
			if req.UID == 0 || req.GID == 0 || req.UID == 1<<32-1 || req.GID == 1<<32-1 {
				return "", nil, 0, "", invalid("uid and gid must be non-root")
			}
			mode := uint32(0o750)
			if req.Mode != "" {
				m, err := strconv.ParseUint(req.Mode, 8, 32)
				if err != nil || m&0o700 != 0o700 || m&^0o770 != 0 {
					return "", nil, 0, "", invalid("mode: 0700, 0750 or 0770")
				}
				mode = uint32(m)
			}
			scope.App = req.App
			q := control.VolumeCreate{Scope: scope, Node: req.Node, UID: req.UID, GID: req.GID, Mode: mode, QuotaMode: "observe", CapacityBytes: req.CapacityBytes}
			return mydc.ActionBeginVolumeCreate, q, 0, req.Name, nil
		case "fixed":
			if !validName(req.Storage) || req.Path == "" {
				return "", nil, 0, "", invalid("storage and path are required")
			}
			// The root generation pins the approved storage root. Only a
			// system admin can read node-storage today (REQUEST.md REQ-30);
			// others pass rootGeneration and mydcd checks it exactly.
			gen := req.RootGeneration
			root, err := findStorageRoot(ctx, c, req.Node, req.Storage)
			switch {
			case err == nil && root != nil:
				if root.Draining || !slices.Contains(root.Definition.Tenants, tenant) {
					return "", nil, 0, "", invalid("storage root " + req.Storage + " on " + req.Node + " is not approved for this workspace")
				}
				if gen != 0 && gen != root.Generation {
					return "", nil, 0, "", invalid("rootGeneration does not match the storage root")
				}
				gen = root.Generation
			case err == nil:
				return "", nil, 0, "", invalid("no storage root " + req.Storage + " on " + req.Node)
			case errors.Is(err, mydc.ErrDenied):
				if gen == 0 {
					return "", nil, 0, "", &httpErr{http.StatusUnprocessableEntity, "storage-root-unknown", "only a system administrator can read storage roots; pass rootGeneration"}
				}
			default:
				return "", nil, 0, "", err
			}
			q := control.VolumeFixedRegister{Scope: scope, Node: req.Node, Storage: req.Storage, Path: req.Path, RootGeneration: gen, QuotaMode: "observe", CapacityBytes: req.CapacityBytes}
			return mydc.ActionRegisterFixedVolume, q, 0, req.Name, nil
		}
		return "", nil, 0, "", invalid(`kind: "managed" or "fixed"`)
	})
}

// POST /t/{t}/vault {opId, realm?(default the workspace), parent, id,
// kind:"secret"|"group", profile?, object?, keys?}: vault-create. Only the
// metadata (name, place, keys); values and a Group password are written
// separately (vault_write.go, SecretInput). Expected is the Vault tree revision.
func (s *Server) handleCreateVault(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID    string   `json:"opId"`
		Realm   string   `json:"realm,omitempty"`
		Parent  string   `json:"parent"`
		ID      string   `json:"id"`
		Kind    string   `json:"kind"`
		Profile string   `json:"profile,omitempty"`
		Object  string   `json:"object,omitempty"`
		Keys    []string `json:"keys,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant := r.PathValue("t")
	if req.Realm == "" {
		req.Realm = tenant
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		if req.Realm != tenant {
			return "", nil, 0, "", invalid("realm must be this workspace")
		}
		o := secrets.Object{ID: req.ID, Parent: req.Parent}
		switch req.Kind {
		case "group":
			if req.Profile != "" || req.Object != "" || len(req.Keys) != 0 {
				return "", nil, 0, "", invalid("a group has no profile, object or keys")
			}
			o.Kind = secrets.Group
		case "secret":
			if len(req.Keys) == 0 || len(req.Keys) > 64 {
				return "", nil, 0, "", invalid("keys: 1..64 names")
			}
			keys := slices.Clone(req.Keys)
			slices.Sort(keys)
			o.Kind, o.Reference = secrets.Secret, secrets.Reference{Profile: req.Profile, Object: req.Object, Keys: keys}
		default:
			return "", nil, 0, "", invalid(`kind: "secret" or "group"`)
		}
		p, err := c.Vault(ctx, tenant, "")
		if err != nil {
			return "", nil, 0, "", err
		}
		return mydc.ActionVaultCreate, control.VaultObject{Realm: req.Realm, Object: o}, p.Collection, req.Parent + "/" + req.ID, nil
	})
}

// findStorageRoot returns the storage root id on node (nil when none).
func findStorageRoot(ctx context.Context, c mydc.Conn, node, id string) (*mydc.StorageRoot, error) {
	after := ""
	for {
		p, err := c.NodeStorage(ctx, node, after)
		if err != nil {
			return nil, err
		}
		for i := range p.Items {
			if p.Items[i].Definition.ID == id {
				return &p.Items[i], nil
			}
		}
		if p.Next == "" {
			return nil, nil
		}
		after = p.Next
	}
}
