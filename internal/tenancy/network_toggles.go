// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"slices"

	"github.com/jay94ks/seafield/internal/access"
)

// NetworkToggle names one on/off option of a TUN network. A member lists the
// toggles that are on (Network.Toggles, sorted); every member of a network
// lists the same ones. Each toggle has its own rule in toggleRules, so adding
// a toggle is one entry there and nothing else in the network data.
type NetworkToggle string

// ToggleLocal keeps a network on one server (LOCAL); off, it may span
// servers (CROSS, the default). The device is the same TUN either way. The
// screens show it as "다른 서버와 잇기" = not local.
const ToggleLocal NetworkToggle = "local"

// toggleRule says whether a network may hold the toggle's value with this
// many members. It is checked whenever the network is created, a member joins
// or leaves, or the toggle is set.
type toggleRule struct {
	allowed func(on bool, members int) bool
}

var toggleRules = map[NetworkToggle]toggleRule{
	// On only with one server: join is refused while it is on, and turning
	// it on needs a lone member. Off is allowed at any size.
	ToggleLocal: {allowed: func(on bool, members int) bool { return !on || members <= 1 }},
	// At any size: it only says whether another tenant may bridge to it.
	ToggleBridgeInbound: {allowed: func(bool, int) bool { return true }},
}

// validToggles: known toggles, sorted, no repeats, on a TUN member only.
func validToggles(v Network) bool {
	if len(v.Toggles) > 0 && v.Logical == "" {
		return false
	}
	for i, t := range v.Toggles {
		if _, ok := toggleRules[t]; !ok || i > 0 && t <= v.Toggles[i-1] {
			return false
		}
	}
	return true
}

// sortedToggles returns a definition's toggles in stored order (nil when
// none), or false when one is unknown or repeated.
func sortedToggles(in []NetworkToggle) ([]NetworkToggle, bool) {
	if len(in) == 0 {
		return nil, true
	}
	out := slices.Clone(in)
	slices.Sort(out)
	for i, t := range out {
		if _, ok := toggleRules[t]; !ok || i > 0 && t == out[i-1] {
			return nil, false
		}
	}
	return out, true
}

// togglesAllowed checks one network's members: the same toggles on every
// member, and each toggle's rule for the member count.
func togglesAllowed(members []Network) bool {
	if len(members) == 0 {
		return true
	}
	on := members[0].Toggles
	for _, v := range members[1:] {
		if !slices.Equal(v.Toggles, on) {
			return false
		}
	}
	for t, r := range toggleRules {
		if !r.allowed(slices.Contains(on, t), len(members)) {
			return false
		}
	}
	return true
}

// SetToggle turns one toggle of a tenant TUN network on or off on every
// member (set-network-toggle). It changes no address, pool, device or member
// revision; the toggle's rule decides whether the network may hold the new
// value.
func (n Networks) SetToggle(c access.Catalog, actor string, expected uint64, tenant, name string, toggle NetworkToggle, on bool) (Networks, error) {
	if !validID(tenant) || !validID(name) {
		return n, ErrPolicy
	}
	if _, ok := toggleRules[toggle]; !ok {
		return n, ErrPolicy
	}
	if expected != n.revision {
		return n, access.ErrConflict
	}
	var members []Network
	for _, v := range n.networks {
		if v.Tenant == tenant && v.Logical == name {
			members = append(members, v)
		}
	}
	if len(members) == 0 {
		return n, ErrPolicy
	}
	for _, v := range members {
		if c.Authorize(actor, tenant, access.ManageNetwork, v.Node) != nil {
			return n, access.ErrDenied
		}
		if v.System || v.Draining || v.PendingChange != 0 {
			return n, ErrPolicy
		}
	}
	if slices.Contains(members[0].Toggles, toggle) == on {
		return n, access.ErrConflict
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	for i, v := range members {
		v.Toggles = slices.DeleteFunc(slices.Clone(v.Toggles), func(t NetworkToggle) bool { return t == toggle })
		if on {
			v.Toggles = append(v.Toggles, toggle)
			slices.Sort(v.Toggles)
		}
		if len(v.Toggles) == 0 {
			v.Toggles = nil
		}
		// The member Revision stays: route bindings, frozen app references
		// and native source pins name it, and a toggle changes none of them.
		// The networks revision is the CAS of this change.
		members[i] = v
		q.networks[key(v.Tenant, v.ID)] = ownNetwork(v)
	}
	if !togglesAllowed(members) {
		return n, ErrPolicy
	}
	return q, nil
}

// NetworkToggles lists the known toggles in order, for clients that show or
// parse them.
func NetworkToggles() []NetworkToggle {
	out := make([]NetworkToggle, 0, len(toggleRules))
	for t := range toggleRules {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// ToggleAllowed reports whether a network with this many members may hold
// the toggle's value (false for an unknown toggle).
func ToggleAllowed(t NetworkToggle, on bool, members int) bool {
	r, ok := toggleRules[t]
	return ok && r.allowed(on, members)
}
