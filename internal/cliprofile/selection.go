// SPDX-License-Identifier: Apache-2.0

package cliprofile

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
)

// PeerIdentity is a node identity proved by the transport handshake.
type PeerIdentity struct {
	Cluster, Key [32]byte
	ID           string
	Endpoint     Endpoint
}

// Pin is one trusted node key and where to reach it.
type Pin struct {
	ID        string
	Key       [32]byte
	Endpoints []Endpoint
}

// Selection is a resolved context for one command.
type Selection struct {
	ClusterName string // the context name
	Cluster     [32]byte
	Endpoint    Endpoint
	Peer        string // trusted node reached at Endpoint
	Username    string
	WalletKey   string
	Tenant      string
	Pins        []Pin

	// Old commands read these; they stay empty and go with those commands.
	TenantName, Project, Node string
	Timeout                   time.Duration
}

// Select joins a context with the keys trusted for its cluster. The node at
// the context's endpoint must be trusted.
func Select(name string, c Context, t Trust) (Selection, error) {
	if err := c.Validate(); err != nil {
		return Selection{}, err
	}
	if t.Validate() != nil || t.Cluster != c.Cluster {
		return Selection{}, ErrTrust
	}
	cluster, _ := clusterHex(c.Cluster)
	endpoint, _ := ParseEndpoint(c.Endpoint, false)
	s := Selection{ClusterName: name, Cluster: cluster, Endpoint: endpoint, Username: c.User, WalletKey: c.Key, Tenant: c.Tenant}
	for _, n := range t.Nodes {
		raw, _ := hex.DecodeString(n.Key)
		pin := Pin{ID: n.ID, Key: [32]byte(raw)}
		for _, e := range n.Endpoints {
			p, _ := ParseEndpoint(e, false)
			pin.Endpoints = append(pin.Endpoints, p)
			if p == endpoint && s.Peer == "" {
				s.Peer = n.ID
			}
		}
		s.Pins = append(s.Pins, pin)
	}
	if s.Peer == "" {
		return Selection{}, fmt.Errorf("%w: no trusted node at %s; run 'sfcli context trust %s'", ErrTrust, c.Endpoint, name)
	}
	slices.SortFunc(s.Pins, func(a, b Pin) int { return strings.Compare(a.ID, b.ID) })
	return s, nil
}

// CheckTenant returns the tenant a command works in. The selected tenant
// (--tenant, else the context's) and any tenant named by the command or a
// document must agree.
func (s Selection) CheckTenant(command, document string, required bool) (string, error) {
	selected := s.Tenant
	for _, id := range []string{command, document} {
		if id == "" {
			continue
		}
		if !ValidKeyName(id) || selected != "" && selected != id {
			return "", ErrSelection
		}
		selected = id
	}
	if required && selected == "" {
		return "", ErrSelection
	}
	return selected, nil
}

// VerifyPeer must pass before credentials or signatures go to a server.
func (s Selection) VerifyPeer(p PeerIdentity) error {
	if s.Cluster != p.Cluster {
		return ErrTrust
	}
	for _, n := range s.Pins {
		if n.ID == p.ID && n.Key == p.Key && slices.Contains(n.Endpoints, p.Endpoint) {
			return nil
		}
	}
	return ErrTrust
}

// TrustNode records a confirmed node in t, adding endpoint to a node already
// trusted with the same key. A different key for a known ID is refused:
// remove the old node first.
func TrustNode(t Trust, p PeerIdentity, how string, at time.Time) (Trust, error) {
	if hex.EncodeToString(p.Cluster[:]) != t.Cluster || !ValidKeyName(p.ID) || p.Key == ([32]byte{}) || !validHow(how) {
		return t, ErrTrust
	}
	key := hex.EncodeToString(p.Key[:])
	nodes := slices.Clone(t.Nodes)
	for i, n := range nodes {
		if n.ID == p.ID || n.Key == key {
			if n.ID != p.ID || n.Key != key {
				return t, fmt.Errorf("%w: node %s is already trusted with a different key; remove it first", ErrTrust, n.ID)
			}
			if !slices.Contains(n.Endpoints, p.Endpoint.URI) {
				nodes[i].Endpoints = append(slices.Clone(n.Endpoints), p.Endpoint.URI)
			}
			t.Nodes = nodes
			return t, nil
		}
	}
	t.Nodes = append(nodes, TrustedNode{ID: p.ID, Key: key, Endpoints: []string{p.Endpoint.URI}, How: how, At: at.UTC().Truncate(time.Second)})
	return t, nil
}
