// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"crypto/ed25519"
	"encoding/json"
)

// RemovalProbe attests only to a fresh authenticated SFCP request outcome.
// A failed request is permission to retire logical membership, never evidence
// of native closure, an absent Task, or a writable Volume fence.
type RemovalProbe struct {
	Schema                                            uint8
	Cluster                                           [32]byte
	Node, Operation                                   string
	Target, Observer                                  [32]byte
	Epoch, Expected, ConfigurationIndex, RootRevision uint64
	StartedAt, FinishedAt                             int64
	Challenge                                         [32]byte
	Responding                                        bool
	Signature                                         []byte
}

func RemovalProbeBytes(p RemovalProbe) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("sfc-force-removal-probe-1\x00"), raw...)
}
func (p RemovalProbe) Valid() bool {
	return p.Schema == 1 && p.Cluster != ([32]byte{}) && ValidID(p.Node) && ValidID(p.Operation) && p.Target != ([32]byte{}) && p.Observer != ([32]byte{}) && p.Epoch > 0 && p.Expected > 0 && p.ConfigurationIndex > 0 && p.StartedAt > 0 && p.FinishedAt >= p.StartedAt && p.FinishedAt-p.StartedAt <= 10 && p.Challenge != ([32]byte{}) && ed25519.Verify(ed25519.PublicKey(p.Observer[:]), RemovalProbeBytes(p), p.Signature)
}

// Retire records the explicit administrator-selected logical retirement. The
// original signed probe survives restart/removal separately from owner Closure.
func (t Topology) Retire(node, id string, expected, epoch uint64, probe RemovalProbe) (Topology, error) {
	v, exists := t.Node(node)
	observer, installed := t.configuration.Member(probe.ObserverID(t.configuration))
	if !exists || !probe.Valid() || probe.Responding || probe.Cluster != t.cluster || probe.Node != node || probe.Operation != id || probe.Target != v.Member.Key || probe.Epoch != epoch || probe.Expected != expected || probe.ConfigurationIndex != t.configuration.Index || !installed || !observer.Voter || observer.ID == node {
		return t, ErrLifecycle
	}
	n, err := t.begin(node, id, ForceRemove, expected, epoch)
	if err != nil {
		return t, err
	}
	v, _ = n.Node(node)
	copy := probe
	copy.Signature = append([]byte(nil), probe.Signature...)
	v.Retirement = &copy
	n.nodes[node] = v
	return n, nil
}
func (p RemovalProbe) ObserverID(c Configuration) string {
	for _, m := range c.Members {
		if m.Key == p.Observer {
			return m.ID
		}
	}
	return ""
}
