// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/identity"
	"slices"
)

// Scheduling metadata is independent of installed membership, topology and
// WorkKey. Cordon never withdraws existing Task/Volume/transport authority.
type Cordon struct {
	Node     string
	Enabled  bool
	Revision uint64
	Origin   json.RawMessage
}
type CordonView struct {
	CordonedBy string `json:",omitempty"`
	CordonedAt string `json:",omitempty"`
	// Reason: the cordon-node original's note, projected by control.
	Reason   string `json:",omitempty"`
	Enabled  bool
	Revision uint64
}

func (d Directory) Cordon(id string) CordonView {
	for _, row := range d.Cordons {
		if row.Node == id {
			return CordonView{Enabled: row.Enabled, Revision: row.Revision}
		}
	}
	return CordonView{}
}
func (d Directory) SetCordon(id string, expected uint64, enabled bool, origin []byte) (Directory, error) {
	if !d.writable() || len(origin) == 0 || len(origin) > 64<<10 || !json.Valid(origin) {
		return d, ErrMember
	}
	entry, ok := d.Entry(id)
	key, err := identity.ParseKey(entry.Peer.Key)
	if !ok || err != nil || !d.MemberKey(key) {
		return d, ErrMember
	}
	current := d.Cordon(id)
	if expected != current.Revision || current.Enabled == enabled {
		return d, ErrMember
	}
	d = clone(d)
	d.Revision++
	next := Cordon{Node: id, Enabled: enabled, Revision: current.Revision + 1, Origin: bytes.Clone(origin)}
	for i, row := range d.Cordons {
		if row.Node == id {
			d.Cordons[i] = next
			return d, d.Validate()
		}
	}
	d.Cordons = append(d.Cordons, next)
	slices.SortFunc(d.Cordons, func(a, b Cordon) int {
		if a.Node < b.Node {
			return -1
		}
		if a.Node > b.Node {
			return 1
		}
		return 0
	})
	return d, d.Validate()
}
func (d Directory) validateCordons() error {
	if len(d.Cordons) > len(d.Entries) {
		return ErrMember
	}
	previous := ""
	for _, row := range d.Cordons {
		_, ok := d.Entry(row.Node)
		if !ok || row.Node <= previous || row.Revision == 0 || row.Revision > d.Revision || len(row.Origin) == 0 || len(row.Origin) > 64<<10 || !json.Valid(row.Origin) {
			return ErrMember
		}
		previous = row.Node
	}
	return nil
}
