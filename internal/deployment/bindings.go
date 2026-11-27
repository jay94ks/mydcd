// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

const maxBindings = 4096

// Bindings owns immutable task input recipes and generation floors. It is part
// of app inventory, committed in the SAME FSM transaction as approvals/volumes,
// not another independently replicated authority.
type Bindings struct {
	cluster  [32]byte
	revision uint64
	live     map[string]Binding
	floors   map[string]uint64
}

func NewBindings(cluster [32]byte) (Bindings, error) {
	if cluster == ([32]byte{}) {
		return Bindings{}, ErrInputs
	}
	return Bindings{cluster: cluster, live: map[string]Binding{}, floors: map[string]uint64{}}, nil
}
func consumerKey(n Needs) string {
	u := n.Use
	return u.Tenant + "/" + u.App + "/" + u.Deployment + "/" + n.Consumer
}
func bindingKey(n Needs) string      { return consumerKey(n) + "/" + strconv.FormatUint(n.Generation, 10) }
func (b Bindings) Revision() uint64  { return b.revision }
func (b Bindings) Cluster() [32]byte { return b.cluster }
func (b Bindings) Owns(v Binding) bool {
	original, ok := b.live[bindingKey(v.d.Needs)]
	return ok && b.cluster == v.d.Cluster && original.Digest() == v.Digest()
}
func (b Bindings) Live() []Binding {
	keys := make([]string, 0, len(b.live))
	for k := range b.live {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]Binding, 0, len(keys))
	for _, k := range keys {
		out = append(out, Binding{ownBinding(b.live[k].d)})
	}
	return out
}
func (b Bindings) clone() (Bindings, error) {
	if b.cluster == ([32]byte{}) || b.live == nil || b.floors == nil || b.revision == ^uint64(0) {
		return b, ErrInputs
	}
	n := Bindings{cluster: b.cluster, revision: b.revision + 1, live: map[string]Binding{}, floors: map[string]uint64{}}
	for k, v := range b.live {
		n.live[k] = Binding{ownBinding(v.d)}
	}
	for k, v := range b.floors {
		n.floors[k] = v
	}
	return n, nil
}

// Reserve protects complete recipes, including file projections. A returned
// generation cannot be borrowed again; changed recipes require new task/native
// lifecycles. This method reads no provider values and creates no native object.
func (b Bindings) Reserve(expected uint64, c access.Catalog, trees map[string]secrets.Tree, a secrets.Approvals, v map[string]volumes.State, needs []Needs, now int64, shares ShareMode) (Reservation, error) {
	if expected != b.revision {
		return Reservation{}, access.ErrConflict
	}
	if _, e := Required(b.cluster, c, trees, needs); e != nil {
		return Reservation{}, e
	}
	added := 0
	for _, n := range needs {
		if old, ok := b.live[bindingKey(n)]; ok {
			if !sameNeeds(old.d.Needs, n) || old.Check(b, c, trees, a, v, now) != nil {
				return Reservation{}, ErrInputs
			}
		} else {
			if n.Generation <= b.floors[consumerKey(n)] {
				return Reservation{}, ErrInputs
			}
			added++
		}
	}
	if len(b.live)+added > maxBindings {
		return Reservation{}, ErrInputs
	}
	r, e := reserve(b.cluster, c, trees, a, v, needs, now, shares)
	if e != nil {
		return Reservation{}, e
	}
	n := b
	if added > 0 {
		n, e = b.clone()
		if e != nil {
			return Reservation{}, e
		}
	}
	for _, bound := range r.Bindings {
		k := bindingKey(bound.d.Needs)
		if old, ok := n.live[k]; ok {
			if old.Digest() != bound.Digest() {
				return Reservation{}, ErrInputs
			}
			continue
		}
		base := consumerKey(bound.d.Needs)
		if _, ok := n.floors[base]; !ok && len(n.floors) >= maxBindings {
			return Reservation{}, ErrInputs
		}
		n.live[k] = bound
		n.floors[base] = bound.d.Needs.Generation
	}
	if _, e = n.Encode(); e != nil {
		return Reservation{}, e
	}
	r.Inventory = n
	return r, nil
}
func sameNeeds(a, b Needs) bool {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(aa, bb)
}

// Release permits original closure after user/approval/node revocation. It
// retires metadata pins, not retained volumes or provider values.
func (b Bindings) Release(expected uint64, bound Binding, a secrets.Approvals, v map[string]volumes.State, proof Closure) (Reservation, error) {
	if expected != b.revision {
		return Reservation{}, access.ErrConflict
	}
	if !b.Owns(bound) {
		return Reservation{}, ErrInputs
	}
	r, e := bound.release(a, v, proof)
	if e != nil {
		return Reservation{}, e
	}
	n, e := b.clone()
	if e != nil {
		return Reservation{}, e
	}
	delete(n.live, bindingKey(bound.d.Needs))
	r.Inventory = n
	return r, nil
}

type bindingFloor struct {
	Key        string
	Generation uint64
}
type bindingsRecord struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Live     []bindingRecord
	Floors   []bindingFloor
}

func (b Bindings) Encode() ([]byte, error) {
	if b.cluster == ([32]byte{}) || b.live == nil || b.floors == nil || len(b.live) > maxBindings || len(b.floors) > maxBindings {
		return nil, ErrInputs
	}
	d := bindingsRecord{Schema: 1, Cluster: b.cluster, Revision: b.revision}
	for _, v := range b.Live() {
		if !validBinding(v) || v.d.Cluster != b.cluster || v.d.Needs.Generation > b.floors[consumerKey(v.d.Needs)] {
			return nil, ErrInputs
		}
		d.Live = append(d.Live, ownBinding(v.d))
	}
	for k, g := range b.floors {
		d.Floors = append(d.Floors, bindingFloor{k, g})
	}
	slices.SortFunc(d.Floors, func(a, b bindingFloor) int { return strings.Compare(a.Key, b.Key) })
	raw, e := json.Marshal(d)
	if len(raw) > 16<<20 {
		return nil, ErrInputs
	}
	return raw, e
}
func DecodeBindings(raw []byte) (Bindings, error) {
	if len(raw) > 16<<20 {
		return Bindings{}, ErrInputs
	}
	var d bindingsRecord
	if json.Unmarshal(raw, &d) != nil || d.Schema != 1 || len(d.Live) > maxBindings || len(d.Floors) > maxBindings || d.Revision == 0 && (len(d.Live) != 0 || len(d.Floors) != 0) || d.Revision > 0 && len(d.Floors) == 0 {
		return Bindings{}, ErrInputs
	}
	b, e := NewBindings(d.Cluster)
	if e != nil {
		return b, e
	}
	b.revision = d.Revision
	for i, f := range d.Floors {
		parts := strings.Split(f.Key, "/")
		if len(parts) != 4 || f.Generation == 0 || i > 0 && d.Floors[i-1].Key >= f.Key {
			return Bindings{}, ErrInputs
		}
		for _, p := range parts {
			if !identifier(p) {
				return Bindings{}, ErrInputs
			}
		}
		b.floors[f.Key] = f.Generation
	}
	previous := ""
	for _, v := range d.Live {
		bound := Binding{v}
		k := bindingKey(v.Needs)
		if !validBinding(bound) || v.Cluster != b.cluster || k <= previous || v.Needs.Generation > b.floors[consumerKey(v.Needs)] {
			return Bindings{}, ErrInputs
		}
		b.live[k] = bound
		previous = k
	}
	canonical, e := b.Encode()
	if e != nil || !bytes.Equal(canonical, raw) {
		return Bindings{}, ErrInputs
	}
	return b, nil
}
