// SPDX-License-Identifier: Apache-2.0

package tenancy

import "slices"

// WithCommittedNetwork joins an already committed source to a read-only view.
// It preserves source generation/revision, grants no permission and creates no
// reservation receipt. Never persist this derived view over its base registry.
func (n Networks) WithCommittedNetwork(v Network) (Networks, error) {
	return n.WithCommittedNetworks([]Network{v})
}

// WithCommittedNetworks validates a complete projection once, rather than
// rebuilding the full address book for every source row.
func (n Networks) WithCommittedNetworks(values []Network) (Networks, error) {
	if len(values) == 0 {
		return n, nil
	}
	if len(values) > maxNetworks-len(n.networks) {
		return n, ErrPolicy
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	q.revision = n.revision
	for _, v := range values {
		if !validNetwork(v) || v.PendingChange != 0 {
			return n, ErrPolicy
		}
		if _, exists := q.networks[key(v.Tenant, v.ID)]; exists || q.reservedOverlap(v, "") {
			return n, ErrPolicy
		}
		q.revision = max(q.revision, v.Revision)
		q.networks[key(v.Tenant, v.ID)] = ownNetwork(v)
	}
	if _, err = q.AddressPlan(1); err != nil {
		return n, err
	}
	return q, nil
}

// WithCommittedReservation counts the exact original metadata source, including
// Drain/unknown lifetime. A manual entry with the same key is a second authority.
func (q Quotas) WithCommittedReservation(r Reservation) (Quotas, error) {
	return q.WithCommittedReservations([]Reservation{r})
}
func (q Quotas) WithCommittedReservations(values []Reservation) (Quotas, error) {
	if len(values) == 0 {
		return q, nil
	}
	if len(values) > 16384-len(q.reservations) {
		return q, ErrPolicy
	}
	n, err := q.clone()
	if err != nil {
		return q, err
	}
	n.revision = q.revision
	for _, r := range values {
		if !validReservation(r) {
			return q, ErrPolicy
		}
		if _, exists := n.reservations[r.Key]; exists {
			return q, ErrPolicy
		}
		n.revision = max(n.revision, r.Revision)
		n.reservations[r.Key] = r
	}
	if _, err = n.Encode(); err != nil {
		return q, err
	}
	return n, nil
}

// AllNetworks returns owned entries, without granting a user a filtered read.
// Only deterministic internal projection consumes this complete reservation set.
func (n Networks) AllNetworks() []Network {
	keys := make([]string, 0, len(n.networks))
	for k := range n.networks {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]Network, 0, len(keys))
	for _, k := range keys {
		out = append(out, ownNetwork(n.networks[k]))
	}
	return out
}
