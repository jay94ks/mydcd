// SPDX-License-Identifier: Apache-2.0

package tenancy

// OwnerRotation changes future quota admission for one logical node. Native
// reservations/networks retain their original owner/signature. The control
// reducer binds this metadata to the accepted dual-key identity transition;
// this package grants no TLS, session, user or node-command authentication.
type OwnerRotation struct {
	Node, Operation string
	Old, New, Proof [32]byte
	Index           uint64
}

func (q Quotas) OwnerRotations() []OwnerRotation {
	out := make([]OwnerRotation, len(q.ownerRotations))
	copy(out, q.ownerRotations)
	return out
}
func (q Quotas) canonicalOwner(node string, key [32]byte) [32]byte {
	for i := 0; i <= 32; i++ {
		row, ok := q.ownerKeys[key]
		if !ok || row.Node != node {
			return key
		}
		key = row.New
	}
	return [32]byte{}
}
func (q Quotas) SameOwner(node string, a, b [32]byte) bool {
	return a != ([32]byte{}) && b != ([32]byte{}) && q.canonicalOwner(node, a) == q.canonicalOwner(node, b) && q.canonicalOwner(node, a) != ([32]byte{})
}
func (q Quotas) RotateOwner(row OwnerRotation) (Quotas, error) {
	if !validID(row.Node) || !validID(row.Operation) || row.Old == ([32]byte{}) || row.New == ([32]byte{}) || row.Old == row.New || row.Proof == ([32]byte{}) || row.Index == 0 || len(q.ownerRotations) >= 32768 || q.canonicalOwner(row.Node, row.Old) != row.Old {
		return q, ErrPolicy
	}
	for _, old := range q.ownerRotations {
		if old.Operation == row.Operation || old.Old == row.New || old.New == row.New || old.Old == row.Old {
			return q, ErrPolicy
		}
	}
	n, err := q.clone()
	if err != nil {
		return q, err
	}
	n.ownerRotations = append(n.ownerRotations, row)
	n.ownerKeys[row.Old] = row
	for key, limit := range n.limits {
		if limit.Node == row.Node {
			if limit.Owner != row.Old {
				return q, ErrPolicy
			}
			limit.Owner = row.New
			limit.Revision = n.revision
			n.limits[key] = limit
		}
	}
	if _, err = n.Encode(); err != nil {
		return q, err
	}
	return n, nil
}
func (q Quotas) validateOwnerRotations() bool {
	if len(q.ownerRotations) > 32768 || len(q.ownerKeys) != len(q.ownerRotations) {
		return false
	}
	seen := map[[32]byte]bool{}
	operations := map[string]bool{}
	for _, row := range q.ownerRotations {
		if !validID(row.Node) || !validID(row.Operation) || row.Old == ([32]byte{}) || row.New == ([32]byte{}) || row.Old == row.New || row.Proof == ([32]byte{}) || row.Index == 0 || seen[row.New] || operations[row.Operation] || q.ownerKeys[row.Old] != row {
			return false
		}
		seen[row.Old] = true
		seen[row.New] = true
		operations[row.Operation] = true
	}
	for _, row := range q.ownerRotations {
		if q.canonicalOwner(row.Node, row.Old) == ([32]byte{}) {
			return false
		}
	}
	return true
}
