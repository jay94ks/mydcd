// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// VolumeSelector selects logical metadata, never a native name or host path.
type VolumeSelector struct{ App, ID string }

func (q VolumeSelector) Valid() bool { return lifecycle.ValidID(q.App) && lifecycle.ValidID(q.ID) }

func sameVolumeNative(a, b volumes.NativeReady) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// VolumeNative runs against the supplied committed view. Its adapter obtains
// a fresh quorum view before and after collecting the node-local observation.
func (p Policy) VolumeNative(s state.State, session access.Session, at int64, tenant string, q VolumeSelector) (volumes.NativeReady, error) {
	policy, err := p.Current(s)
	if err != nil {
		return volumes.NativeReady{}, err
	}
	p = policy
	c, err := p.Catalog(s)
	if err != nil || tenant == "" || !q.Valid() || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, "") != nil {
		return volumes.NativeReady{}, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return volumes.NativeReady{}, err
	}
	e, ok := v.entries[tenant+"/"+q.App+"/"+q.ID]
	if !ok || e.State.Deleted() {
		return volumes.NativeReady{}, access.ErrDenied
	}
	owner, _ := e.State.Owner()
	current, err := p.nodeOwner(s, owner.Node)
	if err != nil || !p.ownsResource(s, current, owner.Key) || e.Native.Owner != owner {
		return volumes.NativeReady{}, access.ErrDenied
	}
	return e.Native, nil
}

// VolumeUsagePermit admits only the current native owner and exact registered
// materialization. A stale local DB, caller-supplied path or another member's
// key cannot authorize a scan. The return value is a source index, not a lease
// or writer permit; collecting usage has no external write effect.
func (p Policy) VolumeUsagePermit(s state.State, caller [32]byte, ready volumes.NativeReady) (uint64, error) {
	if ready.Verify() != nil || ready.Spec.Scope.Cluster != p.Cluster || !p.ownsResource(s, caller, ready.Owner.Key) {
		return 0, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return 0, err
	}
	e, ok := v.entries[volumeKey(ready.Spec.Scope)]
	if !ok || e.State.Deleted() || !sameVolumeNative(e.Native, ready) {
		return 0, access.ErrDenied
	}
	owner, _ := e.State.Owner()
	current, err := p.nodeOwner(s, owner.Node)
	if err != nil || owner != ready.Owner || current != caller || s.Index() == 0 {
		return 0, access.ErrDenied
	}
	return s.Index(), nil
}
