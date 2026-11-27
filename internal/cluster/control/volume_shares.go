// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// VolumeSharesKey records which Volumes other servers may use through
// their home (SFCP VolumeFS). A Volume without a record is used only on its
// home node, as before. Mounts, open files and locks are never here: the
// home keeps them and drops them when a consuming server goes away.
// See devel/proposals/shared-volumes-over-sfcp.md.
const VolumeSharesKey = "control/volume-shares"

const (
	// VolumeRemoteSingleWriter lets one server write and any server read.
	VolumeRemoteSingleWriter = "single-writer"
	// VolumeRemoteShared lets servers write together under the home's locks.
	VolumeRemoteShared = "shared"
	// VolumeRemoteOff removes the record (the Volume stays on its home).
	VolumeRemoteOff = "off"
)

// VolumeRemoteChange is the signed set-volume-remote payload. Change.Expected
// is the Volume's current share Revision (0 when it has none), so a change
// made on a stale view fails instead of overwriting another one.
type VolumeRemoteChange struct {
	Volume volumes.Scope
	Mode   string
}

func validRemoteMode(m string) bool {
	return m == VolumeRemoteSingleWriter || m == VolumeRemoteShared || m == VolumeRemoteOff
}

// VolumeShare is one Volume's remote access setting.
type VolumeShare struct {
	Origin   UserOperation
	Volume   volumes.Scope
	Mode     string
	Revision uint64
	At       uint64
}

// VolumeShares is the book, one record per Volume key in ascending order.
type VolumeShares struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Records  []VolumeShare
}

// Share returns the setting of the Volume generation scope names. A record
// left from an earlier generation does not apply.
func (b VolumeShares) Share(scope volumes.Scope) (VolumeShare, bool) {
	i, ok := b.find(scope.Key())
	if !ok || b.Records[i].Volume != scope {
		return VolumeShare{}, false
	}
	return b.Records[i], true
}

func (b VolumeShares) find(key string) (int, bool) {
	return slices.BinarySearchFunc(b.Records, key, func(r VolumeShare, k string) int {
		switch rk := r.Volume.Key(); {
		case rk < k:
			return -1
		case rk > k:
			return 1
		}
		return 0
	})
}

func (p Policy) VolumeShares(s state.State) (VolumeShares, error) {
	out := VolumeShares{Schema: 1, Cluster: p.Cluster}
	raw, revision, err := readCheckpoint(s, VolumeSharesKey, p.Cluster, p.TrustRoot)
	if err != nil || raw == nil {
		return out, err
	}
	if canonical(raw, &out) != nil || out.Schema != 1 || out.Cluster != p.Cluster || out.Revision != revision || len(out.Records) > maxVolumes {
		return out, ErrCatalog
	}
	last := ""
	for _, r := range out.Records {
		var q VolumeRemoteChange
		key := r.Volume.Key()
		if r.Origin.VerifyOriginal(p.Cluster) != nil || r.Origin.Change.Action != "set-volume-remote" || canonical(r.Origin.Change.Payload, &q) != nil || q.Volume != r.Volume || q.Mode != r.Mode || r.Mode == VolumeRemoteOff || !validRemoteMode(r.Mode) || r.Volume.Cluster != p.Cluster || r.Volume.RegistryManaged() || r.Revision == 0 || r.At != uint64(r.Origin.At) || key <= last {
			return out, ErrCatalog
		}
		last = key
	}
	return out, nil
}

// planning lists tenant's records for the app planner.
func (b VolumeShares) planning(tenant string) map[string]deployment.VolumeShare {
	out := map[string]deployment.VolumeShare{}
	for _, r := range b.Records {
		if r.Volume.Tenant == tenant {
			out[r.Volume.Key()] = deployment.VolumeShare{Scope: r.Volume, Mode: r.Mode}
		}
	}
	return out
}

// mode is Reserve's view of the records (deployment.ShareMode).
func (b VolumeShares) mode(scope volumes.Scope) string {
	r, ok := b.Share(scope)
	if !ok {
		return ""
	}
	return r.Mode
}

// remoteRunner says whether caller is the current key of the server that
// runs remote consumer c, and scope still has a share record of exactly this
// generation. Historical runner keys never match.
func (p Policy) remoteRunner(s state.State, caller [32]byte, scope volumes.Scope, c volumes.Consumer) bool {
	original, ok := c.GoneKey()
	if !ok || caller == ([32]byte{}) || p.resourceCallerForNode(s, c.Runner, original) != caller {
		return false
	}
	b, err := p.VolumeShares(s)
	if err != nil {
		return false
	}
	_, ok = b.Share(scope)
	return ok
}

// VolumeRemoteGrant is the home's answer to a VolumeFS mount: peer may use
// scope for consumer id now when peer is that remote consumer's runner, the
// share record matches the exact generation, the Volume admits a start and
// the consumer's user may still use it. The returned consumer says whether
// the mount writes; the NativeReady names the directory to serve. home is the caller's own current key; the Volume must
// be owned by it.
func (p Policy) VolumeRemoteGrant(s state.State, home, peer [32]byte, scope volumes.Scope, id string) (volumes.Consumer, volumes.NativeReady, error) {
	v, err := p.Volumes(s)
	if err != nil {
		return volumes.Consumer{}, volumes.NativeReady{}, err
	}
	e, ok := v.entries[volumeKey(scope)]
	if !ok || e.State.Scope() != scope {
		return volumes.Consumer{}, volumes.NativeReady{}, access.ErrDenied
	}
	owner, _ := e.State.Owner()
	current, err := p.nodeOwner(s, owner.Node)
	if err != nil || current != home || !p.ownsResource(s, current, owner.Key) {
		return volumes.Consumer{}, volumes.NativeReady{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return volumes.Consumer{}, volumes.NativeReady{}, err
	}
	for _, g := range e.Grants {
		if g.Consumer.ID != id || !g.Consumer.Remote() {
			continue
		}
		if !p.remoteRunner(s, peer, scope, g.Consumer) || e.State.CheckActivation(g.Consumer) != nil {
			return volumes.Consumer{}, volumes.NativeReady{}, access.ErrDenied
		}
		if err := p.canUseFixedVolume(s, c, g.Principal, e); err != nil {
			return volumes.Consumer{}, volumes.NativeReady{}, err
		}
		if c.Authorize(g.Principal, scope.Tenant, access.ManageVolumes, owner.Node) != nil {
			return volumes.Consumer{}, volumes.NativeReady{}, access.ErrDenied
		}
		return g.Consumer, e.Native, nil
	}
	return volumes.Consumer{}, volumes.NativeReady{}, access.ErrDenied
}

// volumeRemoteAuthorized: changing where a Volume may be used is managing
// that tenant's Volumes on its home node.
func (p Policy) volumeRemoteAuthorized(s state.State, c access.Catalog, op UserOperation) (VolumeRemoteChange, volumes.State, error) {
	var q VolumeRemoteChange
	if canonical(op.Change.Payload, &q) != nil || !validRemoteMode(q.Mode) || q.Volume.Cluster != p.Cluster || q.Volume.RegistryManaged() {
		return q, volumes.State{}, access.ErrInvalid
	}
	v, err := p.Volumes(s)
	if err != nil {
		return q, volumes.State{}, err
	}
	vol, ok := v.Volume(q.Volume)
	if !ok {
		return q, volumes.State{}, access.ErrInvalid
	}
	owner, _ := vol.Owner()
	if err := c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Volume.Tenant, access.ManageVolumes, owner.Node); err != nil {
		return q, vol, err
	}
	return q, vol, nil
}

func (p Policy) reduceVolumeShares(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	p, err := p.Current(s)
	if err != nil || cmd.Kind != state.Module || cmd.Key != VolumeSharesKey {
		return nil, state.Invalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || op.Change.Action != "set-volume-remote" {
		return nil, state.Invalid
	}
	if c.OperationAllowed(op.Session, op.Change.Action) != nil {
		return nil, state.Forbidden
	}
	q, _, err := p.volumeRemoteAuthorized(s, c, op)
	if err == access.ErrInvalid {
		return nil, state.Invalid
	}
	if err != nil {
		return nil, state.Forbidden
	}
	b, err := p.VolumeShares(s)
	if err != nil {
		return nil, state.Invalid
	}
	key := q.Volume.Key()
	i, exists := b.find(key)
	current := uint64(0)
	if exists && b.Records[i].Volume == q.Volume {
		current = b.Records[i].Revision
	}
	if op.Change.Expected != current || b.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	switch {
	case q.Mode == VolumeRemoteOff && !exists:
		return nil, state.ConditionFailed
	case q.Mode == VolumeRemoteOff:
		b.Records = slices.Delete(b.Records, i, i+1)
	case exists && b.Records[i].Mode == q.Mode && b.Records[i].Volume == q.Volume:
		return nil, state.ConditionFailed
	default:
		// A record of an earlier generation is replaced, never carried over.
		r := VolumeShare{Origin: op, Volume: q.Volume, Mode: q.Mode, Revision: current + 1, At: uint64(op.At)}
		if exists {
			b.Records[i] = r
		} else {
			if len(b.Records) >= maxVolumes {
				return nil, state.ConditionFailed
			}
			b.Records = slices.Insert(b.Records, i, r)
		}
	}
	b.Revision++
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > 4<<20 {
		return nil, state.ConditionFailed
	}
	return writeCheckpoint(s, VolumeSharesKey, p.Cluster, p.TrustRoot, b.Revision, raw)
}

// volumeSharesBook is the VolumeSharesKey Raft book (see book.go).
var volumeSharesBook = Book{
	Key:     VolumeSharesKey,
	Actions: []string{"set-volume-remote"},
	Reduce:  byKind(map[state.CommandKind]reducer{state.Module: Policy.reduceVolumeShares}),
	Authorize: func(p Policy, s state.State, c access.Catalog, op UserOperation) error {
		_, _, err := p.volumeRemoteAuthorized(s, c, op)
		return err
	},
}
