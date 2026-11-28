// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// VolumeRemoteFenceWork is a remote consumer of a Volume the home owns whose
// runner was removed or retired from the cluster: it can never sign its Gone,
// so the home ends its sessions and signs a volumes.RemoteFence instead.
type VolumeRemoteFenceWork struct {
	Scope    volumes.Scope
	Consumer volumes.Consumer
	// Owner is the Volume's original owner key, the one that signs.
	Owner [32]byte
}

// VolumeRemoteFenceReport carries the home's fence (node report).
type VolumeRemoteFenceReport struct {
	Operation           string
	Schema              uint8
	Epoch, RootRevision uint64
	At                  int64
	Proof               volumes.RemoteFence
}

func volumeRemoteFenceReportValue(raw []byte) bool {
	var value struct{ Operation string }
	return json.Unmarshal(raw, &value) == nil && value.Operation == "remote-fence"
}

// runnerGone: the remote consumer's runner is no longer a member and never
// will be again (removed or retired). Isolated or unreachable is not gone.
func (p Policy) runnerGone(s state.State, c volumes.Consumer) bool {
	if !c.Remote() {
		return false
	}
	d, err := p.Members(s)
	return err == nil && d.Gone(c.Runner)
}

// VolumeRemoteFences lists the fence work of the Volumes whose original owner
// key mine accepts, in Volume then consumer order.
func (p Policy) VolumeRemoteFences(s state.State, mine func(owner [32]byte) bool) ([]VolumeRemoteFenceWork, error) {
	v, err := p.Volumes(s)
	if err != nil {
		return nil, err
	}
	var out []VolumeRemoteFenceWork
	for _, e := range v.entries {
		owner, _ := e.State.Owner()
		if !mine(owner.Key) {
			continue
		}
		for _, c := range e.State.Consumers() {
			if p.runnerGone(s, c) {
				out = append(out, VolumeRemoteFenceWork{Scope: e.State.Scope(), Consumer: c, Owner: owner.Key})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := out[i].Scope.Key(), out[j].Scope.Key(); a != b {
			return a < b
		}
		return out[i].Consumer.ID < out[j].Consumer.ID
	})
	return out, nil
}

func (p Policy) volumeRemoteFenceReport(s state.State, cmd state.Command) (VolumeRemoteFenceReport, error) {
	var r VolumeRemoteFenceReport
	if cmd.Kind != state.ModuleReport || cmd.Key != VolumesKey || canonical([]byte(cmd.Value), &r) != nil || r.Operation != "remote-fence" || r.Schema != 1 || r.Epoch != cmd.Epoch || r.RootRevision != cmd.Expected || r.At < 0 || cmd.RequestID != state.ReportRequestID(cmd) {
		return r, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return r, err
	}
	e, ok := v.entries[volumeKey(r.Proof.Scope)]
	if !ok || e.State.Scope() != r.Proof.Scope {
		return r, access.ErrDenied
	}
	owner, _ := e.State.Owner()
	if cmd.Actor != "node/"+hex.EncodeToString(owner.Key[:]) || r.Proof.Verify(owner.Key) != nil {
		return r, access.ErrDenied
	}
	current, err := p.nodeOwner(s, owner.Node)
	if err != nil || !p.ownsResource(s, current, owner.Key) {
		return r, access.ErrDenied
	}
	if !slices.Contains(e.State.Consumers(), r.Proof.Consumer) || !p.runnerGone(s, r.Proof.Consumer) {
		return r, access.ErrDenied
	}
	return r, nil
}

// ResolveVolumeRemoteFenceReport admits the report from the home's current key.
func (p Policy) ResolveVolumeRemoteFenceReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	r, err := schema.Decode[VolumeRemoteFenceReport](raw)
	if err != nil {
		return state.Command{}, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return state.Command{}, err
	}
	e, ok := v.entries[volumeKey(r.Proof.Scope)]
	if !ok {
		return state.Command{}, access.ErrDenied
	}
	owner, _ := e.State.Owner()
	if !p.ownsResource(s, caller, owner.Key) {
		return state.Command{}, access.ErrDenied
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(owner.Key[:]), Epoch: r.Epoch, Key: VolumesKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = p.volumeRemoteFenceReport(s, cmd)
	return cmd, err
}

func (p Policy) reduceVolumeRemoteFenceReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.volumeRemoteFenceReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	key := volumeKey(r.Proof.Scope)
	e := v.entries[key]
	if e.State, err = e.State.ReleaseFenced(r.Proof); err != nil {
		return nil, state.ConditionFailed
	}
	e.Grants = slices.DeleteFunc(e.Grants, func(g volumeGrant) bool { return g.Consumer == r.Proof.Consumer })
	v.entries[key] = e
	return p.volumeCheckpoint(s, v)
}
