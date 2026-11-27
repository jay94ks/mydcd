// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// VolumeMoveInputs contains only the original target's authorized public
// metadata. A digest is not evidence that any provider value has been read.
type VolumeMoveInputs struct {
	ReadSet      [32]byte
	CommandIndex uint64
	Reads        []AppInputRead           `json:"-"`
	Resources    []VolumeMoveResourceRead `json:"-"`
}

type VolumeMoveInputProbe struct {
	Selection    VolumeMoveSelection
	ReadSet      [32]byte
	MinimumIndex uint64
	At           int64
}

// Each actual consumer observes only its own private inputs. The target gathers
// these public, signed observations before attesting whole-target preparation.
type VolumeMoveInputProof struct {
	Schema                     uint8
	Selection                  VolumeMoveSelection
	Binding, ReadSet, Consumer [32]byte
	At                         int64
	Signature                  []byte
}

func VolumeMoveInputProofBytes(p VolumeMoveInputProof) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("sfc-volume-move-inputs-1\x00"), raw...)
}

func (p VolumeMoveInputProof) Verify(j VolumeMove, readSet, consumer [32]byte, now int64) error {
	if p.Schema != 1 || p.Selection != j.Selection() || p.Binding != j.Digest() || p.ReadSet != readSet || readSet == ([32]byte{}) || p.Consumer != consumer || consumer == ([32]byte{}) || p.At < 0 || p.At > now || now-p.At > 30 || !ed25519.Verify(consumer[:], VolumeMoveInputProofBytes(p), p.Signature) {
		return access.ErrDenied
	}
	return nil
}

func (p Policy) moveInputSet(s state.State, j VolumeMove, at int64) (*VolumeMoveInputs, error) {
	reads, err := p.moveAppInputReads(s, j, at)
	if err != nil {
		return nil, err
	}
	if j.App == nil || j.App.Target == nil {
		return nil, nil
	}
	resources, err := p.moveResourceReads(s, j)
	if err != nil {
		return nil, err
	}
	digest, err := movePreparationDigest(j.Digest(), reads, resources)
	if err != nil {
		return nil, err
	}
	return &VolumeMoveInputs{ReadSet: digest, CommandIndex: s.Index(), Reads: reads, Resources: resources}, nil
}

func (p Policy) moveInputsPrepared(s state.State, j VolumeMove, m volumes.Move, at int64) error {
	if j.App == nil || j.App.Target == nil {
		return nil
	}
	current, err := p.moveInputSet(s, j, at)
	if err != nil || current == nil || m.Preparation == nil || m.Preparation.Inputs == nil || *m.Preparation.Inputs != current.ReadSet || m.Preparation.InputsAt <= 0 || m.Preparation.InputsAt > at || at-m.Preparation.InputsAt > 30 {
		return access.ErrDenied
	}
	return nil
}

func moveInputConsumer(inputs *VolumeMoveInputs, caller [32]byte) bool {
	for _, resource := range inputs.Resources {
		if resource.Owner == caller {
			return true
		}
	}
	for _, read := range inputs.Reads {
		if read.Plan.Use.NodeKey == caller {
			return true
		}
	}
	return false
}

// The wire permit stays bounded. Exact plans are reconstructed from the local
// committed replica only after it contains the same quorum read-set/index.
func (p Policy) VolumeMovePreparationInputs(s state.State, caller [32]byte, permit VolumeMovePermit, at int64) (*VolumeMoveInputs, error) {
	current, err := p.VolumeMovePermit(s, caller, VolumeMovePermitRequest{Selection: permit.Job.Selection(), Kind: "prepare-inputs"}, at)
	if err != nil || permit.Inputs == nil || current.Inputs == nil || current.Job.Digest() != permit.Job.Digest() || s.Index() < permit.Inputs.CommandIndex || current.Inputs.ReadSet != permit.Inputs.ReadSet {
		return nil, access.ErrDenied
	}
	return current.Inputs, nil
}

func (p Policy) VolumeMoveInputReads(s state.State, caller [32]byte, permit VolumeMovePermit, at int64) ([]AppInputRead, error) {
	inputs, err := p.VolumeMovePreparationInputs(s, caller, permit, at)
	if err != nil {
		return nil, err
	}
	return inputs.Reads, nil
}

// CheckMoveInputValues consumes only a local replica containing the exact
// current quorum permit. No copied permit or preflight allocates a Binding.
func (p Policy) CheckMoveInputValues(s state.State, caller [32]byte, permit VolumeMovePermit, at int64, values []deployment.Fetched, maxBytes int) error {
	reads, err := p.VolumeMoveInputReads(s, caller, permit, at)
	if err != nil {
		return err
	}
	apps, err := p.Apps(s)
	if err != nil {
		return err
	}
	var q VolumeMoveBegin
	if moveBeginForJob(permit.Job, &q) != nil {
		return ErrCatalog
	}
	b, err := p.frozenMoveBlueprint(apps, permit.Job.Origin, q)
	if err != nil {
		return err
	}
	plans := map[string]map[string]secrets.UsePlan{}
	for _, read := range reads {
		if !p.ownsResource(s, caller, read.Plan.Use.NodeKey) {
			continue
		}
		service := read.Plan.Use.Service
		if plans[service] == nil {
			plans[service] = map[string]secrets.UsePlan{}
		}
		if _, exists := plans[service][read.Realm]; exists {
			return ErrCatalog
		}
		plans[service][read.Realm] = read.Plan
	}
	used := map[string]bool{}
	for service, realms := range plans {
		wanted := map[string]bool{}
		for realm, plan := range realms {
			for _, leaf := range plan.Leaves {
				wanted[realm+"/"+leaf.Secret] = true
			}
		}
		var selected []deployment.Fetched
		for _, value := range values {
			key := value.Realm + "/" + value.Value.Secret
			if wanted[key] {
				selected = append(selected, value)
				used[key] = true
			}
		}
		instances, err := b.ServiceInstances(service)
		if err != nil {
			return err
		}
		matched := false
		for _, instance := range instances {
			local := true
			for _, plan := range realms {
				local = local && plan.Use.Node == instance.Node
			}
			if !local {
				continue
			}
			matched = true
			if err := b.CheckPreparedInputs(instance.ResourceID(), moveInputRequester(permit.Job.Origin, q), realms, selected, maxBytes); err != nil {
				return err
			}
		}
		if !matched {
			return ErrCatalog
		}
	}
	for _, value := range values {
		if !used[value.Realm+"/"+value.Value.Secret] {
			return access.ErrDenied
		}
	}
	return nil
}

func movePreparationDigest(binding [32]byte, reads []AppInputRead, resources []VolumeMoveResourceRead) ([32]byte, error) {
	raw, err := json.Marshal(struct {
		Binding   [32]byte
		Reads     []AppInputRead
		Resources []VolumeMoveResourceRead
	}{binding, reads, resources})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte("sfc-volume-move-readset-1\x00"), raw...)), nil
}

func (p Policy) moveInputCaller(s state.State, inputs *VolumeMoveInputs, caller [32]byte) bool {
	for _, resource := range inputs.Resources {
		if p.ownsResource(s, caller, resource.Owner) {
			return true
		}
	}
	for _, read := range inputs.Reads {
		if p.ownsResource(s, caller, read.Plan.Use.NodeKey) {
			return true
		}
	}
	return false
}
