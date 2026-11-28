// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/secrets"
)

// This is public metadata for a read of an already approved exact binding.
// It contains no provider URL/token, password, plaintext or plaintext hash.
type AppInputFetch struct {
	Schema           uint8
	Consumer         [32]byte
	Binding          AppBindingRequest
	ReadSet          [32]byte
	MinimumIndex     uint64
	Realm, Secret    string
	Move             *VolumeMoveSelection           `json:",omitempty"`
	ExternalRegistry *ExternalRegistryReadSelection `json:",omitempty"`
	ImageBuild       *ImageBuildSecretSelection     `json:",omitempty"`
}
type AppInputFetchPermit struct {
	Schema       uint8
	ReadSet      [32]byte
	CommandIndex uint64
	Realm        string
	Leaf         secrets.Leaf
	Provider     secrets.WriteProfile
	// Builtin is the holding of a builtin leaf: the digest the serving
	// voter must open from its local store.
	Builtin *secrets.BuiltinHolding `json:",omitempty"`
}

// servesProvider is whether provider may answer for profile: a current voter
// for the builtin profile, else the profile's own node key.
func (p Policy) servesProvider(s state.State, provider [32]byte, profile secrets.WriteProfile) bool {
	if profile.Builtin() {
		members, err := p.Members(s)
		return err == nil && members.VoterKey(provider)
	}
	return p.ownsResource(s, provider, profile.Key)
}

func (p Policy) AppInputFetchPermit(s state.State, provider [32]byte, q AppInputFetch) (AppInputFetchPermit, error) {
	permit, err := p.appInputFetchPermit(s, provider, q)
	if err != nil || !permit.Provider.Builtin() {
		return permit, err
	}
	v, err := p.Vault(s)
	if err != nil {
		return AppInputFetchPermit{}, err
	}
	h, ok := v.Trees[permit.Realm].BuiltinHolding(secrets.ValueWrite, permit.Leaf.Reference.Object, permit.Leaf.Reference.Revision)
	if !ok || permit.Leaf.Reference.Object != permit.Leaf.Secret {
		return AppInputFetchPermit{}, access.ErrDenied
	}
	permit.Builtin = &h
	return permit, nil
}

func (p Policy) appInputFetchPermit(s state.State, provider [32]byte, q AppInputFetch) (AppInputFetchPermit, error) {
	if q.Schema != 1 || q.Consumer == ([32]byte{}) || q.ReadSet == ([32]byte{}) || q.MinimumIndex == 0 || s.Index() < q.MinimumIndex {
		return AppInputFetchPermit{}, access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil || !(members.WorkKey(provider) || q.Move != nil && members.MemberKey(provider)) || !members.WorkKey(q.Consumer) {
		return AppInputFetchPermit{}, access.ErrDenied
	}
	if q.ImageBuild != nil {
		if q.Move != nil || q.ExternalRegistry != nil || q.Binding.Task != (deployment.ObjectRef{}) || q.Binding.Digest != ([32]byte{}) {
			return AppInputFetchPermit{}, access.ErrDenied
		}
		work, err := p.ImageBuildSecretInputs(s, q.Consumer, ImageBuildSecretRequest{Selection: *q.ImageBuild, At: q.Binding.At})
		if err != nil || work.Inputs.ReadSet != q.ReadSet {
			return AppInputFetchPermit{}, access.ErrDenied
		}
		for _, entry := range work.Inputs.Entries {
			if entry.Realm == q.Realm && entry.Leaf.Secret == q.Secret && p.servesProvider(s, provider, entry.Provider) {
				return AppInputFetchPermit{Schema: 1, ReadSet: q.ReadSet, CommandIndex: s.Index(), Realm: entry.Realm, Leaf: entry.Leaf, Provider: entry.Provider}, nil
			}
		}
		return AppInputFetchPermit{}, access.ErrDenied
	}
	if q.ExternalRegistry != nil {
		if q.Move != nil || q.Binding.Task != (deployment.ObjectRef{}) || q.Binding.Digest != ([32]byte{}) {
			return AppInputFetchPermit{}, access.ErrDenied
		}
		work, err := p.ExternalRegistryWork(s, q.Consumer, ExternalRegistryWorkRequest{Selection: *q.ExternalRegistry, At: q.Binding.At})
		if err != nil || work.Inputs.ReadSet != q.ReadSet {
			return AppInputFetchPermit{}, access.ErrDenied
		}
		for _, entry := range work.Inputs.Entries {
			if entry.Realm == q.Realm && entry.Leaf.Secret == q.Secret && p.servesProvider(s, provider, entry.Provider) {
				return AppInputFetchPermit{Schema: 1, ReadSet: q.ReadSet, CommandIndex: s.Index(), Realm: entry.Realm, Leaf: entry.Leaf, Provider: entry.Provider}, nil
			}
		}
		return AppInputFetchPermit{}, access.ErrDenied
	}
	var reads []AppInputRead
	var bound deployment.Binding
	if q.Move != nil {
		if q.Binding.Task.Key != "" || q.Binding.Task.Generation != 0 || q.Binding.Task.Revision != 0 || q.Binding.Digest != ([32]byte{}) {
			return AppInputFetchPermit{}, access.ErrDenied
		}
		permit, err := p.VolumeMovePermit(s, q.Consumer, VolumeMovePermitRequest{Selection: *q.Move, Kind: "prepare-inputs"}, q.Binding.At)
		if err != nil || permit.Inputs == nil || permit.Inputs.ReadSet != q.ReadSet {
			return AppInputFetchPermit{}, access.ErrDenied
		}
		reads = permit.Inputs.Reads
	} else {
		permit, err := p.AppBindingPermit(s, q.Consumer, q.Binding)
		if err != nil {
			return AppInputFetchPermit{}, access.ErrDenied
		}
		bound, err = deployment.DecodeBinding(permit.Binding)
		if err != nil {
			return AppInputFetchPermit{}, access.ErrDenied
		}
		switch {
		case permit.ReadSet == q.ReadSet:
			reads, err = p.AppInputReads(s, q.Consumer, q.Binding, permit)
		case permit.SocketReadSet != ([32]byte{}) && permit.SocketReadSet == q.ReadSet:
			// sfev.sock: the same holder answers, for the socket grants only.
			reads, err = p.AppSocketReads(s, q.Consumer, q.Binding, permit)
		}
		if err != nil {
			return AppInputFetchPermit{}, err
		}
	}
	for _, read := range reads {
		if read.Realm != q.Realm || q.Move != nil && !p.ownsResource(s, q.Consumer, read.Plan.Use.NodeKey) {
			continue
		}
		for _, leaf := range read.Plan.Leaves {
			if leaf.Secret != q.Secret {
				continue
			}
			for _, profile := range read.Profiles {
				if profile.ID == leaf.Reference.Profile && p.servesProvider(s, provider, profile) && profile.Enabled && profile.Values {
					return AppInputFetchPermit{Schema: 1, ReadSet: q.ReadSet, CommandIndex: s.Index(), Realm: read.Realm, Leaf: leaf, Provider: profile}, nil
				}
			}
		}
	}
	if q.Move == nil {
		for _, ref := range bound.Needs().RegistrySources {
			if ref.Realm != q.Realm || ref.Object != q.Secret {
				continue
			}
			var goal deployment.GoalCommand
			var service deployment.ComposeService
			if canonical([]byte(s.Object(q.Binding.Task.Key).Value), &goal) != nil || json.Unmarshal(goal.Config, &service) != nil {
				return AppInputFetchPermit{}, access.ErrDenied
			}
			current, err := p.RegistryImagePermit(s, q.Consumer, RegistryImageRequest{AppBindingRequest: q.Binding, Image: service.Image})
			if err != nil || current.ExternalInputs == nil || current.ExternalInputs.ReadSet != q.ReadSet {
				return AppInputFetchPermit{}, access.ErrDenied
			}
			for _, entry := range current.ExternalInputs.Entries {
				if entry.Realm == q.Realm && entry.Leaf.Secret == q.Secret && p.servesProvider(s, provider, entry.Provider) {
					return AppInputFetchPermit{Schema: 1, ReadSet: q.ReadSet, CommandIndex: s.Index(), Realm: entry.Realm, Leaf: entry.Leaf, Provider: entry.Provider}, nil
				}
			}
		}
	}
	return AppInputFetchPermit{}, access.ErrDenied
}
