// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/imagecache"
	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/secrets"
)

// RegistryImagePermit is a current, owner-only read. Managed and external
// definitions are exclusive. With neither, trusted external access is anonymous.
type RegistryImageRequest struct {
	AppBindingRequest
	Image    string
	ConfigID string `json:",omitempty"` // optional resolved native cache fence, never an origin proof
}
type RegistryImagePermit struct {
	Subject        registry.TaskSubject
	Registry       *registry.Specification `json:",omitempty"`
	External       *imagesource.Source     `json:",omitempty"`
	ExternalInputs *RegistryImageInputs    `json:",omitempty"`
	Index, Epoch   uint64
}

type RegistryImageInput struct {
	Realm    string
	Leaf     secrets.Leaf
	Provider secrets.WriteProfile
}
type RegistryImageInputs struct {
	ReadSet [32]byte
	Entries []RegistryImageInput
}

func (p Policy) RegistryImagePermit(s state.State, caller [32]byte, q RegistryImageRequest) (RegistryImagePermit, error) {
	if q.At <= 0 {
		return RegistryImagePermit{}, access.ErrDenied
	}
	permit, err := p.AppBindingPermit(s, caller, q.AppBindingRequest)
	if err != nil {
		return RegistryImagePermit{}, err
	}
	binding, err := deployment.DecodeBinding(permit.Binding)
	if err != nil {
		return RegistryImagePermit{}, access.ErrDenied
	}
	needs := binding.Needs()
	if q.ConfigID != "" && (!imagecache.ValidID(q.ConfigID) || p.imageCacheAvailable(s, needs.Use.Node, q.ConfigID) != nil) {
		return RegistryImagePermit{}, access.ErrDenied
	}
	var goal deployment.GoalCommand
	object := s.Object(q.Task.Key)
	if canonical([]byte(object.Value), &goal) != nil || goal.Kind != "task" || goal.Owner != caller || goal.Tenant != needs.Use.Tenant {
		return RegistryImagePermit{}, access.ErrDenied
	}
	var service deployment.ComposeService
	if json.Unmarshal(goal.Config, &service) != nil {
		return RegistryImagePermit{}, access.ErrDenied
	}
	original, imageErr := access.PinImage(service.Image)
	requested, requestErr := access.PinImage(q.Image)
	if imageErr != nil && requestErr == nil {
		// A tag: the deploy's resolution (or the server's own copy when the
		// deploy could not resolve it) names the digest.
		apps, err := p.readOnlyApps(s)
		if err != nil {
			return RegistryImagePermit{}, err
		}
		if e, ok := apps.Execution(goal.Tenant, goal.App); ok && e.TagAllows(service.Image, requested.Reference) {
			original, imageErr = requested, nil
		}
	}
	if imageErr != nil || requestErr != nil || original != requested {
		return RegistryImagePermit{}, access.ErrDenied
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return RegistryImagePermit{}, err
	}
	image, err := catalog.CheckImage(needs.Use.User, needs.Use.Tenant, needs.Use.Node, q.Image)
	if err != nil {
		return RegistryImagePermit{}, err
	}
	out := RegistryImagePermit{Subject: registry.TaskSubject{Task: q.Task, Binding: q.Digest, Node: caller, Image: image.Reference}, Index: s.Index(), Epoch: s.ModuleEpoch()}
	book, err := p.Registries(s)
	if err != nil {
		return RegistryImagePermit{}, err
	}

	var selected *RegistryEntry
	retained := false
	for _, entry := range book.Entries() {
		activeMatch := entry.Active != nil && entry.Active.Spec.Authority == image.Registry
		if entry.Spec.Authority != image.Registry && !activeMatch {
			continue
		}
		retained = true
		if entry.Deleted && entry.Active == nil {
			continue
		}
		// A definition can be replaced while its old run is still joining. Both
		// authorities remain managed until the original run is really closed.
		if selected != nil {
			return RegistryImagePermit{}, access.ErrDenied
		}
		copy := entry
		selected = &copy
	}
	if selected == nil {
		if retained {
			return RegistryImagePermit{}, access.ErrDenied
		}
		external, err := p.ExternalRegistryForImage(s, needs.Use.Tenant, image)
		if err != nil {
			return RegistryImagePermit{}, err
		}
		out.External = external
		if external != nil && len(external.References()) > 0 {
			var expected []deployment.Source
			for _, ref := range external.References() {
				expected = append(expected, deployment.Source{Realm: ref.Realm, Object: ref.ID})
			}
			if !slices.Equal(needs.RegistrySources, expected) {
				return RegistryImagePermit{}, access.ErrDenied
			}
			vault, err := p.Vault(s)
			if err != nil {
				return RegistryImagePermit{}, err
			}
			reads, err := p.bindingGrantReads(s, vault, catalog, binding.RegistryGrants(), q.At)
			if err != nil {
				return RegistryImagePermit{}, err
			}
			fingerprint, err := json.Marshal(struct {
				Subject registry.TaskSubject
				Source  imagesource.Source
				Reads   []AppInputRead
			}{out.Subject, *external, reads})
			if err != nil {
				return RegistryImagePermit{}, err
			}
			inputs := RegistryImageInputs{ReadSet: sha256.Sum256(fingerprint)}
			inputs.Entries, err = registrySourceReadInputs(*external, reads)
			if err != nil {
				return RegistryImagePermit{}, err
			}
			out.ExternalInputs = &inputs
		}
		return out, nil
	}
	entry := *selected
	if entry.Spec.Authority != image.Registry || entry.Spec.Tenant != needs.Use.Tenant || entry.Deleted || !entry.Spec.Enabled || entry.Active == nil || entry.Active.Draining || entry.Active.Ready == nil || entry.Active.Spec != entry.Spec || entry.Active.SpecRevision != entry.Revision {
		return RegistryImagePermit{}, access.ErrDenied
	}
	work, err := p.RegistryWork(s, entry.Active.Owner, RegistryWorkRequest{RegistrySelection: RegistrySelection{Tenant: entry.Spec.Tenant, ID: entry.Spec.ID}, At: q.At})
	if err != nil || !work.MayStart {
		return RegistryImagePermit{}, access.ErrDenied
	}
	spec := entry.Spec
	out.Registry = &spec

	return out, nil
}

// Shared exact leaf/key selection for Task authentication and source service
// authentication. Neither caller may turn a group into arbitrary value reads.
func registrySourceReadInputs(spec imagesource.Source, reads []AppInputRead) ([]RegistryImageInput, error) {
	var entries []RegistryImageInput
	for _, ref := range spec.References() {
		found := false
		for _, read := range reads {
			if read.Realm != ref.Realm {
				continue
			}
			for _, leaf := range read.Plan.Leaves {
				if leaf.Secret != ref.ID {
					continue
				}
				if c := spec.Credential; c != nil && c.Realm == ref.Realm && c.ID == ref.ID && (!slices.Contains(leaf.Reference.Keys, c.UsernameKey) || !slices.Contains(leaf.Reference.Keys, c.PasswordKey)) {
					return nil, access.ErrDenied
				}
				if c := spec.CA; c != nil && c.Realm == ref.Realm && c.ID == ref.ID && !slices.Contains(leaf.Reference.Keys, c.Key) {
					return nil, access.ErrDenied
				}
				for _, profile := range read.Profiles {
					if !found && profile.ID == leaf.Reference.Profile && profile.Enabled && profile.Values {
						entries = append(entries, RegistryImageInput{ref.Realm, leaf, profile})
						found = true
					}
				}
			}
		}
		if !found {
			return nil, access.ErrDenied
		}
	}
	return entries, nil
}
