// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registryclient"
)

func (p Policy) ValidateImageBuildBaseTrust(s state.State, original ImageBuildBaseRead, trust registryclient.RegistryTrust, at int64) error {
	read, err := p.CurrentImageBuildBaseMaterial(s, original, at)
	if err != nil || read.Target.Managed != nil || !trust.Valid() || trust.Fingerprint != ([32]byte{}) {
		return access.ErrDenied
	}
	_, authority, _, err := registryclient.Normalize(read.Target.Normalized)
	if err != nil || authority != trust.Authority {
		return access.ErrDenied
	}
	expectsCA := false
	if read.Target.External != nil {
		entries, err := p.ExternalRegistries(s)
		if err != nil {
			return err
		}
		found := false
		for _, entry := range entries {
			if entry.Spec.Tenant == read.Query.Tenant && entry.Spec.ID == read.Target.External.ID && entry.Reader != nil && entry.Reader.Generation == read.Target.External.Generation {
				found, expectsCA = true, entry.Spec.CA != nil
			}
		}
		if !found {
			return access.ErrDenied
		}
	}
	if expectsCA != (len(trust.Certificates) > 0) {
		return access.ErrDenied
	}
	return nil
}
