// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registryclient"
)

func (p Policy) CurrentImageBuildRegistryTrust(s state.State, permit ImageBuildRegistryPermit, at int64) (ImageBuildRegistryPermit, error) {
	if permit.Index == 0 || permit.Epoch == 0 || permit.Run.Ready == nil || permit.Run.Ready.Certificate == ([32]byte{}) {
		return ImageBuildRegistryPermit{}, access.ErrDenied
	}
	action := "push"
	if permit.Subject.Image != "" {
		action = "pull"
	}
	q := ImageBuildRegistryRequest{Tenant: permit.Subject.Tenant, Job: permit.Subject.Job, Snapshot: permit.Subject.Snapshot, Action: action, Image: permit.Subject.Image, At: at}
	current, err := p.ImageBuildRegistryPermit(s, permit.Subject.Node, q)
	if err != nil || current.Epoch != permit.Epoch || current.Index < permit.Index || current.Subject != permit.Subject || current.Repository != permit.Repository || !sameMaintenanceRun(current.Run, permit.Run) || current.Run.Ready == nil || current.Run.Ready.Certificate != permit.Run.Ready.Certificate {
		return ImageBuildRegistryPermit{}, access.ErrDenied
	}
	return current, nil
}

func (p Policy) ValidateImageBuildRegistryTrust(s state.State, permit ImageBuildRegistryPermit, trust registryclient.RegistryTrust, at int64) error {
	current, err := p.CurrentImageBuildRegistryTrust(s, permit, at)
	if err != nil || !trust.Valid() || trust.Authority != current.Run.Spec.Authority || trust.Fingerprint != current.Run.Ready.Certificate {
		return access.ErrDenied
	}
	return nil
}
