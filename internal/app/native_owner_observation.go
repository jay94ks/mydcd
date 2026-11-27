// SPDX-License-Identifier: Apache-2.0

package app

import (
	"strings"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Observation selects an exact retained source in the supplied committed view.
// It grants no effect and never interprets an old owner as current TLS identity.
func (r *Runtime) managedObservationOwner(v cluster.View, projection control.ResourceProjection, key string) (*Runtime, bool) {
	var original [32]byte
	if source, found := projection.ManagedSources[key]; found {
		original = source.Network.Owner
	} else if goal, found := projection.Goals[key]; found {
		original = goal.Goal.Owner
	} else {
		return nil, false
	}
	members, err := r.controlPolicy.Members(v.State)
	if err != nil || !members.OwnsResource(r.commandIdentity().Public, original) {
		return nil, false
	}
	return r.nativeOwner(original)
}

// A management DNS key is a policy source, not a projected Bridge or Goal. Its
// existing published rows identify the original local DNS runtime; several
// pools may share that one runtime, but distinct local owners are ambiguous.
func (r *Runtime) managedDNSObservationOwner(v cluster.View, key string) (*Runtime, error) {
	object := v.State.Object(key)
	members, err := r.controlPolicy.Members(v.State)
	if err != nil {
		return nil, err
	}
	apps, err := r.controlPolicy.ReadApps(v.State)
	if err != nil {
		return nil, err
	}
	authority, _, known := apps.NetworkDNS([32]byte{})
	if !known || authority.Cluster() != r.controlPolicy.Cluster {
		return nil, deployment.ErrInputs
	}
	seen := map[[32]byte]bool{}
	var candidates []managedDNSObservationCandidate
	for _, reference := range authority.ReferenceConsumers() {
		original := reference.Local.Owner
		if seen[original] {
			continue
		}
		seen[original] = true
		_, rows, known := apps.NetworkDNS(original)
		if !known {
			return nil, deployment.ErrInputs
		}
		for _, row := range rows {
			if row.Source.Key != key {
				continue
			}
			ref, found := authority.ReferenceConsumer(row.Reference)
			if !found || row.Managed == nil || ref.Local.Owner != original || ref.Local.Node != row.Managed.Node {
				return nil, deployment.ErrInputs
			}
			candidates = append(candidates, managedDNSObservationCandidate{owner: original, row: row})
		}
	}
	original, err := managedDNSObservationIdentity(key, object, members, r.commandIdentity().Public, candidates)
	if err != nil {
		return nil, err
	}
	owner, found := r.nativeOwner(original)
	if !found {
		return nil, deployment.ErrInputs
	}
	return owner, nil
}

type managedDNSObservationCandidate struct {
	owner [32]byte
	row   control.AppDNSOwner
}

// The candidate rows and owners come only from the same validated Apps /
// Authority view above. This read-only selection grants no native effect or
// permission; observeAppDNS still checks its current material and Inspect.
func managedDNSObservationIdentity(key string, object state.Object, members membership.Directory, current [32]byte, candidates []managedDNSObservationCandidate) ([32]byte, error) {
	if !strings.HasPrefix(key, services.ManagedDNSPrefix) || !object.Present || object.Generation == 0 || object.Revision < object.Generation {
		return [32]byte{}, deployment.ErrInputs
	}
	if !members.MemberKey(current) {
		return [32]byte{}, sfcp.ErrAdmission
	}
	var selected [32]byte
	for _, candidate := range candidates {
		row := candidate.row
		if row.Source.Key != key || !members.OwnsResource(current, candidate.owner) {
			continue
		}
		if row.Managed == nil || !members.ResourceKeyForNode(row.Managed.Node, candidate.owner) {
			return [32]byte{}, sfcp.ErrAdmission
		}
		if row.Source.Generation != object.Generation || row.Source.Revision != object.Revision {
			return [32]byte{}, deployment.ErrInputs
		}
		if selected != ([32]byte{}) && selected != candidate.owner {
			return [32]byte{}, deployment.ErrInputs
		}
		selected = candidate.owner
	}
	if selected == ([32]byte{}) {
		return selected, deployment.ErrInputs
	}
	return selected, nil
}
