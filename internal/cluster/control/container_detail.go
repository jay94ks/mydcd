// SPDX-License-Identifier: Apache-2.0

package control

import (
	"maps"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
)

func (p Policy) ContainerDetailDeclaration(s state.State, read ContainerRead, at int64) (containerops.DetailDeclaration, error) {
	if read.Query.Kind != "inspect" {
		return containerops.DetailDeclaration{}, access.ErrInvalid
	}
	if _, err := p.ContainerReadPermit(s, read.Target.Owner, read, at); err != nil {
		return containerops.DetailDeclaration{}, err
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return containerops.DetailDeclaration{}, err
	}
	ref := deployment.ObjectRef{Key: read.Target.Instance, Generation: read.Target.Generation, Revision: read.Target.Revision}
	claim, ok := apps.Claim(read.Target.Tenant, read.Target.App, ref)
	if !ok || claim.Removed {
		return containerops.DetailDeclaration{}, access.ErrDenied
	}
	var goal deployment.GoalCommand
	var service deployment.ComposeService
	if canonical([]byte(claim.Command.Value), &goal) != nil || goal.Kind != "task" || canonical(goal.Config, &service) != nil {
		return containerops.DetailDeclaration{}, ErrCatalog
	}
	decl := containerops.DetailDeclaration{Environment: maps.Clone(service.Environment), NetworkAliases: map[string][]string{}}
	for name, network := range service.Networks {
		decl.NetworkAliases[name] = slices.Clone(network.Aliases)
	}
	if execution, exists := apps.Execution(read.Target.Tenant, read.Target.App); exists {
		decl.Ingress = execution.Blueprint().ServiceIngress(read.Target.Service)
	}
	return decl, nil
}
