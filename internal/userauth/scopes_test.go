// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"reflect"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

func TestFullUserScopesAreOwnedAuthenticationCeilings(t *testing.T) {
	expected := []access.Scope{{Tenant: "*", Actions: []access.Action{
		access.Read, access.CallService, access.ManageNetwork, access.Deploy, access.ManageSecrets,
		access.ManageVolumes, access.ManageRoutes, access.ManageServices,
		access.ManageCD, access.ManageRegistry, access.ManageTrust,
		access.ManageMembers, access.ManageCluster, access.ManageCredentials, access.NodeShell,
	}}}
	first, second := fullUserScopes(), fullUserScopes()
	if !reflect.DeepEqual(first, expected) || !access.ValidateScopes(first) {
		t.Fatal("default authentication ceiling changed", first)
	}
	first[0].Tenant = "one"
	first[0].Actions[0] = access.Deploy
	first[0].Actions = append(first[0].Actions, access.Read)
	if !reflect.DeepEqual(second, expected) || !reflect.DeepEqual(fullUserScopes(), expected) {
		t.Fatal("another login inherited caller mutations")
	}
}
