// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"slices"
	"testing"
)

func TestAutomationPathRoutesListsOnlyTheChallengePathAndBelow(t *testing.T) {
	d := IngressDeclaration{Routes: []IngressRouteDeclaration{
		{ID: "root", Host: "shop.example", Prefix: "/", Service: "web"},
		{ID: "well-known", Host: "shop.example", Prefix: "/.well-known", Service: "web"},
		{ID: "acme", Host: "shop.example", Prefix: "/.well-known/acme-challenge", Service: "web"},
		{ID: "token", Host: "api.shop.example", Prefix: "/.well-known/acme-challenge/x", Service: "web"},
		{ID: "lookalike", Host: "shop.example", Prefix: "/.well-known/acme-challenge-old", Service: "web"},
	}}
	got := AutomationPathRoutes(d)
	want := []string{"acme shop.example/.well-known/acme-challenge", "token api.shop.example/.well-known/acme-challenge/x"}
	if !slices.Equal(got, want) {
		t.Fatal(got)
	}
	if AutomationPathRoutes(IngressDeclaration{Host: "shop.example"}) != nil {
		t.Fatal("single-host default route listed")
	}
}
