// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestAppSourceQueriesRejectCrossMethodSelectorsAndUnpinnedParts(t *testing.T) {
	q := control.AppSourceSelection{App: "app"}
	for _, r := range []Request{{Method: "app-source", Tenant: "tenant", AppSource: &q}, {Method: "app-revisions", Tenant: "tenant", AppSource: &q, After: "cursor"}} {
		if !r.validMethodFields() || !r.validQuerySelectors() {
			t.Fatal("valid app source query rejected", r.Method)
		}
	}
	local := control.AppSourceSelection{App: "app", Section: "local-services", Revision: 2, Part: 1, Digest: [32]byte{1}}
	request := Request{Method: "app-source", Tenant: "tenant", AppSource: &local}
	if !request.validMethodFields() || !request.validQuerySelectors() {
		t.Fatal("pinned local source section rejected")
	}
	for _, r := range []Request{
		{Method: "app-source", AppSource: &q},
		{Method: "app-source", Tenant: "tenant"},
		{Method: "app-source", Tenant: "tenant", AppSource: &q, After: "cursor"},
		{Method: "app-source", Tenant: "tenant", AppSource: &q, Node: "node-a"},
		{Method: "app-source", Tenant: "tenant", AppSource: &q, After: "other"},
		{Method: "whoami", AppSource: &q},
		{Method: "submit", AppSource: &q},
		{Method: "app-source", Tenant: "tenant", AppSource: &control.AppSourceSelection{App: "app", Part: 1}},
		{Method: "app-revisions", Tenant: "tenant", AppSource: &control.AppSourceSelection{App: "app", Revision: 1}},
		{Method: "app-revisions", Tenant: "tenant", AppSource: &local},
		{Method: "app-source", Tenant: "tenant", AppSource: &control.AppSourceSelection{App: "app", Section: "local-services", Part: 1}},
	} {
		if r.validMethodFields() && r.validQuerySelectors() {
			t.Fatal("foreign/unpinned source selector accepted", r.Method)
		}
	}
}
