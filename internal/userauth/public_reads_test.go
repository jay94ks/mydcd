// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"strings"
	"testing"
)

// Every PublicRead method takes PublicReadParams, decoded strictly, with
// only the selectors control.PublicReadQuery.Valid allows for it.
func TestPublicReadParamsAreExactPerMethod(t *testing.T) {
	methods := map[string]control.PublicReadQuery{
		"network-users": {Name: "services"}, "network-closure": {Name: "member"}, "volume-users": {Name: "data", App: "app"}, "volume-backup-limits": {Node: "node-a"}, "lifecycle-uses": {Name: "ready"}, "route-endpoints": {}, "bridge-endpoints": {}, "vault-approvals": {App: "app"}, "vault-usages": {Name: "group"}, "volume-retained-sources": {Name: "data"}, "image-trust": {}, "volume-file-grants": {Name: "data"},
	}
	if len(methods) != len(control.PublicReadMethods()) || len(publicReadMethods) != len(methods) {
		t.Fatal("a PublicRead method has no typed method or no case here")
	}
	for method, query := range methods {
		t.Run(method, func(t *testing.T) {
			p := PublicReadParams{Tenant: "tenant", Query: query}
			raw, _ := json.Marshal(p)
			if _, ok := methodRules[method].decode(raw); !ok || !p.valid(method) {
				t.Fatal("valid finite query rejected")
			}
			if _, ok := methodRules[method].decode(json.RawMessage(`{"Tenant":"tenant","Query":{"Name":"","App":"","Node":""},"Secret":"x"}`)); ok {
				t.Fatal("unknown field decoded")
			}
			for _, mutate := range []func(*PublicReadParams){
				func(p *PublicReadParams) { p.Query.Node = "Bad Node" },
				func(p *PublicReadParams) { p.Tenant = "Bad Tenant" },
				func(p *PublicReadParams) { p.After = strings.Repeat("a", 513) },
			} {
				bad := p
				mutate(&bad)
				if bad.valid(method) {
					t.Fatal("foreign selector crossed read boundary", bad)
				}
			}
			if method == "network-closure" {
				if paged := (PublicReadParams{Tenant: "tenant", Query: query, After: "x"}); paged.valid(method) {
					t.Fatal("network-closure took a cursor")
				}
			}
		})
	}
	if (PublicReadParams{Tenant: "tenant"}).valid("whoami") {
		t.Fatal("public read params accepted for another method")
	}
}
func TestPublicReadReplyRejectsWrongMethodUnionAndForeignRealm(t *testing.T) {
	query := control.PublicReadQuery{Name: "services"}
	page := control.PublicReadPage{Schema: 1, Method: "network-users", Tenant: "tenant", Rows: []control.PublicReadRow{{Key: "task", User: &control.PublicResourceUser{Tenant: "tenant", Kind: "app-service", App: "app", Service: "web"}}}, Total: 1}
	if err := verifyPublicReadPage([32]byte{1}, "network-users", "tenant", query, page); err != nil {
		t.Fatal("valid projected row", err)
	}
	page.Rows[0].User.Tenant = "foreign"
	if err := verifyPublicReadPage([32]byte{1}, "network-users", "tenant", query, page); err == nil {
		t.Fatal("foreign realm accepted")
	}
	page.Rows[0] = control.PublicReadRow{Key: "wrong", BackupLimit: &control.PublicBackupLimit{Tenant: "tenant"}}
	if err := verifyPublicReadPage([32]byte{1}, "network-users", "tenant", query, page); err == nil {
		t.Fatal("wrong union accepted")
	}
	page.Rows = nil
	page.Total = 0
	page.Next = "not-a-row"
	if err := verifyPublicReadPage([32]byte{1}, "network-users", "tenant", query, page); err == nil {
		t.Fatal("empty page with continuation accepted")
	}
}

func TestNetworkClosureWireNeverTurnsMissingProofIntoClosed(t *testing.T) {
	query := control.PublicReadQuery{Name: "member"}
	page := control.PublicReadPage{Schema: 1, Method: "network-closure", Tenant: "tenant", Rows: []control.PublicReadRow{{Key: "member", Closure: &control.NetworkClosureStatus{State: "closed"}}}, Total: 1}
	if err := verifyPublicReadPage([32]byte{1}, "network-closure", "tenant", query, page); err == nil {
		t.Fatal("unsigned terminal status accepted")
	}
	page.Rows[0].Closure.State = "unreachable"
	if err := verifyPublicReadPage([32]byte{1}, "network-closure", "tenant", query, page); err != nil {
		t.Fatal("explicit unreachable state refused", err)
	}
	page.Rows[0].Key = "other-member"
	if err := verifyPublicReadPage([32]byte{1}, "network-closure", "tenant", query, page); err == nil {
		t.Fatal("foreign member row accepted")
	}
}

func TestFileGrantReplyUsesOriginalFolderGrantScope(t *testing.T) {
	grant := control.PublicFileGrant{Tenant: "tenant", App: "app", Volume: "data", Prefix: "backups/", User: "delegate", Revision: 7, AccountEnabled: true, VolumePresent: true, Operations: []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}}
	query := control.PublicReadQuery{Name: "data", App: "app"}
	makeReply := func(g control.PublicFileGrant) control.PublicReadPage {
		return control.PublicReadPage{Schema: 1, Method: "volume-file-grants", Tenant: "tenant", Total: 1, Rows: []control.PublicReadRow{{Key: g.User + "/" + g.App + "/" + g.Volume + "/" + g.Prefix, FileGrant: &g}}}
	}
	if err := verifyPublicReadPage([32]byte{1}, "volume-file-grants", "tenant", query, makeReply(grant)); err != nil {
		t.Fatal("valid original folder grant rejected", err)
	}
	for name, mutate := range map[string]func(*control.PublicFileGrant){
		"foreign tenant":          func(g *control.PublicFileGrant) { g.Tenant = "foreign" },
		"foreign app":             func(g *control.PublicFileGrant) { g.App = "foreign" },
		"foreign Volume":          func(g *control.PublicFileGrant) { g.Volume = "foreign" },
		"wildcard user":           func(g *control.PublicFileGrant) { g.User = "*" },
		"wildcard Volume":         func(g *control.PublicFileGrant) { g.Volume = "*" },
		"traversal prefix":        func(g *control.PublicFileGrant) { g.Prefix = "../backups/" },
		"file prefix":             func(g *control.PublicFileGrant) { g.Prefix = "backups" },
		"missing source revision": func(g *control.PublicFileGrant) { g.Revision = 0 },
		"management operation":    func(g *control.PublicFileGrant) { g.Operations = []string{"create-volume"} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := grant
			mutate(&bad)
			if err := verifyPublicReadPage([32]byte{1}, "volume-file-grants", "tenant", query, makeReply(bad)); err == nil {
				t.Fatal("invalid folder grant accepted")
			}
		})
	}
	reply := makeReply(grant)
	reply.Rows[0].Key = "different-key"
	if err := verifyPublicReadPage([32]byte{1}, "volume-file-grants", "tenant", query, reply); err == nil {
		t.Fatal("wrong row source key accepted")
	}
	// Empty app/name are read selectors. A tenant-managed Volume still has an
	// exact empty App in its grant and never represents all app Volumes.
	grant.App = ""
	if err := verifyPublicReadPage([32]byte{1}, "volume-file-grants", "tenant", control.PublicReadQuery{}, makeReply(grant)); err != nil {
		t.Fatal("tenant-managed Volume read selector rejected", err)
	}
}

func TestRQ10SDKQueryMethodsKeepEarlierTypedConsumers(t *testing.T) {
	_, client, session, _ := journalFixture(t)
	requests := []Request{
		{Method: "tenant-storage", Tenant: "tenant"},
		{Method: "cd-probe", Tenant: "tenant", CDProbe: &deployment.GitProbeRequest{App: "shop", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}},
		{Method: "standalone-list", Tenant: "tenant", Standalone: &control.StandaloneQuery{}},
		{Method: "standalone-get", Tenant: "tenant", Standalone: &control.StandaloneQuery{Name: "debug"}},
	}
	for _, r := range requests {
		// Missing transport is intentional: supported SDK methods must reach the
		// normal transport admission boundary rather than the unsupported branch.
		if _, err := client.query(context.Background(), client.Peers[0], session, r); !errors.Is(err, sfcp.ErrAdmission) {
			t.Fatal("typed query lost during integration", r.Method, err)
		}
	}
}
