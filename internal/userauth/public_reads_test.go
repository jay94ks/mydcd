// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/servicecall"
	"testing"
)

func TestPublicReadWireSelectorsAreAnExactMethodUnion(t *testing.T) {
	methods := map[string]control.PublicReadQuery{
		"network-users": {Name: "services"}, "network-closure": {Name: "member"}, "volume-users": {Name: "data", App: "app"}, "volume-backup-limits": {Node: "node-a"}, "lifecycle-uses": {Name: "ready"}, "route-endpoints": {}, "vault-approvals": {App: "app"}, "vault-usages": {Name: "group"}, "volume-retained-sources": {Name: "data"}, "image-trust": {}, "volume-file-grants": {Name: "data"},
	}
	for method, query := range methods {
		t.Run(method, func(t *testing.T) {
			r := Request{Schema: 1, Method: method, Nonce: [32]byte{1}, Tenant: "tenant", PublicRead: &query}
			if !r.validMethodFields() || !r.validQuerySelectors() {
				t.Fatal("valid finite query rejected")
			}
			for _, mutate := range []func(*Request){
				func(r *Request) { r.Node = "unrelated" },
				func(r *Request) { r.App = "foreign" },
				func(r *Request) { r.Secret = []byte("never") },
				func(r *Request) { r.PublicRead = nil },
				func(r *Request) { r.Certificate = &control.CertificateQuery{} },
				func(r *Request) { r.Ingress = &control.IngressQuery{Tenant: "tenant", Part: "mappings"} },
				func(r *Request) { r.Standalone = &control.StandaloneQuery{Name: "debug"} },
				func(r *Request) { r.VolumeFile = &control.VolumeFileQuery{ID: "original"} },
				func(r *Request) {
					r.ServiceCall = &servicecall.Request{App: "shop", Service: "api", Port: 8080, Path: "/", Method: "POST"}
					r.ServiceInput = &ServiceCallInput{Digest: sha256.Sum256(nil)}
				},
				func(r *Request) {
					r.CDProbe = &deployment.GitProbeRequest{App: "shop", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}
				},
			} {
				bad := r
				mutate(&bad)
				if bad.validMethodFields() || bad.validQuerySelectors() {
					t.Fatal("foreign selector crossed read boundary")
				}
			}
			bad := r
			bad.Method = "whoami"
			if bad.validMethodFields() {
				t.Fatal("read selector reused by a different method")
			}
		})
	}
}
func TestPublicReadReplyRejectsWrongMethodUnionAndForeignRealm(t *testing.T) {
	query := control.PublicReadQuery{Name: "services"}
	page := control.PublicReadPage{Schema: 1, Method: "network-users", Tenant: "tenant", Rows: []control.PublicReadRow{{Key: "task", User: &control.PublicResourceUser{Tenant: "tenant", Kind: "app-service", App: "app", Service: "web"}}}, Total: 1}
	reply := Reply{Schema: 1, Code: "ok", PublicRead: &page}
	if err := verifyPublicReadReply([32]byte{1}, "network-users", "tenant", query, reply); err != nil {
		t.Fatal("valid projected row", err)
	}
	page.Rows[0].User.Tenant = "foreign"
	if err := verifyPublicReadReply([32]byte{1}, "network-users", "tenant", query, reply); err == nil {
		t.Fatal("foreign realm accepted")
	}
	page.Rows[0] = control.PublicReadRow{Key: "wrong", BackupLimit: &control.PublicBackupLimit{Tenant: "tenant"}}
	if err := verifyPublicReadReply([32]byte{1}, "network-users", "tenant", query, reply); err == nil {
		t.Fatal("wrong union accepted")
	}
	page.Rows = nil
	page.Total = 0
	page.Next = "not-a-row"
	if err := verifyPublicReadReply([32]byte{1}, "network-users", "tenant", query, reply); err == nil {
		t.Fatal("empty page with continuation accepted")
	}
}

func TestNetworkClosureWireNeverTurnsMissingProofIntoClosed(t *testing.T) {
	query := control.PublicReadQuery{Name: "member"}
	page := control.PublicReadPage{Schema: 1, Method: "network-closure", Tenant: "tenant", Rows: []control.PublicReadRow{{Key: "member", Closure: &control.NetworkClosureStatus{State: "closed"}}}, Total: 1}
	reply := Reply{Schema: 1, Code: "ok", PublicRead: &page}
	if err := verifyPublicReadReply([32]byte{1}, "network-closure", "tenant", query, reply); err == nil {
		t.Fatal("unsigned terminal status accepted")
	}
	page.Rows[0].Closure.State = "unreachable"
	if err := verifyPublicReadReply([32]byte{1}, "network-closure", "tenant", query, reply); err != nil {
		t.Fatal("explicit unreachable state refused", err)
	}
	page.Rows[0].Key = "other-member"
	if err := verifyPublicReadReply([32]byte{1}, "network-closure", "tenant", query, reply); err == nil {
		t.Fatal("foreign member row accepted")
	}
}

func TestFileGrantReplyUsesOriginalFolderGrantScope(t *testing.T) {
	grant := control.PublicFileGrant{Tenant: "tenant", App: "app", Volume: "data", Prefix: "backups/", User: "delegate", Revision: 7, AccountEnabled: true, VolumePresent: true, Operations: []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}}
	query := control.PublicReadQuery{Name: "data", App: "app"}
	makeReply := func(g control.PublicFileGrant) Reply {
		return Reply{Schema: 1, Code: "ok", PublicRead: &control.PublicReadPage{Schema: 1, Method: "volume-file-grants", Tenant: "tenant", Total: 1, Rows: []control.PublicReadRow{{Key: g.User + "/" + g.App + "/" + g.Volume + "/" + g.Prefix, FileGrant: &g}}}}
	}
	if err := verifyPublicReadReply([32]byte{1}, "volume-file-grants", "tenant", query, makeReply(grant)); err != nil {
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
			if err := verifyPublicReadReply([32]byte{1}, "volume-file-grants", "tenant", query, makeReply(bad)); err == nil {
				t.Fatal("invalid folder grant accepted")
			}
		})
	}
	reply := makeReply(grant)
	reply.PublicRead.Rows[0].Key = "different-key"
	if err := verifyPublicReadReply([32]byte{1}, "volume-file-grants", "tenant", query, reply); err == nil {
		t.Fatal("wrong row source key accepted")
	}
	// Empty app/name are read selectors. A tenant-managed Volume still has an
	// exact empty App in its grant and never represents all app Volumes.
	grant.App = ""
	if err := verifyPublicReadReply([32]byte{1}, "volume-file-grants", "tenant", control.PublicReadQuery{}, makeReply(grant)); err != nil {
		t.Fatal("tenant-managed Volume read selector rejected", err)
	}
}

func TestRQ10SDKQueryMethodsKeepEarlierTypedConsumers(t *testing.T) {
	_, client, session, _ := journalFixture(t)
	methods := map[string]control.PublicReadQuery{
		"network-users": {Name: "services"}, "network-closure": {Name: "member"}, "volume-users": {Name: "data", App: "app"}, "volume-backup-limits": {Node: "node-a"}, "route-endpoints": {}, "lifecycle-uses": {Name: "ready"}, "vault-approvals": {}, "vault-usages": {Name: "group"}, "volume-retained-sources": {Name: "data"}, "image-trust": {}, "volume-file-grants": {},
	}
	requests := []Request{
		{Method: "tenant-storage", Tenant: "tenant"},
		{Method: "certificates", Certificate: &control.CertificateQuery{}},
		{Method: "ingresses", Tenant: "tenant", Ingress: &control.IngressQuery{Tenant: "tenant", Part: "mappings"}},
		{Method: "cd-probe", Tenant: "tenant", CDProbe: &deployment.GitProbeRequest{App: "shop", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}},
		{Method: "standalone-list", Tenant: "tenant", Standalone: &control.StandaloneQuery{}},
		{Method: "standalone-get", Tenant: "tenant", Standalone: &control.StandaloneQuery{Name: "debug"}},
		{Method: "volume-file-plan", Tenant: "tenant", VolumeFile: &control.VolumeFileQuery{Volume: "backup", Path: "exports/", Method: "volume-file-list"}},
		{Method: "volume-file-status", Tenant: "tenant", VolumeFile: &control.VolumeFileQuery{ID: "original"}},
	}
	for method, query := range methods {
		q := query
		requests = append(requests, Request{Method: method, Tenant: "tenant", PublicRead: &q})
	}
	for _, r := range requests {
		// Missing transport is intentional: supported SDK methods must reach the
		// normal transport admission boundary rather than the unsupported branch.
		if _, err := client.query(context.Background(), client.Peers[0], session, r); !errors.Is(err, mydcp.ErrAdmission) {
			t.Fatal("typed query lost during integration", r.Method, err)
		}
	}
}

func TestPublicReadSelectorCannotAccompanyEarlierMethods(t *testing.T) {
	query := control.PublicReadQuery{Name: "data"}
	for _, method := range []string{"whoami", "tenant-storage", "certificates", "ingresses", "cd-probe", "service-call", "standalone-list", "standalone-get", "volume-file-plan", "volume-file-status", "build-zip-transfer", "image-builds"} {
		r := Request{Method: method, Tenant: "tenant", PublicRead: &query}
		if r.validMethodFields() || r.validQuerySelectors() {
			t.Fatal("public read selector crossed method", method)
		}
	}
}
