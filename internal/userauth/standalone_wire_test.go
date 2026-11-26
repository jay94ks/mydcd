// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/servicecall"
)

func TestRQ9SelectorsPreserveOtherAuthenticatedFeatureBoundaries(t *testing.T) {
	call := servicecall.Request{App: "shop", Service: "api", Port: 8080, Path: "/", Method: "POST"}
	input := ServiceCallInput{Digest: sha256.Sum256(nil)}
	probe := deployment.GitProbeRequest{App: "shop", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}
	ingress := control.IngressQuery{Tenant: "tenant", Part: "mappings"}
	queries := []Request{
		{Method: "standalone-list", Tenant: "tenant", Standalone: &control.StandaloneQuery{}, After: "previous"},
		{Method: "standalone-get", Tenant: "tenant", Standalone: &control.StandaloneQuery{Name: "debug"}},
		{Method: "volume-file-plan", Tenant: "tenant", VolumeFile: &control.VolumeFileQuery{Volume: "backup", Path: "backups/", Method: "volume-file-list"}},
		{Method: "volume-file-status", Tenant: "tenant", VolumeFile: &control.VolumeFileQuery{ID: "original"}},
	}
	foreign := []func(*Request){
		func(r *Request) { r.Certificate = &control.CertificateQuery{} },
		func(r *Request) { r.Ingress = &ingress },
		func(r *Request) { r.ServiceCall = &call; r.ServiceInput = &input },
		func(r *Request) { r.CDProbe = &probe },
		func(r *Request) { r.Node = "node-a" },
		func(r *Request) { r.ImageBuild = &control.ImageBuildQuery{Part: "contexts"} },
	}
	for _, q := range queries {
		t.Run(q.Method, func(t *testing.T) {
			if !q.validMethodFields() || !q.validQuerySelectors() {
				t.Fatal("valid RQ9 request rejected")
			}
			for i, change := range foreign {
				bad := q
				change(&bad)
				if bad.validMethodFields() || bad.validQuerySelectors() {
					t.Fatal("mixed feature selector accepted", i)
				}
			}
			bad := q
			if q.Standalone != nil {
				bad.VolumeFile = &control.VolumeFileQuery{ID: "original"}
			} else {
				bad.Standalone = &control.StandaloneQuery{Name: "debug"}
			}
			if bad.validMethodFields() || bad.validQuerySelectors() {
				t.Fatal("mixed RQ9 owner selector accepted")
			}
		})
	}
	for _, method := range []string{"whoami", "tenant-storage", "certificates", "ingresses", "service-call", "cd-probe"} {
		// A selector cannot turn another method into a standalone/file query.
		for _, q := range queries {
			q.Method = method
			if q.validMethodFields() || q.validQuerySelectors() {
				t.Fatal("RQ9 selector crossed method", method)
			}
		}
	}
}

func TestRQ9QueryMethodsPreservePreviousSDKAdmission(t *testing.T) {
	_, client, session, _ := journalFixture(t)
	for _, q := range []Request{
		{Method: "standalone-list", Tenant: "tenant", Standalone: &control.StandaloneQuery{}},
		{Method: "standalone-get", Tenant: "tenant", Standalone: &control.StandaloneQuery{Name: "debug"}},
		{Method: "volume-file-plan", Tenant: "tenant", VolumeFile: &control.VolumeFileQuery{Volume: "backup", Path: "backups/", Method: "volume-file-list"}},
		{Method: "volume-file-status", Tenant: "tenant", VolumeFile: &control.VolumeFileQuery{ID: "original"}},
		{Method: "tenant-storage", Tenant: "tenant"},
		{Method: "certificates", Certificate: &control.CertificateQuery{}},
		{Method: "ingresses", Tenant: "tenant", Ingress: &control.IngressQuery{Tenant: "tenant", Part: "mappings"}},
		{Method: "cd-probe", Tenant: "tenant", CDProbe: &deployment.GitProbeRequest{App: "shop", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}},
	} {
		// No transport is installed. Every supported method must reach the same
		// transport admission boundary instead of the unsupported-query branch.
		if _, err := client.query(context.Background(), client.Peers[0], session, q); !errors.Is(err, mydcp.ErrAdmission) {
			t.Fatal("SDK query not connected", q.Method, err)
		}
	}
}

func TestVolumeFileQueryGatePreservesManagerWithoutReadScope(t *testing.T) {
	_, client, session, issuer := journalFixture(t)
	users, err := access.New(client.Self.Public)
	if err != nil {
		t.Fatal(err)
	}
	users, err = users.Enroll(client.Self.Public, access.User{ID: session.User, Username: session.User, Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: client.Self.Public, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	users, err = users.CreateTenant(session.User, "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.ManageVolumes}}}
	session.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(session))
	service := Service{Policy: control.Policy{Cluster: client.Cluster, Issuers: [][32]byte{issuer.Public}}}
	binding := userBinding{key: session.Key, challenge: [32]byte{1}}
	for _, request := range []Request{
		{Method: "volume-file-plan", Tenant: "tenant", VolumeFile: &control.VolumeFileQuery{Volume: "backup", Path: "backups/", Method: "volume-file-list"}},
		{Method: "volume-file-status", Tenant: "tenant", VolumeFile: &control.VolumeFileQuery{ID: "original"}},
	} {
		raw, e := requestBody(request)
		if e != nil {
			t.Fatal(e)
		}
		envelope := Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(session, binding.challenge, raw))}
		// This is only the authenticated dispatch gate. The real handler still
		// calls PlanVolumeFile/VolumeFileStatus for exact current folder authority.
		if got := service.execute(users, binding, request, envelope); got.Code != "ok" {
			t.Fatal("generic Read gate replaced Volume authority", request.Method, got.Code)
		}
		revoked := session
		revoked.Signature = append([]byte(nil), session.Signature...)
		revoked.Signature[0] ^= 1
		envelope.Session = &revoked
		if got := service.execute(users, binding, request, envelope); got.Code == "ok" {
			t.Fatal("invalid current session passed dispatch")
		}
	}
}
