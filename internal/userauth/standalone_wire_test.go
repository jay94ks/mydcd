// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/servicecall"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestRQ9SelectorsPreserveOtherAuthenticatedFeatureBoundaries(t *testing.T) {
	call := servicecall.Request{App: "shop", Service: "api", Port: 8080, Path: "/", Method: "POST"}
	input := ServiceCallInput{Digest: sha256.Sum256(nil)}
	probe := deployment.GitProbeRequest{App: "shop", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}
	queries := []Request{
		{Method: "standalone-list", Tenant: "tenant", Standalone: &control.StandaloneQuery{}, After: "previous"},
		{Method: "standalone-get", Tenant: "tenant", Standalone: &control.StandaloneQuery{Name: "debug"}},
	}
	foreign := []func(*Request){
		func(r *Request) { r.Params = json.RawMessage("{}") },
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
		})
	}
	for _, method := range []string{"whoami", "tenant-storage", "ingresses", "service-call", "cd-probe"} {
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
		{Method: "tenant-storage", Tenant: "tenant"},
		{Method: "cd-probe", Tenant: "tenant", CDProbe: &deployment.GitProbeRequest{App: "shop", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}},
	} {
		// No transport is installed. Every supported method must reach the same
		// transport admission boundary instead of the unsupported-query branch.
		if _, err := client.query(context.Background(), client.Peers[0], session, q); !errors.Is(err, sfcp.ErrAdmission) {
			t.Fatal("SDK query not connected", q.Method, err)
		}
	}
}
