// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registryclient"
)

func TestBuildTokenRequiresSignedBeginReservationAndCurrentOriginalScope(t *testing.T) {
	f, plan, inputs, sources := buildBoundSourceFixture(t)
	query := buildBaseQuery(plan, inputs[0].Source.Reference)
	read, err := f.p.ImageBuildBaseRead(f.s, plan.Spec.Scope.Root.Key, query)
	if err != nil {
		t.Fatal(err)
	}
	challenge := registryclient.PullTokenChallenge{Host: "ghcr.io", Realm: "https://ghcr.io/token", Service: "ghcr.io", Scopes: []string{"repository:team/base:pull"}}
	if _, err := f.p.CurrentImageBuildBaseToken(f.s, ImageBuildBaseTokenRequest{Read: read, Challenge: challenge}, 3); err == nil {
		t.Fatal("queued job minted a token before reserving the source")
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin", Inputs: inputs, Sources: sources}, state.Applied)
	read, err = f.p.ImageBuildBaseRead(f.s, plan.Spec.Scope.Root.Key, query)
	if err != nil {
		t.Fatal(err)
	}
	request := ImageBuildBaseTokenRequest{Read: read, Challenge: challenge}
	if _, err := f.p.CurrentImageBuildBaseToken(f.s, request, 3); err != nil {
		t.Fatal("original source-bound token scope denied", err)
	}
	for _, edit := range []func(*ImageBuildBaseTokenRequest){
		func(q *ImageBuildBaseTokenRequest) { q.Challenge.Host = "foreign.example" },
		func(q *ImageBuildBaseTokenRequest) { q.Challenge.Scopes = []string{"repository:team/other:pull"} },
		func(q *ImageBuildBaseTokenRequest) { q.Challenge.Scopes = []string{"repository:team/base:push"} },
		func(q *ImageBuildBaseTokenRequest) { q.Read.Builder[0] ^= 1 },
		func(q *ImageBuildBaseTokenRequest) { q.Read.Target.Owner[0] ^= 1 },
		func(q *ImageBuildBaseTokenRequest) { q.Read.Target.ExternalReadSet[0] ^= 1 },
		func(q *ImageBuildBaseTokenRequest) { q.Read.Query.Source.Stage++ },
	} {
		bad := request
		edit(&bad)
		if _, err := f.p.CurrentImageBuildBaseToken(f.s, bad, 3); err == nil {
			t.Fatal("token scope broadened from original begin")
		}
	}
	f.apply("manager", "cancel-image-build", 2, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	if _, err := f.p.CurrentImageBuildBaseToken(f.s, request, 3); err == nil {
		t.Fatal("cancelled job acquired fresh token")
	}
	if held, err := f.p.ExternalRegistryImageBuildsPending(f.s, *sources[0].External); err != nil || !held {
		t.Fatal("token revocation discarded the original in-flight reference", err)
	}
}
