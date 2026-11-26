// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagesource"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

// Uses real accepted begin/source reservations. Token/registry I/O is not
// simulated as success here; actual SDK exchange is covered separately.
func buildMultiSourceTokenFixture(t *testing.T, separateReaders bool) (*nodeStorageFixture, ImageBuildBaseTokenRequest) {
	t.Helper()
	f, plan, inputs, _ := buildBoundSourceFixture(t)
	other := inputs[0]
	other.Source.Reference = "ghcr.io/team/two:latest"
	other.Source.Stage, other.Source.Line = 1, 2
	other.Image = "ghcr.io/team/two@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	inputs = append(inputs, other)
	if separateReaders {
		spec := imagesource.Source{Tenant: "tenant", ID: "another-source", Authority: "ghcr.io", Repository: "team/two", Enabled: true, Auth: "none"}
		f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{Spec: spec}, state.Applied)
		bind, err := f.p.PlanExternalRegistryBind(f.s, f.sessions["manager"], 2, "tenant", spec.ID, "node-a")
		if err != nil {
			t.Fatal(err)
		}
		f.apply("manager", "bind-external-registry", bind.Expected, bind.Selection, state.Applied)
	}
	sources, err := f.p.ImageBuildBeginSources(f.s, plan.Spec.Scope.Root.Key, ImageBuildJobWorkQuery{Tenant: "tenant", ID: plan.Spec.ID, At: 3}, inputs)
	if err != nil || len(sources) != 2 {
		t.Fatal("missing two original source reservations", err)
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin", Inputs: inputs, Sources: sources}, state.Applied)
	var reads []ImageBuildBaseRead
	for _, input := range inputs {
		q := buildBaseQuery(plan, input.Source.Reference)
		q.Source = input.Source
		read, err := f.p.ImageBuildBaseRead(f.s, plan.Spec.Scope.Root.Key, q)
		if err != nil {
			t.Fatal("selected source not individually authorized", err)
		}
		reads = append(reads, read)
	}
	q := ImageBuildBaseTokenRequest{Read: reads[0], Additional: reads[1:], Challenge: registryclient.PullTokenChallenge{Host: "ghcr.io", Realm: "https://ghcr.io/token", Service: "ghcr.io", Scopes: []string{"repository:team/base:pull", "repository:team/two:pull"}}}
	return f, q
}

func TestBuildTokenCombinedScopesRequireEveryOriginalReaderAndKeepSingleWire(t *testing.T) {
	f, q := buildMultiSourceTokenFixture(t, false)
	if _, err := f.p.CurrentImageBuildBaseToken(f.s, q, 3); err != nil {
		t.Fatal("same original reader did not authorize both repositories", err)
	}
	for _, mutate := range []func(*ImageBuildBaseTokenRequest){
		func(q *ImageBuildBaseTokenRequest) { q.Additional[0].Builder[0] ^= 1 },
		func(q *ImageBuildBaseTokenRequest) { q.Additional[0].Query.Tenant = "foreign" },
		func(q *ImageBuildBaseTokenRequest) { q.Additional[0].Query.Job = "other" },
		func(q *ImageBuildBaseTokenRequest) { q.Additional[0].Query.Snapshot[0] ^= 1 },
		func(q *ImageBuildBaseTokenRequest) { q.Additional[0].Query.Source.Stage++ },
		func(q *ImageBuildBaseTokenRequest) { q.Additional[0].Target.ExternalReadSet[0] ^= 1 },
		func(q *ImageBuildBaseTokenRequest) { q.Additional[0].Target.Owner[0] ^= 1 },
		func(q *ImageBuildBaseTokenRequest) { q.Additional = []ImageBuildBaseRead{q.Read} },
		func(q *ImageBuildBaseTokenRequest) { q.Challenge.Scopes = []string{"repository:team/base:pull"} },
		func(q *ImageBuildBaseTokenRequest) {
			q.Challenge.Scopes = []string{"repository:team/base:pull", "repository:team/two:push"}
		},
		func(q *ImageBuildBaseTokenRequest) {
			q.Challenge.Scopes = []string{"repository:team/base:pull", "repository:team/other:pull"}
		},
	} {
		bad := q
		bad.Additional = append([]ImageBuildBaseRead(nil), q.Additional...)
		mutate(&bad)
		if _, err := f.p.CurrentImageBuildBaseToken(f.s, bad, 3); err == nil {
			t.Fatal("combined token omitted/changed an original scope")
		}
	}
	single := q
	single.Additional = nil
	single.Challenge.Scopes = []string{"repository:team/base:pull"}
	if _, err := f.p.CurrentImageBuildBaseToken(f.s, single, 3); err != nil {
		t.Fatal("single-source compatibility lost", err)
	}
	current, _ := json.Marshal(single)
	legacy, _ := json.Marshal(struct {
		Read      ImageBuildBaseRead
		Challenge registryclient.PullTokenChallenge
	}{single.Read, single.Challenge})
	if !bytes.Equal(current, legacy) {
		t.Fatal("absent Additional changed schema1 request bytes")
	}
	f.apply("manager", "cancel-image-build", 2, ImageBuildJobSelection{Tenant: q.Read.Query.Tenant, ID: q.Read.Query.Job}, state.Applied)
	if _, err := f.p.CurrentImageBuildBaseToken(f.s, q, 3); err == nil {
		t.Fatal("cancelled job minted a combined token")
	}
	if held, err := f.p.ExternalRegistryImageBuildsPending(f.s, *q.Read.Target.External); err != nil || !held {
		t.Fatal("denied exchange released original source reservation", held, err)
	}
}

func TestBuildTokenSameHostAndOwnerDoNotMergeDistinctReaders(t *testing.T) {
	f, q := buildMultiSourceTokenFixture(t, true)
	for i, read := range []ImageBuildBaseRead{q.Read, q.Additional[0]} {
		single := ImageBuildBaseTokenRequest{Read: read, Challenge: q.Challenge}
		single.Challenge.Scopes = []string{q.Challenge.Scopes[i]}
		if _, err := f.p.CurrentImageBuildBaseToken(f.s, single, 3); err != nil {
			t.Fatal("fixture reader not individually usable", i, err)
		}
	}
	if q.Read.Target.Owner != q.Additional[0].Target.Owner || q.Read.Target.External.ID == q.Additional[0].Target.External.ID {
		t.Fatal("fixture did not use same node with distinct approved readers")
	}
	if _, err := f.p.CurrentImageBuildBaseToken(f.s, q, 3); err == nil {
		t.Fatal("same host/node implicitly combined separate credential grants")
	}
}
