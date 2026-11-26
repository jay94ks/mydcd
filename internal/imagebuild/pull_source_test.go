// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/registryclient"
)

func TestPullSourceSelectsRepositoryRatherThanHostAndRejectsBroaderScopes(t *testing.T) {
	var inputs []FrozenSource
	for stage, repo := range []string{"one", "two"} {
		inputs = append(inputs, FrozenSource{Source: Source{Reference: "registry.example/team/" + repo + ":latest", Platform: "linux/amd64", Kind: "from", Stage: stage, Line: stage + 1}, Image: "registry.example/team/" + repo + "@sha256:" + strings.Repeat("a", 64)})
	}
	q := registryclient.PullTokenChallenge{Host: "registry.example", Realm: "https://registry.example/token", Scopes: []string{"repository:team/two:pull"}}
	source, err := SelectPullSource(inputs, q)
	if err != nil || source != inputs[1].Source {
		t.Fatal("same-host lookup chose another repository", source, err)
	}
	for _, scopes := range [][]string{nil, {"repository:team/other:pull"}, {"repository:team/two:pull,push"}, {"repository:team/two:pull", "repository:team/one:pull"}, {"registry:catalog:*"}} {
		bad := q
		bad.Scopes = scopes
		if _, err := SelectPullSource(inputs, bad); err == nil {
			t.Fatal("scope outside accepted frozen repository was authorized", scopes)
		}
	}
}

func TestPullSourcesKeepEveryFrozenRepositoryAndDeduplicateRepeatedScopes(t *testing.T) {
	var inputs []FrozenSource
	for stage, repo := range []string{"one", "two"} {
		inputs = append(inputs, FrozenSource{Source: Source{Reference: "registry.example/team/" + repo + ":latest", Platform: "linux/amd64", Kind: "from", Stage: stage, Line: stage + 1}, Image: "registry.example/team/" + repo + "@sha256:" + strings.Repeat("a", 64)})
	}
	q := registryclient.PullTokenChallenge{Host: "registry.example", Realm: "https://registry.example/token", Scopes: []string{"repository:team/two:pull", "repository:team/one:pull", "repository:team/two:pull"}}
	got, err := SelectPullSources(inputs, q)
	if err != nil || !slices.Equal(got, []Source{inputs[1].Source, inputs[0].Source}) {
		t.Fatal("scope set dropped or duplicated an original source", got, err)
	}
	for _, scopes := range [][]string{{"repository:team/one:pull", "repository:team/missing:pull"}, {"repository:team/one:pull", "repository:team/two:pull,push"}, {"repository:team/one:pull", "registry:catalog:*"}, {"repository:team/one:pull repository:team/two:pull"}} {
		bad := q
		bad.Scopes = scopes
		if got, err := SelectPullSources(inputs, bad); err == nil || got != nil {
			t.Fatal("partial selection authorized an unfrozen/broader repository", got, scopes, err)
		}
	}
}
