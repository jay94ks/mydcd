// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/json"
	"slices"

	"github.com/distribution/reference"
	spb "github.com/moby/buildkit/sourcepolicy/pb"
)

// SourcePolicy creates BuildKit's native --source-policy-file, not rewritten
// Dockerfile text. The initial deny also covers image pulls introduced by base
// ONBUILD instructions that were absent from the uploaded Dockerfile. Exact
// converts freeze accepted tags and final exact allows admit only those pins.
// The policy contains public image references; registry secrets stay separate.
func SourcePolicy(sources []FrozenSource) ([]byte, error) {
	if len(sources) > MaxTreeEntries {
		return nil, ErrInvalid
	}
	pins := map[string]string{}
	allowed := map[string]bool{}
	for _, source := range sources {
		original, err := reference.ParseNormalizedNamed(source.Source.Reference)
		pin, pinErr := parseCanonical(source.Image)
		if err != nil || pinErr != nil || source.Source.Reference != reference.TagNameOnly(original).String() || original.Name() != pin.Name() || pin.Digest().Algorithm().String() != "sha256" || !ValidPlatform(source.Source.Platform) {
			return nil, ErrInvalid
		}
		if before, found := pins[source.Source.Reference]; found && before != source.Image {
			return nil, ErrConflict
		}
		pins[source.Source.Reference] = source.Image
		allowed[source.Image] = true
	}
	policy := &spb.Policy{Version: 1, Rules: []*spb.Rule{{Action: spb.PolicyAction_DENY, Selector: &spb.Selector{Identifier: "docker-image://*", MatchType: spb.MatchType_WILDCARD}}}}
	var names []string
	for name := range pins {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if name == pins[name] {
			continue
		}
		policy.Rules = append(policy.Rules, &spb.Rule{Action: spb.PolicyAction_CONVERT, Selector: &spb.Selector{Identifier: "docker-image://" + name, MatchType: spb.MatchType_EXACT}, Updates: &spb.Update{Identifier: "docker-image://" + pins[name]}})
	}
	names = nil
	for name := range allowed {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		policy.Rules = append(policy.Rules, &spb.Rule{Action: spb.PolicyAction_ALLOW, Selector: &spb.Selector{Identifier: "docker-image://" + name, MatchType: spb.MatchType_EXACT}})
	}
	return json.Marshal(policy)
}
