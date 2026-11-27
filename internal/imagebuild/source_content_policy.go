// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"

	opspb "github.com/moby/buildkit/solver/pb"
	spb "github.com/moby/buildkit/sourcepolicy/pb"
)

func sourceContentStoreID(pin string) string {
	sum := sha256.Sum256([]byte(pin))
	return "sfc-from-" + hex.EncodeToString(sum[:])
}

// Convert in both metadata resolution and LLB evaluation. The native
// Dockerfile frontend retains image config/ONBUILD/platform semantics, while
// exact accepted refs use the session store instead of host-only credentials.
func sourceContentPolicy(inputs []FrozenSource) (*spb.Policy, error) {
	if _, err := SourcePolicy(inputs); err != nil {
		return nil, err
	}
	converts := map[string]string{}
	allowed := map[string]bool{}
	for _, input := range inputs {
		converts[input.Source.Reference] = input.Image
		converts[input.Image] = input.Image
		allowed[input.Image] = true
	}
	policy := &spb.Policy{Version: 1}
	for _, scheme := range []string{"docker-image://*", "oci-layout://*"} {
		policy.Rules = append(policy.Rules, &spb.Rule{Action: spb.PolicyAction_DENY, Selector: &spb.Selector{Identifier: scheme, MatchType: spb.MatchType_WILDCARD}})
	}
	var refs []string
	for ref := range converts {
		refs = append(refs, ref)
	}
	slices.Sort(refs)
	for _, ref := range refs {
		pin := converts[ref]
		policy.Rules = append(policy.Rules, &spb.Rule{Action: spb.PolicyAction_CONVERT, Selector: &spb.Selector{Identifier: "docker-image://" + ref, MatchType: spb.MatchType_EXACT}, Updates: &spb.Update{Identifier: "oci-layout://" + pin, Attrs: map[string]string{opspb.AttrOCILayoutStoreID: sourceContentStoreID(pin), opspb.AttrOCILayoutSessionID: ""}}})
	}
	refs = nil
	for pin := range allowed {
		refs = append(refs, pin)
	}
	slices.Sort(refs)
	for _, pin := range refs {
		policy.Rules = append(policy.Rules, &spb.Rule{Action: spb.PolicyAction_ALLOW, Selector: &spb.Selector{Identifier: "oci-layout://" + pin, MatchType: spb.MatchType_EXACT, Constraints: []*spb.AttrConstraint{{Key: opspb.AttrOCILayoutStoreID, Value: sourceContentStoreID(pin), Condition: spb.AttrMatch_EQUAL}, {Key: opspb.AttrOCILayoutSessionID, Value: "", Condition: spb.AttrMatch_EQUAL}}}})
	}
	return policy, nil
}
