// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	spb "github.com/moby/buildkit/sourcepolicy/pb"
)

func TestSourcePolicyUsesNativeDenyConvertAllowAndStableOrder(t *testing.T) {
	a := FrozenSource{Source: Source{Reference: "docker.io/library/alpine:latest", Platform: "linux/amd64"}, Image: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64)}
	b := FrozenSource{Source: Source{Reference: "docker.io/library/busybox:latest", Platform: "linux/amd64"}, Image: "docker.io/library/busybox@sha256:" + strings.Repeat("b", 64)}
	raw, err := SourcePolicy([]FrozenSource{b, a})
	if err != nil {
		t.Fatal(err)
	}
	other, err := SourcePolicy([]FrozenSource{a, b, a})
	if err != nil || !bytes.Equal(raw, other) {
		t.Fatal("noncanonical policy", err)
	}
	var policy spb.Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Version != 1 || len(policy.Rules) != 5 || policy.Rules[0].Action != spb.PolicyAction_DENY || policy.Rules[0].Selector.Identifier != "docker-image://*" || policy.Rules[1].Action != spb.PolicyAction_CONVERT || policy.Rules[3].Action != spb.PolicyAction_ALLOW || policy.Rules[3].Selector.MatchType != spb.MatchType_EXACT {
		t.Fatal("native policy contract", string(raw))
	}
	conflicting := a
	conflicting.Image = "docker.io/library/alpine@sha256:" + strings.Repeat("c", 64)
	if _, err := SourcePolicy([]FrozenSource{a, conflicting}); err == nil {
		t.Fatal("platform pins silently overwrite same source")
	}
	// Actual BuildKit/ONBUILD/tag movement refusal belongs to the final native
	// batch; decoding JSON does not establish engine execution behavior.
}
