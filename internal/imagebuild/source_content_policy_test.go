// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	opspb "github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/sourcepolicy"
	spb "github.com/moby/buildkit/sourcepolicy/pb"
)

// Execute the adopted policy engine, rather than reproducing its rule or
// attribute matching in a fixture. Real frontend/daemon is a separate gate.
func TestSourceContentPolicyConvertsOnlyAcceptedPinsAndPreservesSDKAttributes(t *testing.T) {
	a := FrozenSource{Source: Source{Reference: "registry.example/team/a:latest", Platform: "linux/amd64", Kind: "from"}, Image: "registry.example/team/a@sha256:" + strings.Repeat("a", 64)}
	b := FrozenSource{Source: Source{Reference: "registry.example/team/b:latest", Platform: "linux/amd64", Kind: "copy"}, Image: "registry.example/team/b@sha256:" + strings.Repeat("b", 64)}
	policy, err := sourceContentPolicy([]FrozenSource{b, a})
	if err != nil {
		t.Fatal(err)
	}
	other, err := sourceContentPolicy([]FrozenSource{a, b, a})
	raw, _ := json.Marshal(policy)
	want, _ := json.Marshal(other)
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatal("source policy not stable", err)
	}
	for _, input := range []FrozenSource{a, b} {
		for _, ref := range []string{input.Source.Reference, input.Image} {
			op := &opspb.SourceOp{Identifier: "docker-image://" + ref, Attrs: map[string]string{opspb.AttrOCILayoutSessionID: "foreign-session", "test.keep": "value"}}
			changed, err := sourcepolicy.NewEngine([]*spb.Policy{policy}).Evaluate(context.Background(), op)
			if err != nil || !changed || op.Identifier != "oci-layout://"+input.Image || op.Attrs[opspb.AttrOCILayoutStoreID] != sourceContentStoreID(input.Image) || op.Attrs[opspb.AttrOCILayoutSessionID] != "" || op.Attrs["test.keep"] != "value" {
				t.Fatal("native source conversion lost policy or image attrs", op, err)
			}
		}
	}
	for _, op := range []*opspb.SourceOp{
		{Identifier: "docker-image://registry.example/team/onbuild:latest"},
		{Identifier: "oci-layout://" + a.Image},
		{Identifier: "oci-layout://" + a.Image, Attrs: map[string]string{opspb.AttrOCILayoutStoreID: sourceContentStoreID(b.Image)}},
		{Identifier: "oci-layout://" + a.Image, Attrs: map[string]string{opspb.AttrOCILayoutStoreID: sourceContentStoreID(a.Image), opspb.AttrOCILayoutSessionID: "foreign-session"}},
	} {
		if _, err := sourcepolicy.NewEngine([]*spb.Policy{policy}).Evaluate(context.Background(), op); err == nil {
			t.Fatal("unapproved ONBUILD/pin/store/session admitted", op)
		}
	}
}
