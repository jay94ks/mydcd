// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

func TestBuildContentUsesAcceptedBeginAndExactFrozenRootWithoutCombiningReaders(t *testing.T) {
	f, tokens := buildMultiSourceTokenFixture(t, true)
	for _, read := range append([]ImageBuildBaseRead{tokens.Read}, tokens.Additional...) {
		q := ImageBuildBaseContentRead{Read: read, Query: registryclient.GraphContentQuery{Root: read.Target.Normalized, Path: []string{"sha256:" + strings.Repeat("c", 64)}, Kind: "layer", Digest: "sha256:" + strings.Repeat("d", 64)}}
		if _, err := f.p.CurrentImageBuildBaseContent(f.s, q, 3); err != nil {
			t.Fatal("individually accepted reader cannot supply content", err)
		}
		for _, edit := range []func(*ImageBuildBaseContentRead){
			func(q *ImageBuildBaseContentRead) {
				q.Query.Root = "ghcr.io/team/other@sha256:" + strings.Repeat("a", 64)
			},
			func(q *ImageBuildBaseContentRead) { q.Query.Root = q.Query.Selected().Ref },
			func(q *ImageBuildBaseContentRead) { q.Read.Builder[0] ^= 1 },
			func(q *ImageBuildBaseContentRead) { q.Read.Query.Job = "different-job" },
			func(q *ImageBuildBaseContentRead) { q.Read.Query.Snapshot[0] ^= 1 },
			func(q *ImageBuildBaseContentRead) { q.Read.Query.Source.Stage++ },
			func(q *ImageBuildBaseContentRead) { q.Read.Target.Owner[0] ^= 1 },
			func(q *ImageBuildBaseContentRead) { q.Read.Target.ExternalReadSet[0] ^= 1 },
			func(q *ImageBuildBaseContentRead) { q.Query.Path[0] = "../../unrelated" },
		} {
			bad := q
			bad.Query.Path = slices.Clone(q.Query.Path)
			edit(&bad)
			if _, err := f.p.CurrentImageBuildBaseContent(f.s, bad, 3); err == nil {
				t.Fatal("changed original build/source content authorized")
			}
		}
	}
	// Policy authorizes a fixed root, not a claimed graph edge. The actual
	// registry adapter must still prove every Path descriptor before any blob.
	q := ImageBuildBaseContentRead{Read: tokens.Read, Query: registryclient.GraphContentQuery{Root: tokens.Read.Target.Normalized, Kind: "manifest"}}
	f.apply("manager", "cancel-image-build", 2, ImageBuildJobSelection{Tenant: q.Read.Query.Tenant, ID: q.Read.Query.Job}, state.Applied)
	if _, err := f.p.CurrentImageBuildBaseContent(f.s, q, 3); err == nil {
		t.Fatal("cancelled build acquired new content")
	}
	if held, err := f.p.ExternalRegistryImageBuildsPending(f.s, *q.Read.Target.External); err != nil || !held {
		t.Fatal("content denial released the original reader", held, err)
	}
}

func TestBuildContentQueuedJobCannotReadBytesBeforeSignedBegin(t *testing.T) {
	f, plan, inputs, _ := buildBoundSourceFixture(t)
	read, err := f.p.ImageBuildBaseRead(f.s, plan.Spec.Scope.Root.Key, buildBaseQuery(plan, inputs[0].Source.Reference))
	if err != nil {
		t.Fatal(err)
	}
	// A source resolution before begin is metadata authority only. Even a
	// syntactically valid claimed digest must not turn it into a content grant.
	read.Target.Normalized = inputs[0].Image
	q := ImageBuildBaseContentRead{Read: read, Query: registryclient.GraphContentQuery{Root: inputs[0].Image, Kind: "manifest"}}
	if _, err := f.p.CurrentImageBuildBaseContent(f.s, q, 3); err == nil {
		t.Fatal("queued source resolution authorized image bytes")
	}
}
