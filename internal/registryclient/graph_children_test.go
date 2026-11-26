// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"slices"
	"strings"
	"testing"
)

func TestGraphChildrenKeepsOriginalRootPathForSDKDiscovery(t *testing.T) {
	f := newGraphContentFixture(t)
	q := f.query
	for depth := 0; depth <= len(f.query.Path); depth++ {
		q.Path = slices.Clone(f.query.Path[:depth])
		_, key, _ := strings.Cut(q.Selected().Ref, "@")
		item := f.items[key]
		children, err := GraphContentChildren(q, item.media, item.raw)
		if err != nil || len(children) == 0 {
			t.Fatal("metadata did not expose witnessed children", depth, err)
		}
		for _, child := range children {
			if child.Query.Root != q.Root || !child.Query.Valid() || !child.Info.Valid(child.Query.Selected()) {
				t.Fatal("child lost root-bound query", child)
			}
			var visited []string
			info, _, err := SelectGraphContent(child.Query, f.reader(t, &visited))
			if err != nil || info != child.Info {
				t.Fatal("SDK child cannot use actual owner selector", child, info, err)
			}
		}
	}
}
