// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	bkclient "github.com/moby/buildkit/client"
)

func TestCachePolicySelectionRetainsSourceIdentityWhileApplyingCurrentThresholds(t *testing.T) {
	source, _ := testJobSpec(t)
	before := source.Digest()
	at := uint64(10 * 86400)
	u, err := NewCacheUsage(source, at, []*bkclient.UsageInfo{{ID: "eligible", Size: 100, CreatedAt: time.Unix(int64(at)-2*86400, 0)}, {ID: "busy", Size: 10, InUse: true}, {ID: "shared", Size: 10, Shared: true}})
	if err != nil {
		t.Fatal(err)
	}
	old, err := SelectCacheCleanup(source, u, "age")
	if err != nil || len(old.IDs) != 0 {
		t.Fatal("fixture source policy was not old", old, err)
	}
	policy := source.Policy.Own()
	policy.Cleanup.UnusedDays = 1
	policy.Cleanup.HighWaterPercent = 50
	policy.CacheBytes = 100
	age, err := SelectCacheCleanupPolicy(source, u, "age", policy)
	if err != nil || len(age.IDs) != 1 || age.IDs[0] != "eligible" {
		t.Fatal("current age not selected", age, err)
	}
	size, err := SelectCacheCleanupPolicy(source, u, "size", policy)
	if err != nil || size.MaxUsedSpace != 50 || len(size.IDs) != 1 || size.IDs[0] != "eligible" || source.Digest() != before || u.Job != before {
		t.Fatal("policy changed original source or selected protected cache", size, err)
	}
	policy.Tenant = "foreign"
	if _, err := SelectCacheCleanupPolicy(source, u, "age", policy); err == nil {
		t.Fatal("foreign cleanup policy accepted")
	}
}

func TestNativeAutomaticPolicyCannotBecomeAManualFilterOrMutateOriginalSpec(t *testing.T) {
	source, _ := testJobSpec(t)
	manual := NativeCachePruneSpec{Schema: 1, Intent: [32]byte{1}, ID: "cache-clear", At: source.CreatedAt, Source: source, Filter: CachePruneFilter{Mode: "all"}}
	before := manual.Source.Digest()
	legacy, _ := json.Marshal(struct {
		Schema uint8
		Intent [32]byte
		ID     string
		At     uint64
		Source JobSpec
		Filter CachePruneFilter
	}{manual.Schema, manual.Intent, manual.ID, manual.At, manual.Source, manual.Filter})
	actual, _ := json.Marshal(manual)
	if !manual.Valid() || !bytes.Equal(actual, legacy) {
		t.Fatal("nil Automatic changed old spec bytes")
	}
	policy := source.Policy.Own()
	auto := manual.Own()
	auto.Filter = CachePruneFilter{Mode: "policy"}
	if auto.Valid() || auto.Filter.Valid() {
		t.Fatal("manual input authorized internal policy mode")
	}
	auto.Automatic = &policy
	if !auto.Valid() {
		t.Fatal("valid original-root policy rejected")
	}
	owned := auto.Own()
	owned.Automatic.Nodes[0].Root.ID = "changed-root"
	if owned.Valid() || !auto.Valid() || auto.Source.Digest() != before {
		t.Fatal("policy/source ownership aliased")
	}
	wrong := auto.Own()
	wrong.Filter = CachePruneFilter{Mode: "all"}
	if wrong.Valid() {
		t.Fatal("automatic policy mixed with explicit manual intent")
	}
	wrong = auto.Own()
	wrong.Automatic.BuilderImage = "registry.example/other/builder@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if wrong.Valid() {
		t.Fatal("new automatic policy started an obsolete builder/cache scope")
	}
}
