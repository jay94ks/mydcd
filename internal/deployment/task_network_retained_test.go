// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"crypto/sha256"
	"encoding/json"
	"maps"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/schema"
)

// These are exact frozen metadata inputs, not permission to start a Task.
// Projection/retirement must still read an original draining dependency while
// the existing live resolver continues to reject it at the native entry edge.
func TestRetainedTaskNetworkKeepsDrainingMetadataWithoutGrantingStart(t *testing.T) {
	f := makeFixture(t)
	c, ctx := smallCompose(t), contextFor(t, f)
	blueprint, err := Compile(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	objects := frozenManagedGoals(t, blueprint, ctx.Current)
	key := ResourceKey("task", blueprint.d.Tenant, blueprint.d.App, "web")
	var task GoalCommand
	if json.Unmarshal([]byte(objects[key].Value), &task) != nil {
		t.Fatal("original Task input")
	}
	material, err := ResolveTaskNetwork(f.cluster, task, "app", objects)
	if err != nil || material.Reference != nil {
		t.Fatal("original frozen Bridge", err)
	}
	bridgeKey := ResourceKey("bridge", task.Tenant, task.App, "app/"+task.Node)
	changed := maps.Clone(objects)
	object := changed[bridgeKey]
	var bridge GoalCommand
	if json.Unmarshal([]byte(object.Value), &bridge) != nil {
		t.Fatal("original Bridge input")
	}
	bridge.Lifecycle = &schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
	raw, _ := json.Marshal(bridge)
	object.Value = string(raw)
	changed[bridgeKey] = object
	retained, err := ResolveRetainedTaskNetwork(f.cluster, task, "app", changed)
	if err != nil || retained.Source != material.Source || retained.NativeOwner(f.cluster) != material.NativeOwner(f.cluster) || !retained.Bridge.Lifecycle.Drain {
		t.Fatal("retained drain reset original attachment identity", err)
	}
	if _, err = ResolveTaskNetwork(f.cluster, task, "app", changed); err == nil {
		t.Fatal("retained metadata lookup weakened fresh Start admission")
	}
	// A drain lookup is not permission to substitute a newer revision for the
	// Task's exact frozen source. Normal closure reads its immutable claim.
	object.Revision++
	changed[bridgeKey] = object
	if _, err = ResolveRetainedTaskNetwork(f.cluster, task, "app", changed); err == nil {
		t.Fatal("drain lookup accepted a different source revision")
	}
	object = objects[bridgeKey]
	object.Generation++
	changed[bridgeKey] = object
	if _, err = ResolveRetainedTaskNetwork(f.cluster, task, "app", changed); err == nil {
		t.Fatal("retained lookup accepted a replacement generation")
	}
}

func TestRetainedTaskReferenceReadsExactDrainingRawNativeSource(t *testing.T) {
	f, c, ctx, source := externalFixture(t)
	blueprint, err := Compile(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	objects := frozenManagedGoals(t, blueprint, ctx.Current)
	key := ResourceKey("task", blueprint.d.Tenant, blueprint.d.App, "web")
	var task GoalCommand
	if json.Unmarshal([]byte(objects[key].Value), &task) != nil {
		t.Fatal("original Task")
	}
	material, err := ResolveTaskNetwork(f.cluster, task, "app", objects)
	if err != nil || material.Reference == nil || material.Source.Key != source {
		t.Fatal("original raw native attachment", err)
	}
	changed := maps.Clone(objects)
	native := changed[source]
	bridge, err := network.DecodeBridge(native.Value)
	if err != nil {
		t.Fatal(err)
	}
	bridge.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
	raw, _ := json.Marshal(bridge)
	native.Value = string(raw)
	changed[source] = native
	// Freeze the exact draining bytes into this explicit metadata input.
	// This is not a mutation of any accepted app/native effect in the test.
	refKey := ResourceKey("network-ref", task.Tenant, task.App, "app/"+task.Node)
	refObject := changed[refKey]
	var refGoal GoalCommand
	var ref NetworkReference
	if json.Unmarshal([]byte(refObject.Value), &refGoal) != nil || json.Unmarshal(refGoal.Config, &ref) != nil {
		t.Fatal("original ref Goal")
	}
	ref.Spec = sha256.Sum256(raw)
	refGoal.Config, _ = json.Marshal(ref)
	rawGoal, _ := json.Marshal(refGoal)
	refObject.Value = string(rawGoal)
	changed[refKey] = refObject
	retained, err := ResolveRetainedTaskNetwork(f.cluster, task, "app", changed)
	if err != nil || !retained.Bridge.Lifecycle.Drain || retained.Source != material.Source || retained.NativeOwner(f.cluster) != material.NativeOwner(f.cluster) {
		t.Fatal("exact draining raw native source lost", err)
	}
	if _, err := ResolveTaskNetwork(f.cluster, task, "app", changed); err == nil {
		t.Fatal("fresh native Start accepted a draining borrowed Bridge")
	}
	native.Value += " "
	changed[source] = native
	if _, err := ResolveRetainedTaskNetwork(f.cluster, task, "app", changed); err == nil {
		t.Fatal("retained read ignored exact original raw source hash")
	}
}
