// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestVolumeMovePreviewUsesCurrentSourceWithoutExecutionAuthority(t *testing.T) {
	f := makeFixture(t)
	ctx := contextFor(t, f)
	input := smallCompose(t)
	source, err := Compile(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Current = map[string]state.Object{}
	for _, step := range source.Steps() {
		raw, _ := json.Marshal(GoalCommand{Schema: 1, Cluster: f.cluster, Tenant: "tenant", App: "php-mysql", Deployment: "deploy", Kind: step.Kind, Node: step.Node, Owner: step.Owner, Config: step.Goal})
		ctx.Current[step.Key] = state.Object{Present: true, Revision: 1, Generation: 1, Value: string(raw)}
	}
	v := f.v["tenant/php-mysql/mysql-data"]
	owner, revision := v.Owner()
	move := VolumeMovePlacement{Scope: v.Scope(), Source: owner, SourceOwnerRevision: revision, Target: volumes.Owner{Node: "node-a", Key: public(f.na), Native: "target-native"}}
	db := input.Services["db"]
	db.MyDC.Node = "node-a"
	db.Networks["app"] = Attachment{IPv4: "10.240.10.20"}
	input.Services["db"] = db
	volume := input.Volumes["mysql-data"]
	volume.MyDC.Node = "node-a"
	input.Volumes["mysql-data"] = volume
	before, _ := v.Encode()
	preview, err := CompileVolumeMove(input, f.c, ctx, move)
	if err != nil {
		t.Fatal(err)
	}
	if err = preview.ValidateVolumeMove(f.c, ctx, move); err != nil {
		t.Fatal(err)
	}
	if _, err = NewExecution(preview, f.c, ctx, "target", "submitter", 1); err == nil {
		t.Fatal("preview granted early execution")
	}
	encoded, _ := preview.Encode()
	decoded, err := DecodeBlueprint(encoded)
	if err != nil || decoded.Digest() != preview.Digest() {
		t.Fatal("immutable artifact", err)
	}
	after, _ := ctx.Volumes["tenant/php-mysql/mysql-data"].Encode()
	if string(before) != string(after) {
		t.Fatal("preview changed actual Volume")
	}
	for _, mutate := range []func(*VolumeMovePlacement){
		func(m *VolumeMovePlacement) { m.SourceOwnerRevision++ },
		func(m *VolumeMovePlacement) { m.Source.Key[0] ^= 1 },
		func(m *VolumeMovePlacement) { m.Scope.Generation++ },
		func(m *VolumeMovePlacement) { m.Target.Key[0] ^= 1 },
	} {
		bad := move
		mutate(&bad)
		if _, err = CompileVolumeMove(input, f.c, ctx, bad); err == nil {
			t.Fatal("wrong source/target accepted")
		}
	}
	wrongActor := ctx
	wrongActor.Actor = "admin"
	if decoded.ValidateVolumeMove(f.c, wrongActor, move) == nil {
		t.Fatal("artifact actor changed")
	}
	limited := ctx
	limited.Nodes = map[string]PlanningNode{}
	for id, n := range ctx.Nodes {
		limited.Nodes[id] = n
	}
	n := limited.Nodes["node-a"]
	n.Capacity.Memory = 1
	limited.Nodes["node-a"] = n
	if _, err = CompileVolumeMove(input, f.c, limited, move); err == nil {
		t.Fatal("preview bypassed target budget")
	}
	key := ResourceKey("volume", "tenant", "php-mysql", "mysql-data")
	original := ctx.Current[key]
	var goal GoalCommand
	_ = json.Unmarshal([]byte(original.Value), &goal)
	goal.Tenant = "other"
	raw, _ := json.Marshal(goal)
	original.Value = string(raw)
	ctx.Current[key] = original
	if _, err = CompileVolumeMove(input, f.c, ctx, move); err == nil {
		t.Fatal("preview adopted foreign goal")
	}
}
