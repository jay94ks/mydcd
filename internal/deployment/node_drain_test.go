// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"testing"
)

func TestNodeDrainRelocationReusesInventoryOriginalClosure(t *testing.T) {
	x := newInventoryFixture(t)
	x.all()
	ctx := contextFor(t, x.f)
	ctx.Current = x.shared.Objects("")
	// Explicit-address declarations must receive a plan blocker rather than a
	// guessed IP on a different subnet. The existing relocation test exercises
	// actual original closure with a caller-selected valid address.
	if _, err := x.b.RelocateNode(x.f.c, ctx, "node-a", "node-b", []string{"web"}); err == nil {
		t.Fatal("drain guessed a replacement static address")
	}
}

func TestNodeDrainMovesDeclaredDynamicAddressAndKeepsOriginalInput(t *testing.T) {
	f, input, ctx := managedNetworkFixture(t)
	web := input.Services["web"]
	web.DependsOn = nil
	web.Networks["app"] = Attachment{}
	input.Services = map[string]ComposeService{"web": web}
	input.Volumes = nil
	before, _ := json.Marshal(input)
	original, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	declared, ok := original.DeclaredService("web")
	if !ok || declared.Networks["app"].IPv4 != "" {
		t.Fatal("dynamic declaration was rewritten as a fixed address")
	}
	next, err := original.RelocateNode(f.c, ctx, "node-a", "node-b", []string{"web"})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range next.Steps() {
		if step.Kind == "task" && (step.Node != "node-b" || step.Owner != public(f.nb)) {
			t.Fatal("target task misplaced")
		}
	}
	after, _ := json.Marshal(input)
	if !bytes.Equal(before, after) {
		t.Fatal("drain changed source declaration")
	}
	if _, err = original.RelocateNode(f.c, ctx, "node-a", "node-a", []string{"web"}); err == nil {
		t.Fatal("self relocation admitted")
	}
}

func TestDrainMultipleVolumesPreviewCannotGrantOwnerOrNativeStart(t *testing.T) {
	f, input, ctx := managedNetworkFixture(t)
	db := input.Services["db"]
	db.Networks["app"] = Attachment{}
	db.Volumes = append(db.Volumes, Mount{Type: "volume", Source: "mysql-logs", Target: "/var/log/mysql"})
	input.Services = map[string]ComposeService{"db": db}
	definition := input.Volumes["mysql-data"]
	input.Volumes["mysql-logs"] = definition
	core := f.v["tenant/php-mysql/mysql-data"]
	source, revision := core.Owner()
	scope := core.Scope()
	scope.ID = "mysql-logs"
	secondOwner := source
	secondOwner.Native = "original-mysql-logs"
	second, err := volumes.New(f.c, "alice", scope, secondOwner, 2)
	if err != nil {
		t.Fatal(err)
	}
	f.v[VolumeKey(scope)] = second
	ctx.Volumes = f.v
	original, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, secondRevision := second.Owner()
	move := VolumeMovePlacement{Scope: core.Scope(), Source: source, SourceOwnerRevision: revision, Target: volumes.Owner{Node: "node-a", Key: public(f.na), Native: "target-mysql"}, Others: []VolumeMovePlacement{{Scope: scope, Source: secondOwner, SourceOwnerRevision: secondRevision, Target: volumes.Owner{Node: "node-a", Key: public(f.na), Native: "target-mysql-logs"}}}}
	before, _ := core.Encode()
	otherBefore, _ := second.Encode()
	preview, err := original.RelocateVolumeNode(f.c, ctx, "node-b", "node-a", []string{"db"}, move)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewExecution(preview, f.c, ctx, "target-before-fence", "submitter", 1); err == nil {
		t.Fatal("preview alone granted real target execution")
	}
	missing := move
	missing.Others = nil
	if _, err = original.RelocateVolumeNode(f.c, ctx, "node-b", "node-a", []string{"db"}, missing); err == nil {
		t.Fatal("second original Volume omitted")
	}
	after, _ := ctx.Volumes[VolumeKey(core.Scope())].Encode()
	otherAfter, _ := ctx.Volumes[VolumeKey(scope)].Encode()
	if !bytes.Equal(before, after) || !bytes.Equal(otherBefore, otherAfter) {
		t.Fatal("preview rewrote native owner/data")
	}
}
