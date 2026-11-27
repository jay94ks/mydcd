// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/workload/volumes"

	"github.com/jay94ks/seafield/internal/engineevents"
)

func TestEngineOpsTableBuilds(t *testing.T) {
	if _, err := (&Runtime{}).newEngineOps(); err != nil {
		t.Fatal(err)
	}
}

func TestEngineEventHandlersBuild(t *testing.T) {
	if _, err := engineevents.New((&Runtime{}).engineEventHandlers(), engineevents.Cursor{}, func(engineevents.Cursor) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestVolumeEngineOpsRegisteredAndNotReadyBeforeStart(t *testing.T) {
	table, err := (&Runtime{}).newEngineOps()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	table.Each(func(p engineops.Purpose, op string) {
		if p == engineops.Volume {
			got[op] = true
		}
	})
	for _, op := range []string{"mount", "unmount", "create", "get", "list", "remove"} {
		if !got[op] {
			t.Fatal("volume op not registered", op)
		}
	}
	body, _ := json.Marshal(volumes.VolumeGetQ{Request: engineops.Request{Schema: 1, Op: "get", OpID: opID(), BootID: bootID()}, Name: "sfc-fixed-x"})
	a := table.Serve(context.Background(), engineops.Volume, body)
	var reply volumes.VolumeGetA
	if err := json.Unmarshal(a.Body, &reply); err != nil || reply.Result != engineops.NotApplied || reply.Reason != engineops.NotReady {
		t.Fatal(string(a.Body), err)
	}
}

// The envelope ID types change to string with the engine contract update;
// only these two helpers follow it.
func opID() string   { return "op1" }
func bootID() string { return "boot2" }
