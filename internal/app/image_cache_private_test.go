// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload"
)

func TestUntaggedCacheReferencesKeepDesiredAppliedAndUnknownOriginalConfigIDs(t *testing.T) {
	id := "sha256:" + strings.Repeat("b", 64)
	spec := workload.ContainerSpec{Schema: 1, Node: "node-a", Image: "ghcr.io/team/app@sha256:" + strings.Repeat("a", 64), Bridge: "network/bridge", BridgeGeneration: 1, IPv4: netip.MustParseAddr("10.80.1.9"), Memory: 16 << 20, NanoCPU: 100000000, Process: &workload.Process{ImageID: id, User: "1000:1000", Command: []string{"true"}, StopSignal: "SIGTERM"}}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = workload.DecodeContainer(string(raw)); err != nil {
		t.Fatal("private recipe fixture", err)
	}
	resource := reconcile.Resource{Generation: 1, Spec: string(raw), Present: true}
	for _, record := range []reconcile.Record{
		{Schema: 1, State: reconcile.State{Desired: reconcile.Desired{Revision: 1, Resource: resource}}},
		{Schema: 1, State: reconcile.State{Applied: resource}},
		{Schema: 1, State: reconcile.State{LastID: 7, Pending: &reconcile.Operation{ID: 7, Kind: reconcile.Apply, Target: resource, Phase: reconcile.RecoveryRequired}}},
	} {
		used, err := journalImageReferences(record, id)
		if err != nil || !used {
			t.Fatal("untagged/original config dependency omitted", err)
		}
		if used, err = journalImageReferences(record, "sha256:"+strings.Repeat("c", 64)); err != nil || used {
			t.Fatal("another image acquired this recipe's reference", err)
		}
	}
	if used, err := journalImageReferences(reconcile.Record{Schema: 1}, id); err != nil || used {
		t.Fatal("empty settled record invented a reference", err)
	}
	broken := reconcile.Record{Schema: 1, State: reconcile.State{Applied: reconcile.Resource{Generation: 1, Present: true, Spec: "{}"}}}
	if _, err = journalImageReferences(broken, id); err == nil {
		t.Fatal("invalid private recipe treated as zero use")
	}
}
