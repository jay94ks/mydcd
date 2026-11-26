// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/api/types/container"
)

func TestContainerExitRequiresPositiveStartedFinishedExitedWitness(t *testing.T) {
	good := container.State{Status: container.StateExited, StartedAt: "2026-11-14T01:00:00Z", FinishedAt: "2026-11-14T01:00:01Z"}
	if observed := engine.ObserveContainerExit(&good); observed == nil || observed.Code != 0 || observed.FinishedAt <= observed.StartedAt {
		t.Fatal("positive exit rejected")
	}
	for _, change := range []func(*container.State){
		func(s *container.State) { s.Status = container.StateCreated },
		func(s *container.State) { s.Running = true }, func(s *container.State) { s.Paused = true },
		func(s *container.State) { s.Restarting = true }, func(s *container.State) { s.OOMKilled = true },
		func(s *container.State) { s.Dead = true }, func(s *container.State) { s.Pid = 123 },
		func(s *container.State) { s.Error = "private start failure" },
		func(s *container.State) { s.StartedAt = "0001-01-01T00:00:00Z" },
		func(s *container.State) { s.FinishedAt = "0001-01-01T00:00:00Z" },
		func(s *container.State) { s.FinishedAt = "2026-11-14T00:59:59Z" },
		func(s *container.State) { s.ExitCode = -1 }, func(s *container.State) { s.ExitCode = 256 },
		func(s *container.State) { s.StartedAt = "9999-01-01T00:00:00Z"; s.FinishedAt = "9999-01-01T00:00:01Z" },
	} {
		state := good
		change(&state)
		if engine.ObserveContainerExit(&state) != nil {
			t.Fatal("ambiguous/not-exited state became success", state.Status)
		}
	}
	failed := good
	failed.ExitCode = 23
	if observed := engine.ObserveContainerExit(&failed); observed == nil || observed.Code != 23 {
		t.Fatal("nonzero exit lost")
	}
	if engine.ObserveContainerExit(nil) != nil {
		t.Fatal("missing state became exit")
	}
}

func TestProbeTaskRecordRejectsDrainReplacementAndPendingWithoutNativeIO(t *testing.T) {
	spec := ContainerSpec{Schema: 1, Node: "owner", Image: "sha256:" + strings.Repeat("a", 64), Command: []string{"/backend"}, Bridge: "bridge", BridgeGeneration: 1, IPv4: netip.MustParseAddr("192.0.2.2"), Memory: 32 << 20, NanoCPU: 100000000}
	raw, _ := json.Marshal(spec)
	resource := reconcile.Resource{Present: true, Generation: 3, Spec: string(raw)}
	original := reconcile.Record{Schema: 1, State: reconcile.State{Desired: reconcile.Desired{Revision: 7, Resource: resource}, Applied: resource, GenerationFloor: 3, LastID: 1}}
	if _, err := probeTaskRecord(original, 3, 7); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*reconcile.Record){
		func(r *reconcile.Record) { r.State.Desired.Revision++ }, func(r *reconcile.Record) { r.State.Stopped = true },
		func(r *reconcile.Record) { r.State.Desired.Present = false }, func(r *reconcile.Record) { r.State.Applied.Present = false },
		func(r *reconcile.Record) {
			r.State.Pending = &reconcile.Operation{ID: 2, Kind: reconcile.Remove, Target: resource, Phase: reconcile.Dispatched}
		},
		func(r *reconcile.Record) { r.State.Desired.Spec = "different recipe" },
		func(r *reconcile.Record) {
			drain := spec
			drain.Lifecycle.Drain = true
			drain.Lifecycle.Nonce[0] = 1
			raw, _ := json.Marshal(drain)
			r.State.Applied.Spec = string(raw)
			r.State.Desired.Spec = string(raw)
		},
	} {
		changed := original
		change(&changed)
		if _, err := probeTaskRecord(changed, 3, 7); err == nil {
			t.Fatal("stale/retiring target admitted")
		}
	}
	changed := original
	changed.State.LastID++
	if sameProbeTask(original, changed) {
		t.Fatal("in-flight native operation change missed")
	}
}

func TestReadProbeConsumerKeepsOriginalRunCallAndRejectsZeroIdentity(t *testing.T) {
	run := sha256.Sum256([]byte("original run"))
	l := ReadProbeLease{Target: ProbeTarget{Key: "task", Generation: 1, Revision: 1, Status: ContainerStatus{NativeID: "original-native"}}, RunID: hex.EncodeToString(run[:]), Call: sha256.Sum256([]byte("original call"))}
	if !validReadProbe(l) {
		t.Fatal("valid read consumer rejected")
	}
	first := l.consumer()
	l.Call[0] ^= 1
	if l.consumer() == first {
		t.Fatal("different call reused consumer")
	}
	l.RunID = strings.Repeat("0", 64)
	if validReadProbe(l) {
		t.Fatal("zero run identity accepted")
	}
}
