// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/workload"
)

func tStep(t *testing.T, key, node, service string, s ComposeService) Step {
	t.Helper()
	s.Sfc.Instance = &TaskInstance{Service: service, Node: node}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return Step{Key: key, Kind: "task", Node: node, Goal: raw}
}

func TestReplacedTaskInterruption(t *testing.T) {
	steps := []Step{
		tStep(t, "web-a", "a", "web", ComposeService{}),
		tStep(t, "web-b", "b", "web", ComposeService{}),
		tStep(t, "api", "a", "api", ComposeService{}),
		tStep(t, "db", "a", "db", ComposeService{Volumes: Mounts{{Type: "volume", Source: "data", Target: "/d"}}}),
		tStep(t, "ro", "a", "ro", ComposeService{Volumes: Mounts{{Type: "volume", Source: "data", Target: "/d", ReadOnly: true}}}),
		tStep(t, "edge", "a", "edge", ComposeService{Ports: []workload.PublishedPort{{Target: 80, Published: "80"}}}),
		tStep(t, "fixed", "a", "fixed", ComposeService{Networks: map[string]Attachment{"n": {IPv4: "10.0.0.5"}}}),
		// A planned address the app did not declare is not a fixed one.
		tStep(t, "auto", "a", "auto", ComposeService{Networks: map[string]Attachment{"n": {IPv4: "10.0.0.6"}}}),
		{Key: "vol", Kind: "volume", Node: "b"},
	}
	input := Compose{Services: map[string]ComposeService{
		"fixed": {Networks: map[string]Attachment{"n": {IPv4: "10.0.0.5"}}},
		"auto":  {Networks: map[string]Attachment{"n": {}}},
	}}
	out := []Change{{Key: "web-a", Action: "Replace"}, {Key: "api", Action: "Replace"}, {Key: "db", Action: "Replace"}, {Key: "ro", Action: "Replace"}, {Key: "edge", Action: "Replace"}, {Key: "fixed", Action: "Replace"}, {Key: "auto", Action: "Replace"}, {Key: "vol", Action: "MoveRequired"}, {Key: "web-b", Action: "Keep"}}
	annotateInterruptions(steps, input, out)
	want := map[string]string{"web-a": "", "api": InterruptSingleInstance, "db": InterruptVolumeWriter, "ro": InterruptSingleInstance, "edge": InterruptHostPort, "fixed": InterruptStaticAddress, "auto": InterruptSingleInstance, "vol": InterruptVolumeMove, "web-b": ""}
	for _, c := range out {
		if c.Interruption != want[c.Key] {
			t.Errorf("%s: interruption %q, want %q", c.Key, c.Interruption, want[c.Key])
		}
	}
}
