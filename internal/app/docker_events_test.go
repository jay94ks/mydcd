// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/moby/moby/api/types/events"
)

func TestDockerDiagnosticTransitionCountsThreeRestartsWithoutDoubleStartEvents(t *testing.T) {
	owner := dockerEventOwner{Schema: 1, Target: eventlog.Target{Tenant: "tenant", App: "app", Task: "workload/task/tenant/app/web", Node: "node-a", Native: "original-native", Generation: 1, Revision: 1}}
	step := func(action events.Action, nano int64, attributes map[string]string) (string, eventlog.Detail) {
		t.Helper()
		var kind string
		var detail eventlog.Detail
		owner, kind, detail = dockerEventTransition(owner, events.Message{Action: action, Actor: events.Actor{ID: owner.Target.Native, Attributes: attributes}}, nano, "same-boot", 1)
		return kind, detail
	}
	base := int64(100 * time.Second)
	if kind, _ := step("start", base, nil); kind != "" {
		t.Fatal("first start became a restart")
	}
	var observed []int64
	for i := range 3 {
		at := base + int64(i+1)*int64(time.Minute)
		kind, detail := step("die", at, map[string]string{"exitCode": "137", "private-env": "not-public"})
		if kind != "task-exited" || detail.ExitCode == nil || *detail.ExitCode != 137 || detail.Reason != "exit" {
			t.Fatal("exit137 was lost or invented as OOM")
		}
		if kind, _ = step("start", at+1, nil); kind != "task-restarted" {
			t.Fatal("restart missing")
		}
		observed = append(observed, owner.LastStart)
		if kind, _ = step("restart", at+2, nil); kind != "" {
			t.Fatal("SDK restart notification duplicated the start")
		}
		// Persist/reopen uses the same owner state, without another algorithm.
		raw, err := json.Marshal(owner)
		if err != nil || json.Unmarshal(raw, &owner) != nil {
			t.Fatal("owner roundtrip", err)
		}
		if kind, _ = step("start", at+1, nil); kind != "" {
			t.Fatal("inclusive source replay emitted another restart")
		}
	}
	if len(observed) != 3 || observed[0] >= observed[1] || observed[1] >= observed[2] || observed[2]-observed[0] >= int64(10*time.Minute) || owner.Target.Native != "original-native" || owner.Target.Generation != 1 {
		t.Fatal("ordered short restart history changed original Task identity")
	}
	if kind, detail := step("health_status: unhealthy", base+int64(5*time.Minute), nil); kind != "probe-failed" || detail.ConsecutiveFailures != 0 {
		t.Fatal("Docker transition fabricated a failing streak")
	}
	step("oom", base+int64(6*time.Minute), nil)
	if kind, detail := step("die", base+int64(6*time.Minute)+1, nil); kind != "task-exited" || detail.Reason != "oom" || detail.ExitCode != nil || detail.Code != "EXIT_CODE_UNAVAILABLE" {
		t.Fatal("actual OOM fact or unknown exit distinction lost")
	}
}

func TestDockerDiagnosticBootChangeRequiresRealBootEvidenceAndPostBootStart(t *testing.T) {
	baseline := dockerEventOwner{EverStarted: true, LastStart: 10, Boot: "old-boot"}
	for _, tc := range []struct {
		boot       string
		bootAt, at int64
		want       string
	}{
		{"new-boot", 100, 101, "node-restart"},
		{"old-boot", 1, 101, "restart"},
		{"", 0, 101, "restart"},
		{"new-boot", 0, 101, "restart"},
		{"new-boot", 100, 99, "restart"},
	} {
		_, kind, detail := dockerEventTransition(baseline, events.Message{Action: "start"}, tc.at, tc.boot, tc.bootAt)
		if kind != "task-restarted" || detail.Reason != tc.want {
			t.Fatal("node restart was inferred from daemon restart or old backlog", tc, detail.Reason)
		}
	}
	backlog, _, _ := dockerEventTransition(baseline, events.Message{Action: "start"}, 99, "new-boot", 100)
	if backlog.Boot != "old-boot" {
		t.Fatal("old backlog consumed new boot identity")
	}
	_, _, detail := dockerEventTransition(backlog, events.Message{Action: "start"}, 101, "new-boot", 100)
	if detail.Reason != "node-restart" {
		t.Fatal("old backlog hid subsequent real reboot start")
	}
}
