// SPDX-License-Identifier: Apache-2.0

package volumes

import "testing"

func TestProcessExitCleanAcceptsTheRequestedStopSignal(t *testing.T) {
	base := ProcessExit{StartedAt: "2026-11-25T10:00:00Z", FinishedAt: "2026-11-25T10:01:00Z", Status: "exited"}
	for _, c := range []struct {
		code   int
		signal string
		oom    bool
		want   bool
	}{
		{0, "", false, true},
		{143, "SIGTERM", false, true},  // ended on the SIGTERM mydc sent
		{131, "SIGQUIT", false, true},  // a configured stop signal
		{143, "", false, false},        // SIGTERM that mydc did not send
		{137, "SIGTERM", false, false}, // Docker's SIGKILL after the grace
		{137, "SIGKILL", false, false}, // a kill is never a clean stop
		{1, "SIGTERM", false, false},
		{143, "SIGTERM", true, false},
	} {
		e := base
		e.Code, e.StopSignal, e.OOM = c.code, c.signal, c.oom
		if got := e.Clean(); got != c.want {
			t.Errorf("exit %d after %q (oom %t): Clean = %t, want %t", c.code, c.signal, c.oom, got, c.want)
		}
	}
}
