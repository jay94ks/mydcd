// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"
)

func TestStartJobRunsOneAtATimeAndStopsWithRuntime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runtime{ctx: ctx}
	var j nodeJob
	release, done := make(chan struct{}), make(chan string, 2)
	run := func(op string) { <-release; done <- op }
	if !r.startJob(&j, "a", run) {
		t.Fatal("first run did not start")
	}
	if r.startJob(&j, "b", run) {
		t.Fatal("second run started while the first is in flight")
	}
	close(release)
	r.wg.Wait()
	if got := <-done; got != "a" {
		t.Fatalf("ran %q", got)
	}
	if !r.startJob(&j, "c", run) {
		t.Fatal("run did not start after the previous one finished")
	}
	r.wg.Wait()
	cancel()
	if r.startJob(&j, "d", run) {
		t.Fatal("run started after the runtime stopped")
	}
}
