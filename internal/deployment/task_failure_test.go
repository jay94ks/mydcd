// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/workload"
)

func TestTaskPreparationFailureEndsTheDeployment(t *testing.T) {
	if PreparationFailure(fmt.Errorf("resolve: %w", workload.ErrProcessUser)) != FailureProcessUser || PreparationFailure(workload.ErrProcess) != FailureProcessInvalid || PreparationFailure(errors.New("UNAVAILABLE")) != "" || PreparationFailure(nil) != "" {
		t.Fatal("permanent preparation errors are not named")
	}
	x := runFixture(t)
	db := ResourceKey("task", "tenant", "php-mysql", "db")
	x.before(db)
	x.prepare(db)
	cmd := x.send(db)
	x.save(x.e.Commit(x.e.Revision(), db, cmd, x.apply(cmd)))
	if x.e.Status() != "Verifying" && x.e.Status() != "Applying" {
		t.Fatal("fixture status", x.e.Status())
	}
	failure := func(change func(*Observation)) Observation {
		o := x.observation(db, false, false)
		o.Native, o.Applied, o.Failure = NeverObservedNative, false, FailureProcessUser
		change(&o)
		return signCompletion(x, o)
	}
	for _, change := range []func(*Observation){
		func(o *Observation) { o.Failure = "SOMETHING" },
		func(o *Observation) { o.Native = "container" },
		func(o *Observation) { o.Applied = true },
		func(o *Observation) { o.StartedAt = 1 },
	} {
		if _, err := x.e.Observe(x.e.Revision(), failure(change), x.now); err == nil {
			t.Fatal("a malformed failure fact was accepted")
		}
	}
	x.save(x.e.Observe(x.e.Revision(), failure(func(*Observation) {}), x.now))
	if x.e.Status() != "Failed" || !summarize(x.e, x.e.Status()).Failed {
		t.Fatal("a failed Task left the deployment", x.e.Status())
	}
	if got := x.e.Failures(8); len(got) != 1 || !strings.Contains(got[0], db) || !strings.Contains(got[0], "non-zero UID:GID") {
		t.Fatal("failure text", got)
	}
	// The failure is final: it cannot turn into a running container.
	if _, err := x.e.Observe(x.e.Revision(), signCompletion(x, x.observation(db, true, false)), x.now); err == nil {
		t.Fatal("a failed Task became running")
	}
	if _, err := x.e.Finish(x.e.Revision(), x.now); err == nil {
		t.Fatal("a failed deployment finished")
	}
	// Stop still closes it: the owner reports the never-created container gone.
	x.save(x.e.stop(x.e.Revision(), true))
	released := x.observation(db, false, true)
	released.Native = NeverObservedNative
	x.save(x.e.Observe(x.e.Revision(), signCompletion(x, released), x.now))
}
