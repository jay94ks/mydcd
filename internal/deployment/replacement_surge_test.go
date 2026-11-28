// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/schema"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// surgeFixture plans the rolling deploy with FeatureTaskSurge. Fresh
// addresses stand in for the planner step that gives a surged Task new ones:
// the original addresses are held by another key.
func surgeFixture(t *testing.T, fresh bool) *inventoryFixture {
	t.Helper()
	return runningReplacementFixtureFor(t, nil, func(ctx *PlanningContext) {
		ctx.Features[FeatureTaskSurge] = true
		if fresh {
			for ip, ref := range ctx.Addresses {
				if strings.Contains(ref.Key, "/web/") {
					ref.Key += "-original"
					ctx.Addresses[ip] = ref
				}
			}
		}
	})
}

func TestSurgeNeedsOwnAddresses(t *testing.T) {
	x := surgeFixture(t, false)
	for _, w := range x.e.d.Replacement.Plan.Waves {
		if w.Surge {
			t.Fatal("surge planned with the original's address")
		}
	}
	if x.e.d.Replacement.Phase != "retiring" {
		t.Fatalf("phase %s", x.e.d.Replacement.Phase)
	}
}

func TestSurgeStartsNewBeforeStoppingOriginal(t *testing.T) {
	x := surgeFixture(t, true)
	r := x.e.d.Replacement
	if r == nil || len(r.Plan.Waves) != 2 || !r.Plan.Waves[0].Surge || !r.Plan.Waves[1].Surge || r.Phase != phaseSurging {
		t.Fatalf("plan %+v", r)
	}
	if _, retiring := x.a.Retirement(); retiring {
		t.Fatal("surge wave stopped the original first")
	}
	first := ResourceKey("task", "tenant", "php-mysql", "web/node-a/r1")
	second := ResourceKey("task", "tenant", "php-mysql", "web/node-b/r1")
	if !x.e.ReplacementAllows(first) || x.e.ReplacementAllows(second) {
		t.Fatal("surge wave allowed the wrong Task")
	}
	if _, ok := x.e.SurgeWindow(first); ok {
		t.Fatal("window open before the new generation ran")
	}
	applyReplacementWave(t, x)
	stage, _ := x.e.Stage(first)
	if stage.Result == nil || stage.Previous == nil || stage.Previous.Removed || stage.Result.Generation <= stage.Previous.Result.Generation {
		t.Fatal("new generation did not start next to the original")
	}
	previous, ok := x.e.SurgeWindow(first)
	if !ok || previous.Generation != stage.Previous.Result.Generation {
		t.Fatal("surge window closed while both run")
	}
	if old, held := x.e.HeldExecutionAt(first, previous.Generation); !held || old.d.Operation != "original" {
		t.Fatal("original recipe lost during surge")
	}
	if _, held := x.e.HeldExecutionAt(first, stage.Result.Generation); held {
		t.Fatal("new generation resolved to the original recipe")
	}
	// An unhealthy new generation keeps the original running.
	x.observe(first, false, false)
	x.sync()
	if x.a.ReplacementReady(x.now) {
		t.Fatal("unhealthy new generation stopped the original")
	}
	x.observe(first, true, false)
	x.sync()
	if !x.a.ReplacementReady(x.now) {
		t.Fatal("healthy new generation did not release the original")
	}
	x.keep(x.a.AdvanceReplacement(x.a.Revision(), x.f.c, x.now))
	x.e, _ = x.a.Execution()
	retirement, retiring := x.a.Retirement()
	if !retiring || x.e.d.Replacement.Phase != "retiring" {
		t.Fatal("originals not stopped after the new generation served")
	}
	for _, target := range retirement.Targets {
		if target.Original.Step.Node != "node-a" {
			t.Fatal("surge stopped another server's original")
		}
	}
	if _, ok := x.e.SurgeWindow(first); !ok {
		t.Fatal("window closed before the original stopped")
	}
	closeSurgeWave(t, x)
	stage, _ = x.e.Stage(first)
	if !stage.Previous.Removed || stage.Observation == nil || !x.a.ReplacementReady(x.now) {
		t.Fatal("closing the original lost the new generation's health")
	}
	if _, ok := x.e.SurgeWindow(first); ok {
		t.Fatal("window open after the original stopped")
	}
	x.keep(x.a.AdvanceReplacement(x.a.Revision(), x.f.c, x.now))
	x.e, _ = x.a.Execution()
	if x.e.d.Replacement.Phase != phaseSurging || x.e.d.Replacement.Wave != 1 {
		t.Fatal("second wave did not surge")
	}
	applyReplacementWave(t, x)
	x.keep(x.a.AdvanceReplacement(x.a.Revision(), x.f.c, x.now))
	x.e, _ = x.a.Execution()
	closeSurgeWave(t, x)
	x.keep(x.a.AdvanceReplacement(x.a.Revision(), x.f.c, x.now))
	x.e, _ = x.a.Execution()
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
	if x.e.Status() != "Succeeded" {
		t.Fatalf("status %s", x.e.Status())
	}
	for _, key := range []string{first, second} {
		s, _ := x.e.Stage(key)
		if s.Result == nil || s.Result.Code != state.Applied {
			t.Fatal("rollout lost a new generation")
		}
		claim := x.a.d.Claims[x.a.claim(key)]
		if claim.Removed || claim.Result != *s.Result {
			t.Fatal("new generation not claimed after the surge")
		}
	}
}

// closeSurgeWave stops a surge wave's originals: each is superseded and
// closes on its owner's Gone signature alone.
func closeSurgeWave(t *testing.T, x *inventoryFixture) {
	t.Helper()
	for attempt := 0; attempt < 64; attempt++ {
		retirement, ok := x.a.Retirement()
		if !ok {
			t.Fatal("no surge retirement")
		}
		pending := false
		for _, target := range retirement.Targets {
			key := target.Original.Step.Key
			if target.Closed {
				continue
			}
			pending = true
			if !target.Superseded || target.Drain != nil {
				t.Fatal("surged original stopped through its object")
			}
			if !x.a.CanRetire(key) {
				continue
			}
			value, ok := x.a.SupersededDrain(key)
			if !ok {
				t.Fatal("no superseded drain value")
			}
			owner := x.f.na
			if target.Original.Step.Owner == public(x.f.nb) {
				owner = x.f.nb
			}
			if _, err := x.a.SupersededGone(x.a.Revision(), key, ed25519.Sign(owner, schema.GoneBytes(x.f.cluster, key, target.Original.Result.Generation+1, value))); err == nil {
				t.Fatal("Gone for another generation closed the original")
			}
			x.keep(x.a.SupersededGone(x.a.Revision(), key, ed25519.Sign(owner, schema.GoneBytes(x.f.cluster, key, target.Original.Result.Generation, value))))
		}
		if !pending {
			x.keep(x.a.FinishRetirement(x.a.Revision()))
			x.e, _ = x.a.Execution()
			return
		}
	}
	t.Fatal("surge wave did not close")
}
