// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestPassProblemLogsChangeRepeatAndRecovery(t *testing.T) {
	var out bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&out)
	log.SetFlags(0)
	defer func() { log.SetOutput(prev); log.SetFlags(flags) }()

	var p passProblem
	start := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	cause := passStep("managed", reconcile.ErrPending)
	p.observe(nil, start)
	p.observe(cause, start)
	p.observe(cause, start.Add(time.Minute))
	p.observe(cause, start.Add(stillFailingEvery))
	p.observe(cause, start.Add(stillFailingEvery+time.Minute))
	p.observe(nil, start.Add(2*stillFailingEvery))
	p.observe(nil, start.Add(3*stillFailingEvery))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 ||
		!strings.HasPrefix(lines[0], "reconciliation failed, retrying: managed: ") ||
		!strings.HasPrefix(lines[1], "reconciliation still failing since 2026-11-27T00:00:00Z (10m0s): managed: ") ||
		lines[2] != "reconciliation recovered after 20m0s" {
		t.Fatalf("log lines:\n%s", out.String())
	}
}

func TestPassStepKeepsCause(t *testing.T) {
	if passStep("x", nil) != nil {
		t.Fatal("nil step error must stay nil")
	}
	err := passStep("system-network", reconcile.ErrPending)
	if !errors.Is(err, reconcile.ErrPending) || !strings.HasPrefix(err.Error(), "system-network: ") {
		t.Fatal(err)
	}
}

func TestFailedStepsNamesOnlySteps(t *testing.T) {
	err := errors.Join(passStep("certificates", errors.New("secret detail")), errors.Join(passStep("node-storage", reconcile.ErrPending), passStep("certificates", errors.New("again"))), errors.New("unnamed"))
	if got := failedSteps(err); !slices.Equal(got, []string{"certificates", "node-storage"}) {
		t.Fatal(got)
	}
	if failedSteps(nil) != nil {
		t.Fatal("nil error has steps")
	}
	// One stopped server: every failure only waits for it.
	wait := func(peer string) error {
		return fmt.Errorf("managed TUN sources: peer 225a0f07: %w", &sfcp.PeerUnreachableError{Peer: peer, Err: errors.New("timeout")})
	}
	if peers, only := waitedPeers(errors.Join(passStep("managed", wait("vps1")), passStep("system-network", wait("vps1")))); !only || !slices.Equal(peers, []string{"vps1"}) {
		t.Fatal("peer wait", peers, only)
	}
	if peers, only := waitedPeers(errors.Join(passStep("managed", wait("vps1")), passStep("node-storage", errors.New("disk")))); only || !slices.Equal(peers, []string{"vps1"}) {
		t.Fatal("own failure hidden behind a peer wait", peers, only)
	}
	if peers, only := waitedPeers(nil); only || peers != nil {
		t.Fatal("nil error waits", peers, only)
	}
	var r Runtime
	now := time.UnixMilli(5000)
	r.setModuleErrorLocked(err, now)
	r.setModuleErrorLocked(err, now.Add(time.Minute))
	if !r.moduleErrorSince.Equal(now) {
		t.Fatal("failing stretch restarted", r.moduleErrorSince)
	}
	r.setModuleErrorLocked(nil, now.Add(2*time.Minute))
	if !r.moduleErrorSince.IsZero() {
		t.Fatal("since kept after recovery")
	}
}
