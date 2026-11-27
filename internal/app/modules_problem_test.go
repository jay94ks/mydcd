// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/reconcile"
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
