// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// Model only the timer-publication race. The production waiter still decides
// using its own actual deadline; no fake clock enters the product algorithm.
type waitDeadlineBeforeContextTimer struct {
	context.Context
	deadline time.Time
}

func (c waitDeadlineBeforeContextTimer) Deadline() (time.Time, bool) { return c.deadline, true }

func TestComposeWaitOwnIODeadlineDoesNotRetryOrHideOtherFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ctx   context.Context
		err   error
		ended bool
		code  int
	}{
		{"socket-wakes-first", waitDeadlineBeforeContextTimer{context.Background(), time.Now().Add(-time.Minute)}, &userauth.Error{Code: "transport", Phase: sfcp.Unknown, Cause: os.ErrDeadlineExceeded}, true, 4},
		{"context-child-deadline", waitDeadlineBeforeContextTimer{context.Background(), time.Now().Add(-time.Minute)}, &userauth.Error{Code: "transport", Phase: sfcp.Unknown, Cause: context.DeadlineExceeded}, true, 4},
		{"earlier-io-deadline", waitDeadlineBeforeContextTimer{context.Background(), time.Now().Add(time.Hour)}, &userauth.Error{Code: "transport", Phase: sfcp.Unknown, Cause: os.ErrDeadlineExceeded}, false, 4},
		{"unbounded-io-deadline", context.Background(), &userauth.Error{Code: "transport", Phase: sfcp.Unknown, Cause: os.ErrDeadlineExceeded}, false, 4},
		{"late-frame-error", waitDeadlineBeforeContextTimer{context.Background(), time.Now().Add(-time.Minute)}, &userauth.Error{Code: "transport", Phase: sfcp.Unknown, Cause: sfcp.ErrFrame}, false, 4},
		{"late-authorization-denied", waitDeadlineBeforeContextTimer{context.Background(), time.Now().Add(-time.Minute)}, &userauth.Error{Code: "denied", Phase: sfcp.Completed, Cause: errors.New("refused")}, false, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, err := parseComposeOptions([]string{"wait", "-p", "app", "--operation", "original"}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			var out, diagnostic bytes.Buffer
			calls := 0
			code := waitComposeOperation(tc.ctx, o, "tenant", func(context.Context) (control.AppView, bool, error) {
				calls++
				return control.AppView{}, false, tc.err
			}, &out, &diagnostic)
			if code != tc.code || calls != 1 || strings.Contains(diagnostic.String(), "deadline/cancellation") != tc.ended {
				t.Fatal("wait retried or reclassified a different failure", code, calls, diagnostic.String())
			}
			if tc.ended {
				if !strings.Contains(out.String(), `"Operation":"original"`) || !strings.Contains(out.String(), `"Complete":false`) {
					t.Fatal("deadline lost the original incomplete operation", out.String())
				}
			} else if out.Len() != 0 {
				t.Fatal("terminal rejection was published as an incomplete deadline", out.String())
			}
		})
	}
}

func TestComposeWaitSlowReadKeepsPostReadPause(t *testing.T) {
	for _, transient := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "unavailable"}[transient], func(t *testing.T) {
			o, err := parseComposeOptions([]string{"wait", "-p", "app", "--operation", "original"}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			calls := 0
			var completed time.Time
			observe := func(context.Context) (control.AppView, bool, error) {
				calls++
				if calls == 1 {
					time.Sleep(300 * time.Millisecond)
					completed = time.Now()
					if transient {
						return control.AppView{}, false, &userauth.Error{Code: "unavailable"}
					}
					return control.AppView{Operation: deployment.OperationSummary{ID: "original", Status: "Planned"}}, true, nil
				}
				if gap := time.Since(completed); gap < 240*time.Millisecond {
					t.Fatalf("slow read triggered immediate catch-up query: %v", gap)
				}
				return control.AppView{Operation: deployment.OperationSummary{ID: "original", Status: "Succeeded"}, Health: "Healthy", ObservedAt: 1, ObservationMaxAge: control.AppObservationMaxAge}, true, nil
			}
			if code := waitComposeOperation(ctx, o, "tenant", observe, io.Discard, io.Discard); code != 0 || calls != 2 {
				t.Fatal("original operation observation", code, calls)
			}
		})
	}
}

func TestComposeWaitCancellationDoesNotReadAgain(t *testing.T) {
	o, err := parseComposeOptions([]string{"wait", "-p", "app", "--operation", "original"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	observe := func(context.Context) (control.AppView, bool, error) {
		calls++
		cancel()
		return control.AppView{Operation: deployment.OperationSummary{ID: "original", Status: "Planned"}}, true, nil
	}
	if code := waitComposeOperation(ctx, o, "tenant", observe, io.Discard, io.Discard); code != 4 || calls != 1 {
		t.Fatal("cancelled wait polled again or changed completion", code, calls)
	}
}

func TestComposeWaitFollowsAcceptedCDTransitionToOriginalHealthyOperation(t *testing.T) {
	o, err := parseComposeOptions([]string{"wait", "-p", "app", "--operation", "next"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	calls := 0
	observe := func(context.Context) (control.AppView, bool, error) {
		calls++
		row := control.AppView{Operation: deployment.OperationSummary{ID: "previous", Status: "Stopping"}}
		if calls <= 2 {
			phase := "retiring"
			if calls == 2 {
				phase = "ready"
				row.Operation.Status = "Closed"
			}
			row.CD = &control.AppCDView{Transition: &deployment.DeliveryTransition{Mode: deployment.DeliveryUpdate, Phase: phase, Selection: deployment.DeliverySelection{Operation: "next"}}}
			row.Retirement = &control.AppRetirementStatus{ID: "next", Status: "Retiring"}
		} else {
			row.Operation = deployment.OperationSummary{ID: "next", Status: "Succeeded"}
			row.Health = "Healthy"
			row.ObservedAt = 1
			row.ObservationMaxAge = control.AppObservationMaxAge
		}
		return row, true, nil
	}
	if code := waitComposeOperation(ctx, o, "tenant", observe, io.Discard, io.Discard); code != 0 || calls != 3 {
		t.Fatal("accepted CD transition was not followed read-only", code, calls)
	}
}

func TestComposeWaitRejectsUnselectedOrForeignCDOperations(t *testing.T) {
	for _, mode := range []string{"candidate-only", "foreign-operation", "down", "foreign-retirement"} {
		t.Run(mode, func(t *testing.T) {
			o, _ := parseComposeOptions([]string{"wait", "-p", "app", "--operation", "next"}, io.Discard)
			row := control.AppView{Operation: deployment.OperationSummary{ID: "previous", Status: "Succeeded"}, CD: &control.AppCDView{Transition: &deployment.DeliveryTransition{Mode: deployment.DeliveryUpdate, Phase: "retiring", Selection: deployment.DeliverySelection{Operation: "next"}}}}
			switch mode {
			case "candidate-only":
				row.CD.Transition = nil
				row.CD.Candidate = &deployment.DeliverySelection{Operation: "next"}
			case "foreign-operation":
				row.CD.Transition.Selection.Operation = "other"
			case "down":
				row.CD.Transition.Mode = deployment.DeliveryDown
			case "foreign-retirement":
				row.Retirement = &control.AppRetirementStatus{ID: "other", Status: "Retiring"}
			}
			calls := 0
			if code := waitComposeOperation(context.Background(), o, "tenant", func(context.Context) (control.AppView, bool, error) { calls++; return row, true, nil }, io.Discard, io.Discard); code != 4 || calls != 1 {
				t.Fatal("wait adopted non-current CD work", code, calls)
			}
		})
	}
}

// A same-yaml redeploy that replaces containers retires the old ones in a
// wave of its own execution first; wait follows it to Healthy instead of
// calling the operation inactive.
func TestComposeWaitFollowsReplacementWaveOfItsOwnOperation(t *testing.T) {
	o, err := parseComposeOptions([]string{"wait", "-p", "app", "--operation", "next"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	calls := 0
	observe := func(context.Context) (control.AppView, bool, error) {
		calls++
		row := control.AppView{Operation: deployment.OperationSummary{ID: "next", Status: "Running"}}
		if calls <= 2 {
			row.Replacement = &deployment.ReplacementProgress{Wave: 1, Waves: 1, Node: "jay2", Phase: "retiring"}
			row.Retirement = &control.AppRetirementStatus{ID: "roll-1", Status: "Retiring"}
		} else {
			row.Operation.Status = "Succeeded"
			row.Health = "Healthy"
			row.ObservedAt = 1
			row.ObservationMaxAge = control.AppObservationMaxAge
		}
		return row, true, nil
	}
	if code := waitComposeOperation(ctx, o, "tenant", observe, io.Discard, io.Discard); code != 0 || calls != 3 {
		t.Fatal("replacement wave was not followed", code, calls)
	}
	// Another operation's wave is still not this one.
	other := func(context.Context) (control.AppView, bool, error) {
		return control.AppView{Operation: deployment.OperationSummary{ID: "previous", Status: "Running"}, Replacement: &deployment.ReplacementProgress{Wave: 1, Waves: 1}, Retirement: &control.AppRetirementStatus{ID: "roll-1", Status: "Retiring"}}, true, nil
	}
	if code := waitComposeOperation(ctx, o, "tenant", other, io.Discard, io.Discard); code != 4 {
		t.Fatal("foreign replacement wave followed", code)
	}
}
