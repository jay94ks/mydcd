// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// Waiting observes the original operation. It never submits or resumes effects.
func runComposeWait(ctx context.Context, o composeOptions, tenant string, c userauth.Client, target sfcp.Peer, stored userauth.Stored, out, diagnostic io.Writer) int {
	return waitComposeOperation(ctx, o, tenant, func(ctx context.Context) (control.AppView, bool, error) {
		return composeInventory(ctx, c, target, stored, tenant, o.project.value)
	}, out, diagnostic)
}

func waitComposeOperation(ctx context.Context, o composeOptions, tenant string, observe func(context.Context) (control.AppView, bool, error), out, diagnostic io.Writer) int {
	condition := o.condition.value
	if condition == "" {
		condition = "healthy"
	}
	// Each delay begins AFTER the completed read. A periodic ticker can retain
	// an elapsed tick during slow quorum IO and turn waiting into back-to-back
	// reads, competing with the original operation's reconciliation.
	pause := func() bool {
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	var last *control.AppView
	finish := func(complete bool) int {
		code := userOutput(out, diagnostic, struct {
			Schema                            uint8
			Tenant, App, Operation, Condition string
			Complete                          bool
			Observed                          *control.AppView
		}{1, tenant, o.project.value, o.operation.value, condition, complete, last})
		if code != 0 || complete {
			return code
		}
		return failure(diagnostic, errors.New("wait deadline/cancellation; original operation and effects are unchanged"), 4)
	}
	for {
		row, exists, err := observe(ctx)
		if err != nil {
			deadline, bounded := ctx.Deadline()
			// The socket deadline and context timer have independent wakeups.
			// IO may report this exact deadline before ctx.Err is published.
			// Finish the same bounded wait; never retry an earlier IO timeout or
			// reclassify a frame/authentication refusal as a deadline.
			ownIODeadline := bounded && !time.Now().Before(deadline) &&
				(errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded))
			if ctx.Err() != nil || ownIODeadline {
				return finish(false)
			}
			if !transient(err) {
				return userFailure(diagnostic, err)
			}
			// This command is read-only. Observe the same original operation through
			// a transient election or lost relayed query response, within the caller's
			// unchanged finite deadline. Unknown here belongs to the AppPage read,
			// never to a mutation result or an authorization decision.
			// Authentication/authorization errors are terminal; never re-login or
			// submit/resume the operation from this polling path.
			if !pause() {
				return finish(false)
			}
			continue
		}
		if !exists {
			return failure(diagnostic, errors.New("app not found; wait does not create or resubmit it"), 4)
		}
		last = &row
		if condition == "retired" {
			if row.Retirement == nil || row.Retirement.ID != o.operation.value {
				return failure(diagnostic, errors.New("original retirement operation is not current"), 4)
			}
			if row.Retirement.Status == "Retired" {
				return finish(true)
			}
		} else {
			if row.Operation.ID != o.operation.value || row.Retirement != nil {
				if pendingComposeDelivery(row, o.operation.value) {
					if !pause() {
						return finish(false)
					}
					continue
				}
				return failure(diagnostic, errors.New("original deployment operation is not active"), 4)
			}
			if row.Operation.Failed || row.Operation.Status == "Failed" || row.Operation.Status == "Closed" || row.Operation.Status == "Stopping" {
				return failure(diagnostic, fmt.Errorf("original deployment is %s", row.Operation.Status), 4)
			}
			if row.Operation.Status == "Succeeded" && row.Health == "Healthy" && row.ObservedAt > 0 && row.ObservationMaxAge == control.AppObservationMaxAge {
				return finish(true)
			}
		}
		if !pause() {
			return finish(false)
		}
	}
}

// Only an accepted current transition selects a future execution. A queued
// candidate or another retirement never authorizes waiting for this ID.
func pendingComposeDelivery(row control.AppView, operation string) bool {
	if row.CD == nil || row.CD.Transition == nil {
		return false
	}
	t := row.CD.Transition
	return t.Selection.Operation == operation && (t.Mode == deployment.DeliveryUpdate || t.Mode == deployment.DeliveryRecover) &&
		(t.Phase == "retiring" || t.Phase == "ready" || t.Phase == "applying") && (row.Retirement == nil || row.Retirement.ID == operation)
}
