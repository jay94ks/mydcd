// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/userauth"
)

// transient reports a refusal that only means "ask again": no leader yet
// (election), the node is not ready, or a relayed reply was lost. Waiting
// paths retry it; authentication, permission and input refusals stay final.
func transient(err error) bool {
	var remote *userauth.Error
	if !errors.As(err, &remote) {
		return false
	}
	switch remote.Code {
	case "not-leader", "unavailable", "unknown":
		return true
	}
	return false
}

// transientPause is how long a waiting path rests after a transient refusal.
var transientPause = time.Second

// pauseFor waits d, or reports false once ctx ends first.
func pauseFor(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// settleSend sends an operation with first and, while the answer is a
// transient refusal, asks again with again until ctx ends. again must only
// read the saved result or resend the same signed original, which the
// server deduplicates by its ID, so a retry never makes a second change.
func settleSend(ctx context.Context, first, again func() (userauth.Reply, error)) (userauth.Reply, error) {
	reply, err := first()
	for transient(err) && pauseFor(ctx, transientPause) {
		reply, err = again()
	}
	return reply, err
}
