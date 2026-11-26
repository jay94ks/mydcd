// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"errors"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

// The original signed coordinates and committed receipt describe one outcome.
// A newer extension or a pin must not change an earlier result, and an unknown
// submission must never render its proposed expiry as an accepted expiry.
func addStandaloneExtensionOutcome(reply *Reply, op control.UserOperation) {
	if op.Change.Action != "standalone-extend" || !reply.Found || reply.Result == nil {
		return
	}
	plan, err := control.StandaloneExtensionResult(op)
	if errors.Is(err, access.ErrInvalid) {
		return
	}
	reply.StandaloneExtension = &plan
	if reply.Result.Code != state.Applied && err != nil {
		if errors.Is(err, control.ErrStandaloneExtensionLimit) || errors.Is(err, control.ErrStandaloneExtensionExpired) || errors.Is(err, control.ErrStandaloneExtensionNotIncreased) {
			reply.StandaloneExtensionCode = err.Error()
		}
	}
}
