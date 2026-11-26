// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// ExplainAppFinish replays the finish branch of reduceAppProgress on s and
// names the check that refuses r, or "" when it applies. Local diagnostics
// only: it reads s and never changes it.
func (p Policy) ExplainAppFinish(s state.State, r AppProgress) string {
	a, err := p.Apps(s)
	if err != nil {
		return "APPS_UNREADABLE"
	}
	entry, ok := a.entries[appKey(r.Tenant, r.App)]
	switch {
	case !ok:
		return "APP_MISSING"
	case entry.Inventory.Revision() != r.Expected:
		return "INVENTORY_REVISION"
	}
	e, ok := entry.Inventory.Execution()
	switch {
	case !ok:
		return "NO_EXECUTION"
	case e.ActiveOperation() != r.Operation:
		return "OPERATION"
	case r.At < uint64(entry.Origin.At):
		return "CLOCK_BEFORE_ORIGIN"
	}
	e, err = e.Finish(e.Revision(), r.At)
	if err != nil {
		return "FINISH_" + inputCode(err)
	}
	if _, err = p.Volumes(s); err != nil {
		return "VOLUMES_UNREADABLE"
	}
	if _, err = p.advanceAppInventory(s, entry.Inventory, e); err != nil {
		if code := inputCode(err); strings.HasPrefix(code, "ADVANCE_") {
			return code
		}
		return "ADVANCE_" + inputCode(err)
	}
	return ""
}

// inputCode is a deployment input error's fixed code, or "REFUSED".
func inputCode(err error) string {
	var input *deployment.InputError
	if errors.As(err, &input) {
		return input.Code
	}
	return "REFUSED"
}
