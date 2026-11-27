// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
)

// ImageSourceNoLongerTrusted is a current diagnostic over accepted work and
// surviving claims, including prune=false orphans from an older execution.
// It never changes health, retires an object or grants permission to execute.
func (a Inventory) ImageSourceNoLongerTrusted(c access.Catalog) bool {
	untrusted := func(step Step) bool {
		if step.Kind != "task" {
			return false
		}
		var service ComposeService
		if json.Unmarshal(step.Goal, &service) != nil {
			return true
		}
		_, err := c.CheckImageTrust(a.d.Tenant, service.Image)
		return err != nil
	}
	if active := a.d.Active; active != nil {
		for _, step := range active.Plan.Steps {
			if untrusted(step) {
				return true
			}
		}
	}
	for _, claim := range a.d.Claims {
		if !claim.Removed && untrusted(claim.Step) {
			return true
		}
	}
	return false
}
