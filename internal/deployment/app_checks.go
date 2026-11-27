// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"math"
	"slices"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// AppCheckResult gates the application, not any service's Healthy/activation.
// ValidUntil is the earliest required pass expiry or the last confirmed fail
// expiry, in Unix milliseconds.
// Zero is allowed for unknown or an already passed startup-only program.
type AppCheckResult struct {
	Program    [32]byte
	Status     contract.Status
	ValidUntil int64
}

func (e Execution) appCheckCoordinator() (string, bool, bool, int64) {
	if e.d.Plan.Checkers == nil {
		return "", false, false, 0
	}
	active, sticky, maxFresh := false, true, int64(0)
	for _, check := range e.d.Plan.Checkers.Program.Checks {
		if check.Phase == contract.Shutdown {
			continue
		}
		active = true
		sticky = sticky && check.Phase == contract.Startup
		maxFresh = max(maxFresh, check.Timing.FreshForMS)
	}
	if !active {
		return "", false, false, 0
	}
	var services []string
	for name := range e.d.Plan.Checkers.Program.Services {
		services = append(services, name)
	}
	slices.Sort(services)
	if len(services) == 0 {
		return "", true, sticky, maxFresh
	}
	instances, err := (Blueprint{e.d.Plan}).ServiceInstances(services[0])
	if err != nil || len(instances) == 0 {
		return "", true, sticky, maxFresh
	}
	return ResourceKey("task", e.d.Plan.Tenant, e.d.Plan.App, instances[0].ResourceID()), true, sticky, maxFresh
}

// AppCheckTask fixes the existing one app-scope coordinator to one concrete
// Task. Per-container checks continue to execute for every replica.
func (e Execution) AppCheckTask() (string, bool) {
	key, required, _, _ := e.appCheckCoordinator()
	return key, required
}

func (e Execution) validAppChecks(i int, o Observation) bool {
	if o.AppChecks == nil {
		return true
	} // initial service reports may precede app checks
	key, required, sticky, maxFresh := e.appCheckCoordinator()
	p := o.AppChecks
	if !required || e.d.Plan.Steps[i].Kind != "task" || o.Key != key || p.Program != e.d.Plan.Checkers.Digest() {
		return false
	}
	if p.Status == contract.Unknown {
		return p.ValidUntil == 0
	}
	if p.Status != contract.Pass && p.Status != contract.Fail {
		return false
	}
	if p.ValidUntil == 0 {
		return sticky && p.Status == contract.Pass
	}
	if o.At > uint64((math.MaxInt64-1000)/1000) {
		return false
	}
	at := int64(o.At) * 1000
	return p.ValidUntil > at && maxFresh > 0 && p.ValidUntil-at-1000 <= maxFresh
}

func (e Execution) appCheckOutcome(o *Observation, now uint64) contract.Status {
	_, required, _, _ := e.appCheckCoordinator()
	if !required {
		return contract.Pass
	}
	if o == nil || o.AppChecks == nil || o.Released || !o.Applied || !o.Live(now) {
		return contract.Unknown
	}
	p := o.AppChecks
	if p.Status == contract.Unknown {
		return contract.Unknown
	}
	// Shared timestamps are seconds. Require validity through this second
	// rather than extending a millisecond expiry by truncating current time.
	if p.ValidUntil != 0 && (now > uint64((math.MaxInt64-1000)/1000) || p.ValidUntil <= (int64(now)+1)*1000) {
		return contract.Unknown
	}
	return p.Status
}

func (e Execution) appChecksStatus(now uint64) contract.Status {
	key, required, _, _ := e.appCheckCoordinator()
	if !required {
		return contract.Pass
	}
	i := e.index(key)
	if i < 0 {
		return contract.Unknown
	}
	return e.appCheckOutcome(e.d.Stages[i].Observation, now)
}
