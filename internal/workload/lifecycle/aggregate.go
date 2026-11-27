// SPDX-License-Identifier: Apache-2.0

package lifecycle

import contract "github.com/jay94ks/seafield/lifecycle/v1"

type Sample struct {
	Checker string
	Phase   contract.Phase
	Status  contract.Status
}

// Aggregate combines only current binding observations supplied by the owner.
// Empty checker sets impose no extra gate; this pass is never native Ready or
// a shutdown/clean-exit/fence proof. The workload still checks those separately.
func Aggregate(phase contract.Phase, samples []Sample) (contract.Status, error) {
	if !validPhase(phase) || len(samples) > 256 {
		return contract.Unknown, ErrContract
	}
	seen := map[string]bool{}
	startup, selected := contract.Pass, contract.Pass
	combine := func(a, b contract.Status) contract.Status {
		if a == contract.Fail || b == contract.Fail {
			return contract.Fail
		}
		if a == contract.Unknown || b == contract.Unknown {
			return contract.Unknown
		}
		return contract.Pass
	}
	for _, s := range samples {
		if !name(s.Checker) || !validPhase(s.Phase) || !validStatus(s.Status) || seen[s.Checker] {
			return contract.Unknown, ErrContract
		}
		seen[s.Checker] = true
		if s.Phase == contract.Startup {
			startup = combine(startup, s.Status)
		}
		if s.Phase == phase {
			selected = combine(selected, s.Status)
		}
	}
	if phase == contract.Readiness || phase == contract.Liveness {
		return combine(startup, selected), nil
	}
	return selected, nil
}
