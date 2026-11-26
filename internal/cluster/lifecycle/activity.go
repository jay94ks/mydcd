// SPDX-License-Identifier: Apache-2.0

package lifecycle

import "math"

// Activity counts outstanding owned effects/references, not configured disks,
// cached bytes or elapsed time. Neither an empty shared view nor an empty local
// view alone is closure; the adapter must combine both and observe native IO.
type Activity struct {
	Resources, Flows, Writers, Leases, CDJobs uint32
}

func (a Activity) Empty() bool { return a.Resources|a.Flows|a.Writers|a.Leases|a.CDJobs == 0 }
func (a Activity) Add(b Activity) (Activity, error) {
	result := a
	for _, pair := range []struct {
		target *uint32
		value  uint32
	}{
		{&result.Resources, b.Resources}, {&result.Flows, b.Flows}, {&result.Writers, b.Writers}, {&result.Leases, b.Leases}, {&result.CDJobs, b.CDJobs},
	} {
		if uint64(*pair.target)+uint64(pair.value) > math.MaxUint32 {
			return a, ErrLifecycle
		}
		*pair.target += pair.value
	}
	return result, nil
}
