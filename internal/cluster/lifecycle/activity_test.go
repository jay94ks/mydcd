// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"math"
	"testing"
)

func TestActivityMergeNeverTurnsUnknownOrOverflowIntoEmpty(t *testing.T) {
	for _, activity := range []Activity{{Resources: 1}, {Flows: 1}, {Writers: 1}, {Leases: 1}, {CDJobs: 1}} {
		merged, err := (Activity{}).Add(activity)
		if err != nil || merged.Empty() || merged != activity {
			t.Fatal("outstanding activity erased", merged, err)
		}
	}
	before := Activity{Resources: math.MaxUint32, Leases: 7}
	after, err := before.Add(Activity{Resources: 1})
	if err == nil || before != after {
		t.Fatal("overflow changed original observation")
	}
}
