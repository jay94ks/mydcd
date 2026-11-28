// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/deployment"
)

// A plan diff comes as rows with sfcd's interruption code, and as the
// text lines it always had.
func TestPlanChanges(t *testing.T) {
	rows, text := planChanges([]deployment.Change{
		{Key: "task/web/1", Action: "Replace", Reason: "config", Interruption: deployment.InterruptVolumeWriter},
		{Key: "task/api/1", Action: "Create"},
	})
	if got := fmt.Sprint(rows); got != "[{Replace task/web/1 config VOLUME_WRITER} {Create task/api/1  }]" {
		t.Fatal(got)
	}
	if text != "Replace task/web/1 (config)\nCreate task/api/1\n" {
		t.Fatal(text)
	}
	if rows, _ := planChanges(nil); rows == nil || len(rows) != 0 {
		t.Fatal("empty diff should be [] rows")
	}
}
