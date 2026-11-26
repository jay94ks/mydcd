// SPDX-License-Identifier: Apache-2.0

package control

import "testing"

func TestExplainAppFinishNamesAMissingApp(t *testing.T) {
	f := newBackupCore(t)
	if got := f.p.ExplainAppFinish(f.s, AppProgress{Tenant: "tenant", App: "absent", Action: "finish", Expected: 1, At: 2}); got != "APP_MISSING" {
		t.Fatal(got)
	}
}
