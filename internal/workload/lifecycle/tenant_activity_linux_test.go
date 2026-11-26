// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"context"
	"testing"
)

func TestTenantCompilerCensusPreservesOtherTenantJobs(t *testing.T) {
	owner := &CompilerOwner{known: map[string]bool{compilerRecordPrefix + "first/job": true, compilerRecordPrefix + "other/job": true}, active: map[string]context.CancelFunc{"other/job": func() {}}}
	first, err := owner.TenantActivity("first")
	if err != nil || first.CDJobs != 1 {
		t.Fatal(first, err)
	}
	absent, err := owner.TenantActivity("absent")
	if err != nil || !absent.Empty() {
		t.Fatal("foreign build entered tenant census", absent, err)
	}
	all, err := owner.Activity()
	if err != nil || all.CDJobs != 3 {
		t.Fatal("node census lost original build", all, err)
	}
	owner.uncertain = true
	if _, err := owner.TenantActivity("absent"); err == nil {
		t.Fatal("uncertain native build became positive closure")
	}
}
