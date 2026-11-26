// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

func TestTenantRetirement(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	const opT, opB, opB2, opF0, opF = "d1b2c3d4-0000-4000-8000-000000000001", "d1b2c3d4-0000-4000-8000-000000000002",
		"d1b2c3d4-0000-4000-8000-000000000003", "d1b2c3d4-0000-4000-8000-000000000004", "d1b2c3d4-0000-4000-8000-000000000005"
	// an empty workspace to retire
	code, out := f.do("POST", "/api/v1/ops", map[string]any{"opId": opT, "action": mydc.ActionCreateTenant, "principal": "u-admin", "expected": 0,
		"payload": map[string]any{"ID": "old"}})
	if opState(t, code, out) != "applied" {
		t.Fatalf("create tenant: %d %v", code, out)
	}
	status := func(tenant string) map[string]any {
		t.Helper()
		code, out := f.do("GET", "/api/v1/tenants/"+tenant+"/retirement", nil)
		if code != 200 {
			t.Fatalf("status: %d %v", code, out)
		}
		return out
	}
	st := status("old")
	if st["phase"] != "active" || st["operation"] != "" || st["ready"] != false {
		t.Fatalf("active: %v", st)
	}
	// finish before begin: nothing to finish
	if code, out := f.do("POST", "/api/v1/tenants/old/retire/finish", map[string]any{"opId": opF0, "expected": st["revision"]}); code != 409 || errCode(out) != "not-retiring" {
		t.Fatalf("finish early: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/tenants/old/retire", map[string]any{"opId": opB, "expected": st["revision"]})
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "begin-tenant-retirement" {
		t.Fatalf("begin: %d %v", code, out)
	}
	var sel control.TenantRetirementSelection
	userPayload(t, f, "u-admin", opB, &sel)
	if sel != (control.TenantRetirementSelection{Tenant: "old", Operation: "retire-" + opB}) {
		t.Fatalf("payload: %+v", sel)
	}
	st = status("old")
	if st["phase"] != "retiring" || st["operation"] != "retire-"+opB || st["ready"] != true {
		t.Fatalf("retiring: %v", st)
	}
	// begin again fails (already retiring)
	if code, out := f.do("POST", "/api/v1/tenants/old/retire", map[string]any{"opId": opB2, "expected": st["revision"]}); opState(t, code, out) != "failed" {
		t.Fatalf("begin twice: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/tenants/old/retire/finish", map[string]any{"opId": opF, "expected": st["revision"]})
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "finish-tenant-retirement" {
		t.Fatalf("finish: %d %v", code, out)
	}
	userPayload(t, f, "u-admin", opF, &sel)
	if sel.Operation != "retire-"+opB {
		t.Fatalf("finish payload: %+v", sel)
	}
	if st = status("old"); st["phase"] != "deleted" || st["ready"] != false {
		t.Fatalf("deleted: %v", st)
	}

	// a workspace with apps and volumes is not ready
	shop := status("shop")
	opS := "d1b2c3d4-0000-4000-8000-000000000006"
	if code, out := f.do("POST", "/api/v1/tenants/shop/retire", map[string]any{"opId": opS, "expected": shop["revision"]}); opState(t, code, out) != "applied" {
		t.Fatalf("begin shop: %d %v", code, out)
	}
	if shop = status("shop"); shop["ready"] != false || shop["remainingCount"].(float64) == 0 {
		t.Fatalf("shop: %v", shop)
	}
	opS2 := "d1b2c3d4-0000-4000-8000-000000000007"
	if code, out := f.do("POST", "/api/v1/tenants/shop/retire/finish", map[string]any{"opId": opS2, "expected": shop["revision"]}); opState(t, code, out) != "failed" {
		t.Fatalf("finish shop: %d %v", code, out)
	}
}
