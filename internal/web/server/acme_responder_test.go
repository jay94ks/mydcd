// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/web/mydc"
)

func TestACMEResponderIsFilledOnceByTheAutomationAccount(t *testing.T) {
	f, _, _, fake := acmeFixture(t)
	makeAutomation(t, f, "mydc-web", "a1b2c3d4-0000-4000-8000-0000000000d1", true, true)
	f.srv.opt.ACMEHTTP01, f.srv.opt.ACMEAdvertise = true, "[::ffff:10.0.0.5]:8402"

	code, out := f.do("GET", "/api/v1/acme/responder", nil)
	if code != 200 || out["listening"] != true || out["advertised"] != "10.0.0.5:8402" || out["address"] != nil {
		t.Fatalf("before: %d %v", code, out)
	}
	ws, err := f.srv.watchSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.srv.acmeResponderSync(t.Context(), ws)
	code, out = f.do("GET", "/api/v1/acme/responder", nil)
	if code != 200 || out["address"] != "10.0.0.5:8402" || out["setBy"] != "u-mydc-web" || out["setAt"] == nil {
		t.Fatalf("after: %d %v", code, out)
	}
	f.srv.acmeResponder.tried = f.srv.acmeResponder.tried.AddDate(0, 0, -1)
	f.srv.acmeResponderSync(t.Context(), ws)
	if n := journalCount(fake, mydc.ActionSetACMEResponder); n != 1 {
		t.Fatalf("set %d times", n)
	}
}

func TestACMEResponderWithoutAnAdvertisedAddressSendsNothing(t *testing.T) {
	f, _, _, fake := acmeFixture(t)
	makeAutomation(t, f, "mydc-web", "a1b2c3d4-0000-4000-8000-0000000000d2", true, true)
	f.srv.opt.ACMEAdvertise = "0.0.0.0:80"
	ws, err := f.srv.watchSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.srv.acmeResponderSync(t.Context(), ws)
	if n := journalCount(fake, mydc.ActionSetACMEResponder); n != 0 {
		t.Fatalf("set %d times", n)
	}
	if code, out := f.do("GET", "/api/v1/acme/responder", nil); code != 200 || out["listening"] != false || out["advertised"] != nil {
		t.Fatalf("%d %v", code, out)
	}
}
