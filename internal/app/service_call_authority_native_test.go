// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/servicecall"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/tests/gitfixture"
)

// Called only by the original service diagnostics native root, after its real
// CD pause/source-read join. Existing owner leases and Git counters distinguish
// admission refusal from a request that reached the native/source adapters.
func verifyManagedDiagnosticsAuthority(t *testing.T, ctx context.Context, r *Runtime, user userauth.Client, peer sfcp.Peer, p control.Policy, read func() cluster.View, wait func(string, func() bool), change func(string, string, uint64, any), source *gitfixture.Fixture, probe deployment.GitProbeRequest, call servicecall.Request, body, commit string, size int64, fingerprint func() [32]byte) {
	t.Helper()
	baseline := fingerprint()
	create := func(id string) (access.Session, *identity.Identity) {
		t.Helper()
		key, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		change(id+"-user", "put-user", 0, access.User{ID: id, Username: id, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}}})
		change(id+"-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: id, Role: access.Manager, Enabled: true})
		session, err := user.Login(ctx, peer, id, key.Private)
		if err != nil {
			clear(key.Private)
			t.Fatal("actual diagnostics account login", err)
		}
		return session, key
	}
	operator, operatorKey := create("rq8-operator")
	defer clear(operatorKey.Private)
	change("rq8-foreign-tenant", "create-tenant", 0, control.TenantID{ID: "rq8-other"})
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	nativeReads := func() uint64 {
		t.Helper()
		row, err := r.workload.View(key)
		if err != nil || row.Pins == nil {
			t.Fatal("original Task native reader census", err)
		}
		for consumer := range row.Consumers {
			if strings.HasPrefix(consumer, "service-call/") {
				t.Fatal("completed service call retained native reader")
			}
		}
		return row.Pins.Next
	}
	unchanged := func() {
		t.Helper()
		if fingerprint() != baseline {
			t.Fatal("diagnostic changed original CD source/candidate/selection/plan/Binding/Task/native")
		}
	}
	positiveCall := func(session access.Session) {
		t.Helper()
		before := nativeReads()
		result, err := user.CallService(ctx, peer, session, "tenant", call)
		if err != nil || result.Code != "" || result.Status != 200 || string(result.Body) != body || result.Task == "" {
			t.Fatal("current Manager service-call success precondition", result, err)
		}
		if nativeReads() <= before {
			t.Fatal("successful service call did not enter original native read lease")
		}
		unchanged()
	}
	positiveProbe := func(session access.Session) {
		t.Helper()
		before := source.Stats()
		result, err := user.ProbeCD(ctx, peer, session, "tenant", probe)
		if err != nil || !result.Valid() || result.Code != "" || result.Commit != commit || result.Size != size {
			t.Fatal("current Deploy Git probe success precondition", result, err)
		}
		after := source.Stats()
		if after.Advertisements <= before.Advertisements || after.Packs <= before.Packs {
			t.Fatal("successful Git probe did not reach original HTTPS source")
		}
		unchanged()
	}
	denied := func(tenant string, session access.Session) {
		t.Helper()
		beforeNative, beforeGit := nativeReads(), source.Stats()
		service, err := user.CallService(ctx, peer, session, tenant, call)
		var refused *userauth.Error
		if !errors.As(err, &refused) || refused.Code != "denied" || refused.Phase != sfcp.Completed || len(service.Body) != 0 || service.Task != "" {
			t.Fatal("service authority refusal was not an authenticated server denial", err)
		}
		result, err := user.ProbeCD(ctx, peer, session, tenant, probe)
		refused = nil
		if !errors.As(err, &refused) || refused.Code != "denied" || refused.Phase != sfcp.Completed || result.Commit != "" || result.Size != 0 {
			t.Fatal("Git authority refusal was not an authenticated server denial", err)
		}
		if nativeReads() != beforeNative || !reflect.DeepEqual(source.Stats(), beforeGit) {
			t.Fatal("unauthorized diagnostic reached original native/source adapter")
		}
		unchanged()
	}
	positiveCall(operator)
	positiveProbe(operator)
	// The other tenant exists. Require the explicit current-authority refusal,
	// rather than accepting missing-app/no-ready-task or a source lookup error.
	denied("rq8-other", operator)
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	membership, exists := catalog.Membership("tenant", operator.User)
	if !exists {
		t.Fatal("diagnostics Manager membership missing")
	}
	change("rq8-operator-revoke", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: operator.User, Role: access.Viewer, Enabled: true})
	// Preserve the original still-issued Manager session. Current Viewer access
	// keeps ordinary Read usable but withdraws both CallService and Deploy.
	if _, err := user.Query(ctx, peer, operator, "apps", "tenant"); err != nil {
		t.Fatal("membership downgrade unexpectedly invalidated ordinary Read", err)
	}
	denied("tenant", operator)
	catalog, err = p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	membership, _ = catalog.Membership("tenant", operator.User)
	change("rq8-operator-restore", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: operator.User, Role: access.Manager, Enabled: true})
	positiveCall(operator)
	positiveProbe(operator)

	// A fresh account starts with no probe usage. Real sessions share its stable
	// user key; do not lower the product limit or set a synthetic clock/window.
	rate, rateKey := create("rq8-probe-rate")
	defer clear(rateKey.Private)
	second, err := user.Login(ctx, peer, rate.User, rateKey.Private)
	if err != nil || second.ID == rate.ID || second.User != rate.User {
		t.Fatal("second real session for rate-limited account", err)
	}
	if r.cdProbeLimit.ScopedPerMinute != 10 {
		t.Fatal("native probe root requires the product ten-per-user minute limit")
	}
	// Start early in an actual minute so ten small real TLS/Git reads and their
	// refusals share one window. Crossing the boundary fails this finite root;
	// it never repeats requests with a fake/future now or resets the limiter.
	wait("native Git probe minute admission window", func() bool { return time.Now().Unix()%60 < 10 })
	minute := time.Now().Unix() / 60
	for i := 0; i < r.cdProbeLimit.ScopedPerMinute; i++ {
		if time.Now().Unix()/60 != minute {
			t.Fatal("actual minute ended before user probe allowance was consumed")
		}
		session := rate
		if i%2 != 0 {
			session = second
		}
		positiveProbe(session)
	}
	refusedProbe := func(session access.Session) {
		t.Helper()
		beforeNative, beforeGit := nativeReads(), source.Stats()
		result, err := user.ProbeCD(ctx, peer, session, "tenant", probe)
		if err != nil || !result.Valid() || result.Code != "rate-limited" || result.Commit != "" || result.Size != 0 {
			t.Fatal("actual exhausted user probe admission", result, err)
		}
		if time.Now().Unix()/60 != minute {
			t.Fatal("rate refusal did not belong to the consumed actual minute")
		}
		if nativeReads() != beforeNative || !reflect.DeepEqual(source.Stats(), beforeGit) {
			t.Fatal("rate-limited probe reached original native/source adapter")
		}
		unchanged()
	}
	refusedProbe(rate)
	refusedProbe(second)
	renewed, err := user.Login(ctx, peer, rate.User, rateKey.Private)
	if err != nil || renewed.ID == rate.ID || renewed.ID == second.ID {
		t.Fatal("renewed real probe session", err)
	}
	refusedProbe(renewed)
	positiveProbe(operator) // A different current user retains its own allowance.
	if time.Now().Unix()/60 != minute {
		t.Fatal("independent user control did not share the exhausted minute")
	}
	unchanged()
}
