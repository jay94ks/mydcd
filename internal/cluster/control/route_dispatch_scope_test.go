// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
)

// Both signed reports consume the reusable product Authority/FSM. Only their
// private owner keys and original journal facts are test inputs.
func routeDispatchAfterPeerProgress(t *testing.T) (*backupCoreFixture, services.ReferenceConsumer, [32]byte, RouteDispatchReport) {
	t.Helper()
	f, proposal, owners := routeControlOwnersFixture(t)
	approveRouteControl(t, f, proposal)
	ref, nonce, report := originalRouteDispatch(t, f)
	report.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(report))
	for owner, private := range owners {
		if owner == ref.Local.Owner {
			continue
		}
		peerFixture := *f
		peerFixture.node = private
		_, _, peerReport := originalRouteDispatch(t, &peerFixture)
		applyRouteDispatch(t, f, peerReport, state.Applied)
	}
	if f.s.Object(AppsKey).Revision <= report.RootRevision || f.s.ModuleExpired(mustRouteDispatchCommand(t, report)) {
		t.Fatal("counterexample did not advance only the global CAS")
	}
	return f, ref, nonce, report
}
func mustRouteDispatchCommand(t *testing.T, report RouteDispatchReport) state.Command {
	t.Helper()
	cmd, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}
func TestRouteDispatchReferenceCASAllowsPeerProgress(t *testing.T) {
	f, ref, nonce, report := routeDispatchAfterPeerProgress(t)
	cmd := mustRouteDispatchCommand(t, report)
	if _, code := f.p.Reduce(f.s, cmd); code != state.Applied {
		t.Fatal("current typed ref validation rejected the counterexample", code)
	}
	_, receipt := applyRouteDispatch(t, f, report, state.Applied)
	request := RouteNativeRequest{Reference: ref.ID, Nonce: nonce, Operation: 1, At: 10}
	permit, err := f.p.RouteNativePermit(f.s, ref.Local.Owner, request)
	if err != nil || permit.Reference != report.Dispatch.Reference || permit.Journal != report.Dispatch.Journal || permit.NativeSpec != report.Dispatch.NativeSpec {
		t.Fatal("scope changed original native identity", err)
	}
	before := f.s.Object(AppsKey)
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, replay := applyRouteDispatch(t, f, report, state.Applied)
	if replay != receipt || f.s.Object(AppsKey) != before {
		t.Fatal("snapshot/ACK loss re-executed the original grant")
	}
}

func TestRouteDispatchReferenceCASKeepsOriginalIdentityAndCurrentRevocation(t *testing.T) {
	for _, name := range []string{"signature", "generation", "owner", "native-spec", "journal-replace", "boot-replace", "withdrawn", "future-root", "epoch"} {
		t.Run(name, func(t *testing.T) {
			f, ref, nonce, report := routeDispatchAfterPeerProgress(t)
			if name == "journal-replace" || name == "boot-replace" {
				applyRouteDispatch(t, f, report, state.Applied)
				report.RootRevision = f.s.Object(AppsKey).Revision
			}
			switch name {
			case "signature":
				report.Signature = append([]byte(nil), report.Signature...)
				report.Signature[0] ^= 1
			case "generation":
				report.Dispatch.Reference.Generation++
				report.Dispatch.Signature = ed25519.Sign(f.node, services.RouteDispatchBytes(report.Dispatch))
				report.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(report))
			case "owner":
				report.Dispatch.Reference.Owner = [32]byte{99}
				report.Dispatch.Signature = ed25519.Sign(f.node, services.RouteDispatchBytes(report.Dispatch))
				report.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(report))
			case "boot-replace":
				report.Dispatch.Boot[0]++
				report.Dispatch.Signature = ed25519.Sign(f.node, services.RouteDispatchBytes(report.Dispatch))
				report.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(report))
			case "native-spec":
				report.Dispatch.NativeSpec[0]++
				report.Dispatch.Signature = ed25519.Sign(f.node, services.RouteDispatchBytes(report.Dispatch))
				report.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(report))
			case "journal-replace":
				report.Dispatch.Journal[0]++
				report.Dispatch.Signature = ed25519.Sign(f.node, services.RouteDispatchBytes(report.Dispatch))
				report.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(report))
			case "withdrawn":
				r, _ := f.p.Resources(f.s)
				route, _ := r.Networks.Route(ref.Route.Policy.Source.Tenant, ref.Route.Policy.ID)
				managedDNSChange(t, f, "scoped-dispatch-withdraw", "withdraw-route", route.Revision, RouteSelection{Tenant: route.Source.Tenant, SourceTenant: route.Source.Tenant, ID: route.ID}, state.Applied)
			case "future-root":
				report.RootRevision = f.s.Object(AppsKey).Revision + 1
				report.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(report))
			case "epoch":
				report.Epoch++
				report.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(report))
			}
			before := f.s.Object(AppsKey)
			cmd := mustRouteDispatchCommand(t, report)
			next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
			if err != nil || result.Code == state.Applied || next.Object(AppsKey) != before {
				t.Fatal("scoped dispatch bypassed original identity/current authority", result, err)
			}
			if name == "withdrawn" {
				if _, err := f.p.RouteNativePermit(next, ref.Local.Owner, RouteNativeRequest{Reference: ref.ID, Nonce: nonce, Operation: 1, At: 10}); err == nil {
					t.Fatal("withdrawn reference acquired native permit")
				}
			}
		})
	}
}
