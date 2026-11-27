// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
)

func TestRouteNativeSpecUsesOriginalBridgeIdentityAndPreservesLegacyStoredHash(t *testing.T) {
	f, proposal := routeControlFixture(t)
	approveRouteControl(t, f, proposal)
	ref, _, report := originalRouteDispatch(t, f)
	spec, err := services.RouteTunnelDefinition(ref)
	if err != nil || spec.RoutePolicy == nil || spec.RoutePolicy.Bridge == "" {
		t.Fatal("new route lacks original Bridge routing selection", err)
	}
	wanted, err := network.BridgeDeviceName(spec.Owner, ref.Native.Key, ref.Native.Generation, ref.Native.Spec)
	if err != nil || spec.RoutePolicy.Bridge != wanted {
		t.Fatal("route invented another Bridge identity", err)
	}
	legacy := spec.Clone()
	legacy.RoutePolicy.Bridge = ""
	oldRaw, _ := json.Marshal(legacy)
	old := report.Dispatch
	old.NativeSpec = sha256.Sum256(oldRaw)
	old.Signature = ed25519.Sign(f.node, services.RouteDispatchBytes(old))
	projection, _ := f.p.ProjectResources(f.s)
	if _, err := projection.NetworkAuthority.RecordRouteDispatch(old); err == nil {
		t.Fatal("new grant accepted a legacy main-table native spec")
	}
	ref.Dispatch = &old // An explicitly retained pre-selector signed record.
	retained, err := services.RouteTunnelDefinition(ref)
	if err != nil {
		t.Fatal(err)
	}
	retainedRaw, _ := json.Marshal(retained)
	if !bytes.Equal(oldRaw, retainedRaw) || services.ValidateRouteDispatch(ref, old) != nil {
		t.Fatal("original recovery/closure spec bytes or signature were reinterpreted")
	}
}
