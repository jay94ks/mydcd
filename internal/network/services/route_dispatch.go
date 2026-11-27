// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"

	"github.com/jay94ks/seafield/internal/network"
)

// RouteDispatch permanently records that this original local journal may have
// dispatched native work. It is neither native Applied nor an absence proof.
type RouteDispatch struct {
	Cluster                         [32]byte
	Reference                       ReferenceNeed
	Boot, Journal, Spec, NativeSpec [32]byte
	Operation                       uint64
	Signature                       []byte
}

func RouteDispatchBytes(dispatch RouteDispatch) []byte {
	dispatch.Signature = nil
	raw, _ := json.Marshal(dispatch)
	return append([]byte("sfc-route-dispatch-1\x00"), raw...)
}

func ownRouteDispatch(dispatch RouteDispatch) RouteDispatch {
	dispatch.Signature = slices.Clone(dispatch.Signature)
	return dispatch
}

// RouteJournalDigest binds the private original nonce to the shared immutable
// consumer/dependency. The nonce is retained only in its protected owner DB.
func RouteJournalDigest(ref ReferenceConsumer, nonce [32]byte) [32]byte {
	raw, _ := json.Marshal(struct {
		Cluster   [32]byte
		Reference ReferenceNeed
		Native    *RouteNativeBinding
		Spec      [32]byte
		Nonce     [32]byte
	}{ref.Local.Cluster, referenceNeed(ref), ref.Native, ref.DesiredHash, nonce})
	return sha256.Sum256(append([]byte("sfc-route-journal-1\x00"), raw...))
}

func RouteTunnelDefinition(ref ReferenceConsumer) (network.TunnelSpec, error) {
	if ref.Route == nil || ref.Native == nil || !validRouteReference(ref) {
		return network.TunnelSpec{}, ErrLease
	}
	route := ref.Route
	policy := network.PacketRoutePolicy{Source: route.Source.Prefix, Destination: route.Destination.Prefix, LocalSource: route.Side == route.Policy.Source.Tenant, Protocol: route.Policy.Protocol}
	for _, ports := range route.Policy.Ports {
		policy.Ports = append(policy.Ports, network.RoutePortRange{First: ports.First, Last: ports.Last})
	}
	remote := policy.Source
	if policy.LocalSource {
		remote = policy.Destination
	}
	name := routePacketNetwork(ref)
	owner := hex.EncodeToString(ref.Local.Cluster[:]) + "/" + hex.EncodeToString(ref.Local.Owner[:])
	bridge, err := network.BridgeDeviceName(owner, ref.Native.Key, ref.Native.Generation, ref.Native.Spec)
	if err != nil {
		return network.TunnelSpec{}, err
	}
	policy.Bridge = bridge
	spec := network.TunnelSpec{Schema: 1, Owner: owner, Network: name, MTU: min(route.Source.MTU, route.Destination.MTU), RouteMetric: 100, Routes: []netip.Prefix{remote}, RoutePolicy: &policy}
	if ref.Dispatch != nil {
		legacy := spec.Clone()
		legacy.RoutePolicy.Bridge = ""
		old, _ := json.Marshal(legacy)
		if sha256.Sum256(old) == ref.Dispatch.NativeSpec {
			return network.DecodeTunnel(string(old))
		}
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return network.TunnelSpec{}, err
	}
	return network.DecodeTunnel(string(raw))
}

func routePacketNetwork(ref ReferenceConsumer) string {
	return "route/" + ref.Route.Policy.Source.Tenant + "/" + ref.Route.Policy.ID + "/" + strconv.FormatUint(ref.Route.Policy.Generation, 10)
}

func validRouteDispatch(ref ReferenceConsumer, dispatch RouteDispatch) bool {
	if ref.Native == nil || ref.Route == nil || dispatch.Cluster != ref.Local.Cluster || !sameReference(dispatch.Reference, referenceNeed(ref)) || dispatch.Boot == ([32]byte{}) || dispatch.Journal == ([32]byte{}) || dispatch.Operation != 1 || dispatch.Spec != ref.DesiredHash {
		return false
	}
	spec, err := RouteTunnelDefinition(ref)
	if err != nil {
		return false
	}
	raw, _ := json.Marshal(spec)
	return dispatch.NativeSpec == sha256.Sum256(raw) && ed25519.Verify(ed25519.PublicKey(ref.Local.Owner[:]), RouteDispatchBytes(dispatch), dispatch.Signature)
}

func ValidateRouteDispatch(ref ReferenceConsumer, dispatch RouteDispatch) error {
	if !validRouteDispatch(ref, dispatch) {
		return ErrLease
	}
	return nil
}

func (a Authority) RecordRouteDispatch(dispatch RouteDispatch) (Authority, error) {
	ref, exists := a.references.Consumers[dispatch.Reference.Consumer]
	if !exists || ref.Closed != nil || !a.CurrentRouteReference(ref.ID) || !validRouteDispatch(ref, dispatch) {
		return a, ErrLease
	}
	if ref.Dispatch != nil {
		old, _ := json.Marshal(ref.Dispatch)
		next, _ := json.Marshal(dispatch)
		if string(old) != string(next) {
			return a, ErrLease
		}
		return a, nil
	}
	next, err := a.clone()
	if err != nil {
		return a, err
	}
	owned := ownRouteDispatch(dispatch)
	ref.Dispatch = &owned
	next.references.Consumers[ref.ID] = ownReferenceConsumer(ref)
	return next, nil
}
