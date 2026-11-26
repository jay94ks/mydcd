// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	dockernet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/vishvananda/netlink"
)

func TestManagedBridgeGatewaySDKOptionsAndLegacyIdentity(t *testing.T) {
	p := pool("pool", "10.8.0.0/24")
	legacy := BridgeSpec{Schema: 1, Network: p.Network, Owner: p.Owner, MTU: p.MTU, Pools: []Pool{p}, Internal: true}
	before, _ := json.Marshal(legacy)
	if strings.Contains(string(before), "GatewayMode") {
		t.Fatal("absent field changed legacy native identity")
	}
	decoded, err := DecodeBridge(string(before))
	after, _ := json.Marshal(decoded)
	if err != nil || string(before) != string(after) || !decoded.Internal || decoded.GatewayMode != "" {
		t.Fatal("legacy spec was silently converted", err)
	}
	id := engine.Identity{Name: "mydc-bridge-0123456789ab", Labels: map[string]string{"owner": "test"}}
	managed := legacy
	managed.Internal, managed.GatewayMode = false, ManagedGatewayMode
	opts := bridgeOptions(managed, id)
	if opts.Internal || opts.Options["com.docker.network.bridge.gateway_mode_ipv4"] != ManagedGatewayMode || opts.Options["com.docker.network.bridge.enable_ip_masquerade"] != "false" || opts.Options["com.docker.network.bridge.gateway_mode_ipv6"] != "" {
		t.Fatal("SDK options lost managed filtering or original packet source", opts.Options)
	}
	native := dockernet.Inspect{Network: dockernet.Network{ID: "original", Name: id.Name, Labels: maps.Clone(id.Labels), Driver: "bridge", Scope: "local", EnableIPv4: true, Options: maps.Clone(opts.Options), IPAM: *opts.IPAM}}
	if !matchBridge(native, managed, id) {
		t.Fatal("exact managed SDK readback rejected")
	}
	for _, option := range []string{"com.docker.network.bridge.gateway_mode_ipv4", "com.docker.network.bridge.enable_ip_masquerade"} {
		changed := native
		changed.Options = maps.Clone(native.Options)
		delete(changed.Options, option)
		if matchBridge(changed, managed, id) {
			t.Fatal("missing managed SDK option adopted", option)
		}
	}
	if matchBridge(native, legacy, id) {
		t.Fatal("legacy original adopted a changed gateway mode")
	}
	managed.Internal = true
	raw, _ := json.Marshal(managed)
	if _, err := DecodeBridge(string(raw)); err == nil {
		t.Fatal("incompatible Docker Internal and delegated filtering accepted")
	}
	managed.Internal, managed.GatewayMode = false, "routed"
	raw, _ = json.Marshal(managed)
	if _, err := DecodeBridge(string(raw)); err == nil {
		t.Fatal("unapproved gateway mode accepted")
	}
	p6 := p
	p6.ID, p6.Prefix, p6.Gateway = "v6", netip.MustParsePrefix("fd00:8::/64"), netip.MustParseAddr("fd00:8::1")
	managed.GatewayMode, managed.Pools = ManagedGatewayMode, []Pool{p, p6}
	opts = bridgeOptions(managed, id)
	if opts.Options["com.docker.network.bridge.gateway_mode_ipv6"] != ManagedGatewayMode || !*opts.EnableIPv6 {
		t.Fatal("IPv6 protection was omitted from SDK create")
	}
}

type bridgeSDKRoundTrip func(*http.Request) (*http.Response, error)

func (f bridgeSDKRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// Real SDK encoding/errors with simulated daemon replies and OS lookup only.
// Actual Docker/kernel/forwarding remains the shared owner fixture.
func TestManagedBridgeProtectionFailureNeverSendsSDKCreateAndUnknownNeverRecreates(t *testing.T) {
	for _, mode := range []string{"missing", "denied", "allowed-reply-lost", "link-present", "link-unknown", "link-cancelled", "legacy-link-present", "legacy-link-unknown"} {
		t.Run(mode, func(t *testing.T) {
			reads, creates, guards, lookups := 0, 0, 0, 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			api, err := client.New(client.WithHost("http://fixture.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: bridgeSDKRoundTrip(func(r *http.Request) (*http.Response, error) {
				status, body := http.StatusNotFound, `{"message":"original absent"}`
				if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/networks/") {
					reads++
				} else if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/networks/create") {
					creates++
					return nil, errors.New("simulated lost SDK reply after create send")
				} else {
					t.Errorf("unexpected SDK request: %s %s", r.Method, r.URL.Path)
					status = http.StatusInternalServerError
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			p := pool("pool", "10.8.0.0/24")
			spec := BridgeSpec{Schema: 1, Network: p.Network, Owner: p.Owner, MTU: p.MTU, Pools: []Pool{p}, GatewayMode: ManagedGatewayMode}
			legacy := strings.HasPrefix(mode, "legacy-")
			if legacy {
				spec.Internal, spec.GatewayMode = true, ""
			}
			raw, _ := json.Marshal(spec)
			target := reconcile.Resource{Generation: 7, Present: true, Spec: string(raw)}
			driver := &BridgeDriver{Engine: &engine.Client{API: api, Owner: p.Owner}}
			id, identityErr := driver.Engine.Identity("bridge", "bridge/original", target)
			if identityErr != nil {
				t.Fatal(identityErr)
			}
			foreign := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridgeDeviceName(id), Alias: "foreign", MTU: 1500}}
			unknown := errors.New("injected netlink lookup failure")
			driver.lookupBridge = func(name string) (netlink.Link, error) {
				lookups++
				if name != foreign.Attrs().Name {
					t.Fatal("lookup changed original deterministic native device")
				}
				if strings.HasSuffix(mode, "link-present") {
					return foreign, nil
				}
				if strings.HasSuffix(mode, "link-unknown") {
					return nil, unknown
				}
				if mode == "link-cancelled" {
					cancel()
				}
				return nil, netlink.LinkNotFoundError{}
			}
			denied := errors.New("original native protection unavailable")
			if mode != "missing" {
				driver.Protect = func(_ context.Context, key string, actual reconcile.Resource) error {
					guards++
					if key != "bridge/original" || actual != target {
						t.Fatal("guard did not receive original target")
					}
					if mode == "denied" {
						return denied
					}
					return nil
				}
			}
			op := reconcile.Operation{ID: 1, Kind: reconcile.Apply, Phase: reconcile.Dispatched, Target: target}
			outcome, err := driver.Execute(ctx, "bridge/original", op)
			if mode == "allowed-reply-lost" {
				if err == nil || outcome != reconcile.EffectUnknown || creates != 1 || guards != 1 || lookups != 1 {
					t.Fatal("sent create was treated as nonexecution", outcome, err, creates, guards)
				}
				outcome, err = driver.Recover(t.Context(), "bridge/original", op)
				if err != nil || outcome != reconcile.EffectUnknown || creates != 1 || guards != 1 || lookups != 1 {
					t.Fatal("missing observation recreated original unknown effect", outcome, err, creates, guards)
				}
			} else {
				wantLookup, wantGuard := 1, 1
				var wantError error
				switch mode {
				case "missing":
					wantLookup, wantGuard = 0, 0
				case "denied":
					wantLookup, wantError = 0, denied
				case "link-present", "legacy-link-present":
					wantError = engine.ErrOwnership
				case "link-unknown", "legacy-link-unknown":
					wantError = unknown
				case "link-cancelled":
					wantError = context.Canceled
				}
				if legacy {
					wantGuard = 0
				}
				if err == nil || outcome != reconcile.EffectNotApplied || creates != 0 || reads != 1 || guards != wantGuard || lookups != wantLookup || wantError != nil && !errors.Is(err, wantError) {
					t.Fatal("pre-create refusal sent SDK mutation or lost no-send evidence", outcome, err, creates, reads, guards, lookups)
				}
			}
			if foreign.Attrs().Alias != "foreign" || foreign.Attrs().MTU != 1500 {
				t.Fatal("preflight modified existing kernel device")
			}
		})
	}
}
