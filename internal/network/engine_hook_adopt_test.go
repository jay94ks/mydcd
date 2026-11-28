// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/engine"
	dockernet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// After a restart an applied Bridge has no pending operation, so only the
// manager's own inspection can teach the engine hooks its network again.
// Without that, every container join on it is answered not-ready.
func TestManagerInspectAdoptsAnAppliedBridgeForJoins(t *testing.T) {
	h, s, op, id := hookFixture(t)
	options := bridgeOptions(s, id)
	n := dockernet.Inspect{Network: dockernet.Network{Name: id.Name, ID: "net1", Driver: EngineDriver, Scope: "local", Internal: s.Internal, EnableIPv4: *options.EnableIPv4, EnableIPv6: *options.EnableIPv6, IPAM: *options.IPAM, Options: options.Options, Labels: id.Labels}}
	body, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	api, err := client.New(client.WithHost("http://fixture.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: bridgeSDKRoundTrip(func(r *http.Request) (*http.Response, error) {
		status, out := http.StatusNotFound, `{"message":"absent"}`
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/networks/") {
			status, out = http.StatusOK, string(body)
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(out)), Request: r}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	h.Admit = func(EngineAdmit) error { return nil }
	join := EngineJoin{EngineEnvelope: EngineEnvelope{OpID: "j1", BootID: "boot"}, ID: "net1", ContainerLabels: map[string]string{"org.sfc.owner": s.Owner}}
	if a := h.Join(join); a.Code != EngineNotReady {
		t.Fatal("join before inspection", a)
	}
	m := &Manager{driver: &BridgeDriver{Engine: &engine.Client{API: api, Owner: s.Owner}, Hooks: h}}
	if _, _, err := m.inspectNetwork(t.Context(), "bridge/system", op.Target); err != nil {
		t.Fatal(err)
	}
	join.OpID = "j2"
	if a := h.Join(join); a.Result != EngineApplied || !a.Allow || a.MTU != 1280 {
		t.Fatal("join after inspection", a)
	}
}
