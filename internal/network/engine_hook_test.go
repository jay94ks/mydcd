// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/client"
)

func hookFixture(t *testing.T) (*EngineHooks, BridgeSpec, reconcile.Operation, engine.Identity) {
	p := pool("pool", "10.254.2.0/24")
	s := BridgeSpec{Schema: 1, Network: p.Network, Owner: p.Owner, MTU: 1280, Pools: []Pool{p}, Internal: true}
	s.Pools[0].MTU = 1280
	raw, _ := json.Marshal(s)
	op := reconcile.Operation{ID: 1, Kind: reconcile.Apply, Phase: reconcile.Dispatched, Target: reconcile.Resource{Generation: 3, Present: true, Spec: string(raw)}}
	id, err := (&engine.Client{Owner: p.Owner}).Identity("bridge", "bridge/system", op.Target)
	if err != nil {
		t.Fatal(err)
	}
	return &EngineHooks{Owner: p.Owner}, s, op, id
}

func hookCreateRequest(id engine.Identity, s BridgeSpec, op string) EngineCreate {
	return EngineCreate{EngineEnvelope: EngineEnvelope{OpID: op, BootID: "boot"}, ID: "net1", Name: id.Name, Labels: id.Labels,
		IPAM: []EngineIPAM{{Subnet: s.Pools[0].Prefix, Gateway: s.Pools[0].Gateway}}}
}

// The engine gets a device name only for the create in flight; once
// Execute is done, a late or repeated create is refused.
func TestEngineHookAnswersOnlyTheCreateInFlight(t *testing.T) {
	h, s, op, id := hookFixture(t)
	if a := h.Create(hookCreateRequest(id, s, "op1")); a.Result != EngineNotApplied || a.Code != EngineNotOwner {
		t.Fatal("create without a dispatch was answered", a)
	}
	done, err := h.Expect("bridge/system", op, s, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Expect("bridge/system", op, s, id); err == nil {
		t.Fatal("second create for the same name in flight")
	}
	wrong := hookCreateRequest(id, s, "op2")
	wrong.Labels = map[string]string{"org.sfc.owner": s.Owner}
	if a := h.Create(wrong); a.Code != EngineNotOwner {
		t.Fatal("foreign labels accepted", a)
	}
	a := h.Create(hookCreateRequest(id, s, "op1"))
	if a.Result != EngineApplied || a.Bridge != bridgeDeviceName(id) || a.MTU != 1280 {
		t.Fatal(a)
	}
	if again := h.Create(hookCreateRequest(id, s, "op1")); again.Bridge != a.Bridge {
		t.Fatal("retry got another answer", again)
	}
	if c := h.Created(EngineCreated{EngineEnvelope: EngineEnvelope{OpID: "op1c", BootID: "boot"}, ID: "net1", Name: id.Name, Labels: id.Labels, Bridge: a.Bridge, MTU: 1500, Gateway: []netip.Addr{s.Pools[0].Gateway}}); c.Code != EngineConflict {
		t.Fatal("wrong MTU readback accepted", c)
	}
	if stage := done(); stage != hookMismatch {
		t.Fatal(stage)
	}
	if late := h.Create(hookCreateRequest(id, s, "op1")); late.Code != EngineNotOwner {
		t.Fatal("create after done was answered", late)
	}
	// The engine failed its own step after our answer and undid it.
	done, _ = h.Expect("bridge/system", op, s, id)
	h.Create(hookCreateRequest(id, s, "op3"))
	h.Delete(EngineDelete{EngineEnvelope: EngineEnvelope{OpID: "op3d", BootID: "boot"}, ID: "net1", Name: id.Name, Labels: id.Labels})
	if stage := done(); !hookRefusedCreate(stage) {
		t.Fatal("undo inside the create is not a refusal", stage)
	}
}

func TestEngineHookJoinNeedsALease(t *testing.T) {
	h, s, op, id := hookFixture(t)
	done, _ := h.Expect("bridge/system", op, s, id)
	a := h.Create(hookCreateRequest(id, s, "op1"))
	if c := h.Created(EngineCreated{EngineEnvelope: EngineEnvelope{OpID: "op1c", BootID: "boot"}, ID: "net1", Name: id.Name, Labels: id.Labels, Bridge: a.Bridge, MTU: 1280, Gateway: []netip.Addr{s.Pools[0].Gateway}}); c.Result != EngineApplied {
		t.Fatal(c)
	}
	if done() != hookConfirmed {
		t.Fatal("readback not confirmed")
	}
	join := func(op, name string) EngineAnswer {
		return h.Join(EngineJoin{EngineEnvelope: EngineEnvelope{OpID: op, BootID: "boot"}, ID: "net1", ContainerName: name, ContainerLabels: map[string]string{"org.sfc.owner": s.Owner}})
	}
	if a := join("j0", "c"); a.Code != EngineNotReady {
		t.Fatal("join without admission", a)
	}
	h.Admit = func(q EngineAdmit) error {
		if q.Key != "bridge/system" || q.Generation != 3 || q.ContainerName != "leased" || q.NetworkID != "net1" {
			return errors.New("no lease")
		}
		return nil
	}
	if a := join("j1", "other"); a.Allow || a.Code != EngineRefused {
		t.Fatal("container without a lease joined", a)
	}
	if a := join("j2", "leased"); !a.Allow || a.MTU != 1280 || a.Routes == nil {
		t.Fatal(a)
	}
	if a := h.Join(EngineJoin{EngineEnvelope: EngineEnvelope{OpID: "j3", BootID: "boot"}, ID: "net1", ContainerName: "leased"}); a.Code != EngineNotOwner {
		t.Fatal("container of another owner joined", a)
	}
	if a := h.Join(EngineJoin{EngineEnvelope: EngineEnvelope{OpID: "j4", BootID: "boot"}, ID: "unknown", ContainerName: "leased", ContainerLabels: map[string]string{"org.sfc.owner": s.Owner}}); a.Code != EngineNotReady {
		t.Fatal("join on an unknown network", a)
	}
}

// With the hooks, a create that failed before the engine asked us (or after
// we refused) made nothing and is settled not applied, even for a 5xx or a
// lost reply; once we gave a name it stays unknown.
func TestBridgeCreateWithEngineHooksIsClassifiedByWhatTheEngineReached(t *testing.T) {
	for _, c := range []struct {
		name  string
		asked bool
		want  reconcile.Outcome
	}{
		{"not-asked", false, reconcile.EffectNotApplied},
		{"asked-then-failed", true, reconcile.EffectUnknown},
		{"asked-then-undone", true, reconcile.EffectNotApplied},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, s, op, id := hookFixture(t)
			api, err := client.New(client.WithHost("http://fixture.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(&http.Client{Transport: bridgeSDKRoundTrip(func(r *http.Request) (*http.Response, error) {
				status, body := http.StatusNotFound, `{"message":"absent"}`
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/networks"):
					status, body = http.StatusOK, `[]`
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/networks/create"):
					if c.asked {
						h.Create(hookCreateRequest(id, s, "op1"))
					}
					if c.name == "asked-then-undone" {
						h.Delete(EngineDelete{EngineEnvelope: EngineEnvelope{OpID: "op1d", BootID: "boot"}, ID: "net1", Name: id.Name, Labels: id.Labels})
					}
					return nil, errors.New("simulated lost reply")
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			driver := &BridgeDriver{Engine: &engine.Client{API: api, Owner: s.Owner}, Hooks: h}
			outcome, err := driver.Execute(context.Background(), "bridge/system", op)
			if err == nil || outcome != c.want {
				t.Fatal(outcome, err)
			}
			if late := h.Create(hookCreateRequest(id, s, "op9")); late.Code != EngineNotOwner {
				t.Fatal("create still answered after Execute", late)
			}
		})
	}
}
