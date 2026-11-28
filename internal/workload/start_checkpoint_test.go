// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	dockernet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

type startRoundTrip func(*http.Request) (*http.Response, error)

func (f startRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type startBridge struct{ lease network.BridgeLease }

func (b startBridge) Acquire(context.Context, string, string, uint64) (network.BridgeLease, error) {
	return b.lease, nil
}
func (b startBridge) InspectConsumer(context.Context, string, string, uint64) (network.BridgeLease, error) {
	return b.lease, nil
}
func (b startBridge) ReturnConsumer(string, string, uint64) error { return nil }

type startFixture struct {
	engine         *engine.Client
	bridge         startBridge
	spec           ContainerSpec
	op             reconcile.Operation
	native         container.InspectResponse
	starts         int
	onStart        func() error
	onInspect      func() error
	stops, removes int
	onStop         func(*http.Request) error
	gone           bool
	lists          int
	listItems      []container.Summary
	// network connect/disconnect: the network ID from the path and body
	onConnect    func(network string, body []byte) error
	onDisconnect func(network string, body []byte) error
}

func makeStartFixture(t *testing.T) *startFixture {
	t.Helper()
	f := &startFixture{}
	f.spec = ContainerSpec{Schema: 1, Node: "owner", Image: "sha256:" + strings.Repeat("a", 64), Command: []string{"/job"}, Bridge: "bridge", BridgeGeneration: 1, IPv4: netip.MustParseAddr("192.0.2.2"), Memory: 32 << 20, NanoCPU: 100000000}
	raw, _ := json.Marshal(f.spec)
	f.op = reconcile.Operation{ID: 1, Kind: reconcile.Apply, Target: reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}, Phase: reconcile.Dispatched}
	f.engine = &engine.Client{Owner: "owner"}
	id, err := f.engine.Identity("container", "task", f.op.Target)
	if err != nil {
		t.Fatal(err)
	}
	f.bridge.lease = network.BridgeLease{NetworkID: "fixture-network", NetworkName: "fixture-bridge"}
	f.native = container.InspectResponse{ID: strings.Repeat("b", 64), Name: "/" + id.Name, Config: &container.Config{Image: f.spec.Image, Cmd: f.spec.Command, Labels: id.Labels}, HostConfig: &container.HostConfig{ReadonlyRootfs: true, NetworkMode: "fixture-network", RestartPolicy: container.RestartPolicy{Name: "no"}, Resources: container.Resources{Memory: f.spec.Memory, NanoCPUs: f.spec.NanoCPU}}, State: &container.State{Status: container.StateCreated}, NetworkSettings: &container.NetworkSettings{Networks: map[string]*dockernet.EndpointSettings{"fixture-bridge": {NetworkID: "fixture-network", IPAddress: f.spec.IPv4, IPAMConfig: &dockernet.EndpointIPAMConfig{IPv4Address: f.spec.IPv4}}}}}
	api, err := client.New(client.WithHost("http://fixture.invalid"), client.WithAPIVersion("1.52"), client.WithHTTPClient(&http.Client{Transport: startRoundTrip(func(r *http.Request) (*http.Response, error) {
		status := http.StatusOK
		var body []byte
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/containers/json"):
			f.lists++
			body, _ = json.Marshal(f.listItems)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/json"):
			if f.onInspect != nil {
				if err := f.onInspect(); err != nil {
					return nil, err
				}
			}
			if f.gone {
				status, body = http.StatusNotFound, []byte(`{"message":"original gone"}`)
			} else {
				body, _ = json.Marshal(f.native)
			}
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/start"):
			f.starts++
			if f.onStart != nil {
				if err := f.onStart(); err != nil {
					return nil, err
				}
			}
			status = http.StatusNoContent
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/stop"):
			f.stops++
			if f.onStop != nil {
				if err := f.onStop(r); err != nil {
					return nil, err
				}
			}
			status = http.StatusNoContent
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/networks/") && (strings.HasSuffix(r.URL.Path, "/connect") || strings.HasSuffix(r.URL.Path, "/disconnect")):
			parts := strings.Split(r.URL.Path, "/")
			networkID := parts[len(parts)-2]
			raw, _ := io.ReadAll(r.Body)
			hook := f.onConnect
			if strings.HasSuffix(r.URL.Path, "/disconnect") {
				hook = f.onDisconnect
			}
			if hook == nil {
				t.Errorf("unexpected native request: %s %s", r.Method, r.URL.Path)
				status = http.StatusInternalServerError
			} else if err := hook(networkID, raw); err != nil {
				return nil, err
			}
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/containers/"):
			f.removes++
			f.gone, status = true, http.StatusNoContent
		default:
			t.Errorf("unexpected native request: %s %s", r.Method, r.URL.Path)
			status = http.StatusInternalServerError
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
	})}))
	if err != nil {
		t.Fatal(err)
	}
	f.engine.API = api
	t.Cleanup(func() { _ = api.Close() })
	return f
}

func TestOriginalStartCheckpointSurvivesLostReplyAndDoesNotResendCreated(t *testing.T) {
	// The HTTP transport and Bridge are fixtures; the workload Manager, A2
	// checkpoint transaction and DB reopen are the actual product paths.
	for _, terminal := range []bool{false, true} {
		f := makeStartFixture(t)
		f.onStart = func() error {
			if terminal {
				f.native.State = &container.State{Status: container.StateExited, StartedAt: "2026-11-14T01:00:00Z", FinishedAt: "2026-11-14T01:00:01Z"}
			}
			return io.ErrUnexpectedEOF
		}
		path := filepath.Join(t.TempDir(), "workload.db")
		m, err := OpenManager(path, f.engine, f.bridge)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = m.Close() }()
		if err = m.Desired("task", 1, 1, &f.spec, 4); err != nil {
			t.Fatal(err)
		}
		if err = m.Step(context.Background(), "task"); err == nil {
			t.Fatal("lost Start reply was silently retried or accepted")
		}
		record, err := m.View("task")
		if err != nil || record.Checkpoint == nil || record.Checkpoint.Operation != f.op.ID || record.Checkpoint.Target != f.op.Target || record.State.Pending == nil {
			t.Fatal("original Start dispatch was not retained", err)
		}
		var proof containerStart
		if json.Unmarshal(record.Checkpoint.Data, &proof) != nil || proof.Schema != 1 || proof.Native != f.native.ID {
			t.Fatal("wrong original immutable native checkpoint")
		}
		_ = m.Close()
		m, err = OpenManager(path, f.engine, f.bridge)
		if err != nil {
			t.Fatal(err)
		}
		err = m.Step(context.Background(), "task")
		if terminal && err != nil || !terminal && !errors.Is(err, reconcile.ErrPending) || f.starts != 1 {
			t.Fatal("Created/terminal recovery changed original dispatch", terminal, f.starts, err)
		}
		if terminal {
			status, err := m.Status(context.Background(), "task")
			if err != nil || status.Exit == nil || status.Exit.Code != 0 || status.Running {
				t.Fatal("positive original fast exit was lost", err)
			}
			f.native.ID = strings.Repeat("c", 64)
			if err = m.Step(context.Background(), "task"); !errors.Is(err, engine.ErrOwnership) {
				t.Fatal("checkpoint native was silently replaced", err)
			}
		}
	}
}

func TestStartIsNotSentWithoutSuccessfulOriginalCheckpointSave(t *testing.T) {
	f := makeStartFixture(t)
	d := &DockerDriver{Engine: f.engine, Network: f.bridge}
	denied := errors.New("checkpoint sync failed")
	called := false
	outcome, err := d.ExecuteCheckpoint(context.Background(), "task", f.op, func(raw []byte) error {
		called = true
		var proof containerStart
		if json.Unmarshal(raw, &proof) != nil || proof.Native != f.native.ID || f.starts != 0 {
			t.Fatal("Start before immutable original checkpoint")
		}
		return denied
	})
	if !called || !errors.Is(err, denied) || outcome != reconcile.EffectUnknown || f.starts != 0 {
		t.Fatal("Start escaped failed sync", outcome, f.starts, err)
	}
	if outcome, err = d.Recover(context.Background(), "task", f.op); outcome != reconcile.EffectUnknown || !errors.Is(err, reconcile.ErrPending) || f.starts != 0 {
		t.Fatal("Created recovery without original proof invented a fresh Start")
	}
}
