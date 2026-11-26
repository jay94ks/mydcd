// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
)

func TestStopPolicyNormalizesFiniteGraceAndFrozenSignal(t *testing.T) {
	for _, tc := range []struct {
		grace, signal string
		seconds       int
		canonical     string
	}{
		{"0s", "TERM", 0, "SIGTERM"}, {"1ms", "15", 1, "SIGTERM"},
		{"1.001s", "sigquit", 2, "SIGQUIT"}, {"2m", "", 120, ""},
		{"24h", "SIGINT", MaxStopGrace, "SIGINT"}, {"", "QUIT", DefaultStopGrace, "SIGQUIT"},
	} {
		p, err := ParseStopPolicy(tc.grace, tc.signal)
		if err != nil || p == nil || p.GraceSeconds != tc.seconds || p.Signal != tc.canonical {
			t.Fatal("stop normalization", tc, p, err)
		}
	}
	if p, err := ParseStopPolicy("", ""); p != nil || err != nil {
		t.Fatal("absence added metadata/defaults to the original Task")
	}
	for _, tc := range [][2]string{{"-1s", ""}, {"24h1ns", ""}, {"999999999999h", ""}, {"forever", ""}, {"1s", "0"}, {"1s", "-1"}, {"1s", "015"}, {"1s", "SIGRTMIN+1"}, {"1s", " SIGTERM"}, {"1s", "SIGTERM\n"}, {"1s", "33"}, {"1s", "UNKNOWN"}} {
		if _, err := ParseStopPolicy(tc[0], tc[1]); err == nil {
			t.Fatal("invalid/unbounded stop policy accepted", tc)
		}
	}
}

func TestStopProjectionUsesSameOriginalTaskAndActualContainerConfig(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		var stop *StopPolicy
		cfg := &container.Config{StopSignal: "SIGQUIT"}
		if explicit {
			stop = &StopPolicy{GraceSeconds: 120, Signal: "SIGQUIT"}
			grace := 120
			cfg.StopTimeout = &grace
		}
		raw, _ := json.Marshal(struct {
			Schema  uint8
			Stop    *StopPolicy `json:",omitempty"`
			Process struct{ StopSignal string }
		}{Schema: 1, Stop: stop, Process: struct{ StopSignal string }{"SIGQUIT"}})
		p, err := MatchStopPolicy(string(raw), cfg)
		if err != nil || p.Signal != "SIGQUIT" || p.GraceSeconds != map[bool]int{false: 10, true: 120}[explicit] {
			t.Fatal("lost image inheritance/explicit Task policy", err)
		}
		cfg.StopSignal = "SIGTERM"
		if _, err = MatchStopPolicy(string(raw), cfg); err == nil {
			t.Fatal("native signal drift accepted")
		}
	}
	for _, raw := range []string{`{"Schema":1,"Stop":null}`, `{"Schema":1,"Stop":{"GraceSeconds":1,"Signal":"SIGTERM"},"Process":{"StopSignal":"SIGQUIT"}}`, `{"Schema":1,"Stop":{"GraceSeconds":-1,"Signal":""}}`, `{"Schema":1,"Stop":{"GraceSeconds":1,"Signal":"","unknown":1}}`} {
		if _, err := StopPolicyFromSpec(raw); err == nil {
			t.Fatal("null/foreign/inconsistent stop metadata accepted")
		}
	}
}

// This is an actual UDS/SDK request boundary, not a real Docker/clean-exit or
// writer-fence assertion. The server delays only the Stop response.
func TestStopUsesDeclaredBudgetOnSameEngineWithoutOrdinaryRPCCap(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "engine.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var stops atomic.Int32
	var hold atomic.Bool
	started, returned := make(chan struct{}), make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			w.Header().Set("API-Version", "1.56")
			w.WriteHeader(http.StatusOK)
			return
		}
		original := strings.HasSuffix(r.URL.Path, "/containers/original/stop") || strings.HasSuffix(r.URL.Path, "/containers/cancelled-original/stop")
		if r.Method != http.MethodPost || !original || r.URL.Query().Get("t") != "2" || r.URL.Query().Get("signal") != "SIGQUIT" {
			t.Errorf("wrong original Stop request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		stops.Add(1)
		if hold.Load() {
			close(started)
			defer close(returned)
			<-r.Context().Done()
			return
		}
		select {
		case <-time.After(300 * time.Millisecond):
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
	})}
	ended := make(chan struct{})
	go func() { _ = server.Serve(listener); close(ended) }()
	defer func() { _ = server.Close(); <-ended }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := open(ctx, "unix://"+listener.Addr().String(), "fixture-owner", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.stopAPI == nil || c.stopAPI.DaemonHost() != c.API.DaemonHost() {
		t.Fatal("Stop client changed the original Engine endpoint")
	}
	policy := StopPolicy{GraceSeconds: 2, Signal: "SIGQUIT"}
	short, stop := context.WithTimeout(ctx, time.Millisecond)
	if err = c.StopContainer(short, "original", policy); !errors.Is(err, ErrStopBudget) || stops.Load() != 0 {
		t.Fatal("insufficient parent budget sent native effect", err)
	}
	stop()
	if err = c.StopContainer(ctx, "original", policy); err != nil || stops.Load() != 1 {
		t.Fatal("ordinary short RPC cap truncated declared Stop grace", stops.Load(), err)
	}
	cancelled, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if err = c.StopContainer(cancelled, "original", policy); !errors.Is(err, context.Canceled) || stops.Load() != 1 {
		t.Fatal("cancelled original dispatched another request", err)
	}
	hold.Store(true)
	inflight, cancelInflight := context.WithCancel(ctx)
	defer cancelInflight()
	result := make(chan error, 1)
	go func() { result <- c.StopContainer(inflight, "cancelled-original", policy) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("Stop request did not start", ctx.Err())
	}
	cancelInflight()
	if err = <-result; !errors.Is(err, context.Canceled) || stops.Load() != 2 {
		t.Fatal("in-flight cancellation was retried/lost", stops.Load(), err)
	}
	select {
	case <-returned:
	case <-ctx.Done():
		t.Fatal("cancelled SDK request/server handler leaked", ctx.Err())
	}
}
