// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engine"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

func probeExecFixture() (contract.Request, ProbeExecReceipt) {
	request := serviceProbeRequest()
	request.Targets[0].StartedAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	p := ProbeExecReceipt{Schema: 1, RunID: request.RunID, Call: sha256.Sum256([]byte("original-exec-call")), Payload: sha256.Sum256([]byte("original-argv")), Target: request.Targets[0], Phase: ProbeExecCreating}
	return request, p
}

func TestExecReceiptProtectsOriginalIdentityAndDispatchBoundary(t *testing.T) {
	request, original := probeExecFixture()
	if original.Validate(request) != nil {
		t.Fatal("invalid fixture")
	}
	created := original
	created.ExecID, created.Phase = "original-exec", ProbeExecCreated
	sent := created
	sent.Phase = ProbeExecSent
	if !created.CanFollow(original) || !sent.CanFollow(created) {
		t.Fatal("valid durable transitions denied")
	}
	for _, mutate := range []func(*ProbeExecReceipt){
		func(p *ProbeExecReceipt) { p.Call[0]++ }, func(p *ProbeExecReceipt) { p.Payload[0]++ },
		func(p *ProbeExecReceipt) { p.Target.Generation++ }, func(p *ProbeExecReceipt) { p.ExecID = "replacement-exec" },
		func(p *ProbeExecReceipt) { p.Phase = ProbeExecCreated }, func(p *ProbeExecReceipt) { p.Phase = ProbeExecCreating },
	} {
		next := sent
		mutate(&next)
		if next.CanFollow(sent) {
			t.Fatal("changed identity or invented closure", next)
		}
	}
	bad := original
	bad.Phase, bad.ExecID = ProbeExecCanceled, "invented-exec"
	if bad.CanFollow(original) {
		t.Fatal("invented canceled native identity")
	}
	bad = original
	bad.Target.Owner = strings.Repeat("a", 64)
	if bad.Validate(request) == nil {
		t.Fatal("foreign owner accepted")
	}
	bad = original
	bad.Target.StartedAt = ""
	if bad.Validate(request) == nil {
		t.Fatal("missing container instance accepted")
	}
}

// This uses the actual SDK response decoder with a fake transport. It is not
// evidence that an actual Docker process ran, ended, or was removed.
func TestExecRecoveryDoesNotReplayAmbiguousStartAndKeepsOriginalID(t *testing.T) {
	for _, initial := range []ProbeExecPhase{ProbeExecCreating, ProbeExecCreated, ProbeExecSent, ProbeExecRunning, ProbeExecStreamEnded} {
		t.Run(string(initial), func(t *testing.T) {
			request, p := probeExecFixture()
			p.Phase = initial
			if initial != ProbeExecCreating {
				p.ExecID = "original-exec"
			}
			running, gone, foreign, missing := false, false, false, false
			exitKnown := initial != ProbeExecSent
			reads, writes := 0, 0
			httpAPI := &http.Client{Transport: startRoundTrip(func(r *http.Request) (*http.Response, error) {
				code := http.StatusOK
				body := []byte(`{}`)
				if r.Method != http.MethodGet {
					writes++
					return nil, errors.New("recovery transmitted an effect")
				}
				reads++
				switch {
				case strings.HasSuffix(r.URL.Path, "/containers/"+p.Target.NativeID+"/json"):
					if gone {
						code = http.StatusNotFound
						body = []byte(`{"message":"original gone"}`)
					}
				case strings.HasSuffix(r.URL.Path, "/exec/original-exec/json"):
					if missing {
						code = http.StatusNotFound
						body = []byte(`{"message":"unknown exec"}`)
					} else {
						id := p.Target.NativeID
						if foreign {
							id = "replacement-container"
						}
						var code *int
						if exitKnown {
							value := 0
							code = &value
						}
						body, _ = json.Marshal(map[string]any{"ID": "original-exec", "ContainerID": id, "Running": running, "ExitCode": code})
					}
				default:
					return nil, errors.New("foreign native path")
				}
				return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
			})}
			httpAPI.Transport = engine.ExecInspectTransport(httpAPI.Transport)
			api, err := client.New(client.WithHost("http://fixture.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(httpAPI))
			if err != nil {
				t.Fatal(err)
			}
			defer api.Close()
			m := &Manager{driver: &DockerDriver{Engine: &engine.Client{API: api, Owner: request.Cluster + "/" + p.Target.Owner}}}
			save := func(next ProbeExecReceipt) error {
				if next.Validate(request) != nil || !next.CanFollow(p) {
					return checker.ErrContract
				}
				p = next
				return nil
			}
			err = m.RecoverProbeExec(context.Background(), request, p, save)
			if initial == ProbeExecCreating || initial == ProbeExecCreated {
				if err != nil || p.Phase != ProbeExecCanceled || reads != 0 || writes != 0 {
					t.Fatal("pre-Start cancellation made native request", p, err)
				}
				return
			}
			if initial != ProbeExecSent {
				if err != nil || p.Phase != ProbeExecCompleted || writes != 0 {
					t.Fatal("positive completion not retained", p, err)
				}
				return
			}
			if !errors.Is(err, ErrProbeExecPending) || p.Phase != ProbeExecSent {
				t.Fatal("!Running invented execution/completion", p, err)
			}
			missing = true
			if err = m.RecoverProbeExec(context.Background(), request, p, save); !errors.Is(err, ErrProbeExecPending) || p.Phase != ProbeExecSent {
				t.Fatal("exec404 invented non-execution", p, err)
			}
			missing = false
			foreign = true
			if err = m.RecoverProbeExec(context.Background(), request, p, save); !errors.Is(err, checker.ErrContract) {
				t.Fatal("foreign exec accepted", err)
			}
			foreign = false
			running = true
			if err = m.RecoverProbeExec(context.Background(), request, p, save); !errors.Is(err, ErrProbeExecPending) || p.Phase != ProbeExecRunning {
				t.Fatal("running identity not retained", p, err)
			}
			running = false
			// Running=false with a null exit code is still not a terminal result.
			if err = m.RecoverProbeExec(context.Background(), request, p, save); !errors.Is(err, ErrProbeExecPending) || p.Phase != ProbeExecRunning {
				t.Fatal("null exit became zero", p, err)
			}
			exitKnown = true
			if err = m.RecoverProbeExec(context.Background(), request, p, save); err != nil || p.Phase != ProbeExecCompleted || writes != 0 {
				t.Fatal("late original exit replayed", p, err)
			}
			p.Phase = ProbeExecSent // positive nullable exit is sufficient even for a fast command
			if err = m.RecoverProbeExec(context.Background(), request, p, save); err != nil || p.Phase != ProbeExecCompleted {
				t.Fatal("positive fast exit lost", p, err)
			}
			p.Phase = ProbeExecSent // independent retained-receipt fixture for native Gone
			gone = true
			if err = m.RecoverProbeExec(context.Background(), request, p, save); err != nil || p.Phase != ProbeExecCanceled || writes != 0 {
				t.Fatal("native Gone not settled", p, err)
			}
		})
	}
}

func TestExecOutputDrainsWithoutUnboundedRetention(t *testing.T) {
	w := &probeExecOutput{max: 4}
	if n, err := w.Write([]byte("abc")); err != nil || n != 3 || w.truncated {
		t.Fatal(n, err)
	}
	for i := 0; i < 100; i++ {
		if n, err := w.Write([]byte("defgh")); err != nil || n != 5 {
			t.Fatal(n, err)
		}
	}
	if string(w.data) != "abcd" || !w.truncated {
		t.Fatal("bounded output lost prefix/truncation", w)
	}
}

func TestExecFramesRejectTruncationBeforeSDKCanTreatItAsCleanEOF(t *testing.T) {
	frame := func(stream byte, payload string) []byte {
		raw := make([]byte, 8+len(payload))
		raw[0] = stream
		binary.BigEndian.PutUint32(raw[4:], uint32(len(payload)))
		copy(raw[8:], payload)
		return raw
	}
	good := append(frame(1, "ready"), frame(2, "private stderr")...)
	for _, n := range []int{1, 7, 9, len(good) - 1} {
		out := &probeExecOutput{max: 8}
		if _, err := stdcopy.StdCopy(out, io.Discard, &probeExecFrames{source: bytes.NewReader(good[:n])}); !errors.Is(err, ErrProbeExecStream) {
			t.Fatal("truncated stream became terminal", n, err)
		}
	}
	oversized := frame(1, "")
	binary.BigEndian.PutUint32(oversized[4:], (1<<20)+1)
	badReserved := frame(1, "ready")
	badReserved[1] = 1
	for _, raw := range [][]byte{oversized, badReserved, frame(8, "foreign")} {
		if _, err := stdcopy.StdCopy(io.Discard, io.Discard, &probeExecFrames{source: bytes.NewReader(raw)}); !errors.Is(err, ErrProbeExecStream) {
			t.Fatal("invalid frame accepted", err)
		}
	}
	out := &probeExecOutput{max: 3}
	if _, err := stdcopy.StdCopy(out, io.Discard, &probeExecFrames{source: bytes.NewReader(good)}); err != nil || string(out.data) != "rea" || !out.truncated {
		t.Fatal("valid multiplexed output failed", out, err)
	}
}
