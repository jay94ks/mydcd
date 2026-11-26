// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

type execInspectRoundTrip func(*http.Request) (*http.Response, error)

func (f execInspectRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type execInspectBody struct {
	io.Reader
	closed *bool
}

func (b execInspectBody) Close() error { *b.closed = true; return nil }

func TestSDKExecInspectionPreservesNullVersusPositiveZeroAndClosesOwnBody(t *testing.T) {
	for _, test := range []struct {
		body             string
		decorated, known bool
	}{
		{`{"ID":"original","ContainerID":"container","Running":false,"ExitCode":null}`, true, false},
		{`{"ID":"original","ContainerID":"container","Running":false,"ExitCode":0}`, true, true},
		{`{"ID":"original","ContainerID":"container","Running":false,"ExitCode":7}`, true, true},
		{`{"ID":"original","ContainerID":"container","Running":false,"ExitCode":0}`, false, false},
	} {
		closed := false
		httpAPI := &http.Client{Transport: execInspectRoundTrip(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/exec/original/json") {
				return nil, errors.New("wrong original request")
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: execInspectBody{Reader: strings.NewReader(test.body), closed: &closed}, Request: r}, nil
		})}
		if test.decorated {
			httpAPI.Transport = ExecInspectTransport(httpAPI.Transport)
		}
		api, err := client.New(client.WithHost("http://fixture.invalid"), client.WithAPIVersion("1.56"), client.WithHTTPClient(httpAPI))
		if err != nil {
			t.Fatal(err)
		}
		c := &Client{API: api}
		result, known, inspectErr := c.InspectExec(context.Background(), "original")
		closeErr := api.Close()
		if !closed || closeErr != nil || known != test.known {
			t.Fatal("SDK body/presence ownership lost", known, inspectErr, closed, closeErr)
		}
		if test.decorated {
			if inspectErr != nil || result.ID != "original" {
				t.Fatal(result, inspectErr)
			}
		} else if !errors.Is(inspectErr, ErrOwnership) {
			t.Fatal("missing capture fabricated zero", inspectErr)
		}
	}
}

// Exercises Engine.Open itself against an owned Unix HTTP endpoint. The SDK
// negotiation/client copy is real; response/native facts are simulated.
func TestSDKExecFactoryCapturesNullableExitOnActualConfiguredUnixClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			w.Header().Set("API-Version", "1.53")
			w.Header().Set("OSType", "linux")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v1.53/exec/original/json" {
			t.Errorf("unexpected SDK operation %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ID":"original","ContainerID":"container","Running":false,"ExitCode":0}`))
	})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	}()
	c, err := Open(ctx, "unix://"+path, "owned-unit")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	result, known, err := c.InspectExec(ctx, "original")
	if err != nil || !known || result.ID != "original" || result.ContainerID != "container" || result.ExitCode != 0 {
		t.Fatal("configured SDK copied away capture transport", result, known, err)
	}
	if _, err := c.API.Ping(ctx, client.PingOptions{}); err != nil {
		t.Fatal("ordinary SDK client changed", err)
	}
}
