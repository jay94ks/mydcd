// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

type execExitKey struct{}

type execExitCapture struct {
	io.ReadCloser
	raw                 []byte
	path                string
	installed, overflow bool
}

func (c *execExitCapture) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	left := (1 << 20) - len(c.raw)
	c.raw = append(c.raw, p[:min(n, left)]...)
	if n > left {
		c.overflow = true
		return n, ErrOwnership
	}
	return n, err
}

type execInspectTransport struct{ base http.RoundTripper }

func (t execInspectTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil || response == nil || response.StatusCode != http.StatusOK {
		return response, err
	}
	c, ok := request.Context().Value(execExitKey{}).(*execExitCapture)
	if !ok || request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, c.path) {
		return response, nil
	}
	c.ReadCloser, c.installed = response.Body, true
	response.Body = c
	return response, nil
}

// ExecInspectTransport wraps a configured transport BEFORE SDK construction. Only the
// exact InspectExec context is observed as the SDK decoder reads/closes it.
// It never sends an extra request or changes endpoint, auth, dialer or body.
// The SDK's read-only response hooks do not expose the body, so they cannot
// preserve the nullable API field. No hook or separate Docker API is used.
func ExecInspectTransport(base http.RoundTripper) http.RoundTripper {
	return execInspectTransport{base: base}
}

// The SDK clones http.Client in WithHTTPClient. A dedicated SDK reader on
// the SAME explicit UDS installs the wrapper before that copy and leaves the
// ordinary client's native Attach dialer and idle connection owner untouched.
func execInspectClient(endpoint string, timeout time.Duration, version string) (*client.Client, func(), error) {
	if !strings.HasPrefix(endpoint, "unix://") {
		return nil, nil, ErrOwnership
	}
	path := strings.TrimPrefix(endpoint, "unix://")
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 6, IdleConnTimeout: 30 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialer.DialContext(ctx, "unix", path) }}
	httpAPI := &http.Client{Transport: ExecInspectTransport(transport), CheckRedirect: client.CheckRedirect}
	api, err := client.New(client.WithHost(endpoint), client.WithHTTPClient(httpAPI), client.WithAPIVersion(version), client.WithTimeout(timeout))
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, err
	}
	return api, transport.CloseIdleConnections, nil
}

// InspectExec retains the API's nullable exit-code distinction which the
// pinned SDK's integer ExecInspectResult discards. A client not configured
// with ExecInspectTransport cannot invent a successful zero exit.
func (c *Client) InspectExec(ctx context.Context, id string) (client.ExecInspectResult, bool, error) {
	if c == nil || c.API == nil || ctx == nil {
		return client.ExecInspectResult{}, false, ErrOwnership
	}
	capture := &execExitCapture{path: "/exec/" + id + "/json"}
	api := c.execAPI
	if api == nil {
		api = c.API
	}
	result, err := api.ExecInspect(context.WithValue(ctx, execExitKey{}, capture), id, client.ExecInspectOptions{})
	if err != nil {
		return result, false, err
	}
	if !capture.installed || capture.overflow {
		return result, false, ErrOwnership
	}
	var wire struct{ ExitCode *int }
	if err = json.Unmarshal(capture.raw, &wire); err != nil {
		return result, false, errors.Join(ErrOwnership, err)
	}
	return result, wire.ExitCode != nil, nil
}
