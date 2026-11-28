// SPDX-License-Identifier: Apache-2.0

// Package sfevtest is a test-only h2c client for sfev.sock, used by the
// endpoint tests to check the wire contract. It is not a library for apps:
// each container image's implementer brings their own client, following
// devel/proposals/sfev-sock.md.
package sfevtest

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/http2"
)

const (
	// EnvSocket names the socket in the container's environment.
	EnvSocket = "SFC_SECRET_SOCKET"
	// DefaultSocket is where the socket is when EnvSocket is unset.
	DefaultSocket = "/run/sfc/sfev.sock"
	// maxResponse bounds one response body (the server's limit is 64KiB of
	// values; JSON adds quoting).
	maxResponse = 512 << 10
)

var (
	// ErrDenied: the container's approval does not allow these values (403).
	ErrDenied = errors.New("sfev: not permitted")
	// ErrNotFound: no such key (404).
	ErrNotFound = errors.New("sfev: no such key")
	// ErrBusy: another connection of this container holds the socket, or a
	// watch is already open on this one (409).
	ErrBusy = errors.New("sfev: socket in use")
	// ErrTooLarge: the values exceed the container limit (413).
	ErrTooLarge = errors.New("sfev: values too large")
	// ErrUnavailable: the cluster could not be reached for the values
	// right now (503). Retry later.
	ErrUnavailable = errors.New("sfev: values not available now")
	// ErrRevoked: the server ended the watch because the approval was
	// withdrawn. Discard the values received.
	ErrRevoked = errors.New("sfev: approval revoked")
	// ErrClosing: sfcd is stopping or the container is stopping.
	ErrClosing = errors.New("sfev: server closing")
)

// Values is one consistent key/value set at one revision.
type Values struct {
	Revision string            `json:"revision"`
	Values   map[string]string `json:"values"`
}

// Event is one line of a watch.
type Event struct {
	// Type is "snapshot" (all values), "changed" (changed keys in Values,
	// deleted keys in Removed), "revoked" or "closing".
	Type     string            `json:"type"`
	Revision string            `json:"revision,omitempty"`
	Values   map[string]string `json:"values,omitempty"`
	Removed  []string          `json:"removed,omitempty"`
	Reason   string            `json:"reason,omitempty"`
}

// Client is one connection to sfev.sock.
type Client struct {
	http      *http.Client
	transport *http2.Transport
}

// Dial opens the connection. An empty path uses $SFC_SECRET_SOCKET, then
// DefaultSocket. The connection itself is made on the first request.
func Dial(path string) (*Client, error) {
	if path == "" {
		path = os.Getenv(EnvSocket)
	}
	if path == "" {
		path = DefaultSocket
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("sfev: %w", err)
	}
	t := &http2.Transport{
		AllowHTTP: true,
		// One connection only: wait for a free stream, never dial a second.
		StrictMaxConcurrentStreams: true,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
	}
	return &Client{http: &http.Client{Transport: t}, transport: t}, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sfev"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sfev: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, statusError(resp)
	}
	return resp, nil
}

func statusError(resp *http.Response) error {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body)
	var base error
	switch resp.StatusCode {
	case http.StatusForbidden:
		base = ErrDenied
	case http.StatusNotFound:
		base = ErrNotFound
	case http.StatusConflict:
		base = ErrBusy
	case http.StatusRequestEntityTooLarge:
		base = ErrTooLarge
	case http.StatusServiceUnavailable:
		base = ErrUnavailable
	default:
		return fmt.Errorf("sfev: status %d: %s", resp.StatusCode, body.Error)
	}
	if body.Error == "" {
		return base
	}
	return fmt.Errorf("%w: %s", base, body.Error)
}

// Secrets reads all values approved for this container.
func (c *Client) Secrets(ctx context.Context) (Values, error) {
	resp, err := c.get(ctx, "/v1/secrets")
	if err != nil {
		return Values{}, err
	}
	defer resp.Body.Close()
	var v Values
	if err = json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&v); err != nil {
		return Values{}, fmt.Errorf("sfev: %w", err)
	}
	return v, nil
}

// Secret reads one key's value and the revision it was read at.
func (c *Client) Secret(ctx context.Context, key string) (value, revision string, err error) {
	if key == "" || strings.Contains(key, "/") {
		return "", "", ErrNotFound
	}
	resp, err := c.get(ctx, "/v1/secrets/"+url.PathEscape(key))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var v struct {
		Revision string `json:"revision"`
		Value    string `json:"value"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&v); err != nil {
		return "", "", fmt.Errorf("sfev: %w", err)
	}
	return v.Value, v.Revision, nil
}

// Watch is an open watch stream.
type Watch struct {
	body io.Closer
	dec  *json.Decoder
}

// Watch opens the watch stream. Its first event is the snapshot.
func (c *Client) Watch(ctx context.Context) (*Watch, error) {
	resp, err := c.get(ctx, "/v1/watch")
	if err != nil {
		return nil, err
	}
	return &Watch{body: resp.Body, dec: json.NewDecoder(resp.Body)}, nil
}

// Next waits for the next event. After "revoked" or "closing" it returns
// the event and then ErrRevoked or ErrClosing.
func (w *Watch) Next() (Event, error) {
	var ev Event
	if err := w.dec.Decode(&ev); err != nil {
		return Event{}, fmt.Errorf("sfev: watch ended: %w", err)
	}
	return ev, nil
}

// Close ends the watch.
func (w *Watch) Close() error { return w.body.Close() }
