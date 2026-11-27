// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

// Read deadlines measure a stalled socket, not the total lifetime of an image
// response. HTTP's original context still interrupts the connection sooner.
type imageConn struct {
	net.Conn
	idle time.Duration
}

func (c *imageConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}
func (c *imageConn) Write(p []byte) (int, error) {
	// A reused idle connection gets a fresh budget when its next request is
	// sent, including if its read loop was already waiting for response bytes.
	if err := c.Conn.SetDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

// The SDK retains JSON/error decoding and owns this transport's idle sockets.
// Only the explicit local UDS accepted by Open is used; ambient TLS/proxy
// settings cannot redirect image operations to a different Engine.
func imageClient(endpoint string, idle time.Duration) (*client.Client, error) {
	transport := &http.Transport{MaxIdleConns: 6, IdleConnTimeout: idle, ResponseHeaderTimeout: idle}
	dialer := &net.Dialer{Timeout: idle}
	return client.New(client.WithHTTPClient(&http.Client{Transport: transport}), client.WithHost(endpoint), client.WithScheme("http"), client.WithAPIVersionNegotiation(), client.WithDialContext(func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, "unix", strings.TrimPrefix(endpoint, "unix://"))
		if err != nil {
			return nil, err
		}
		return &imageConn{conn, idle}, nil
	}))
}

// pullImage asks the engine for ref; it sends no registry credential.
func (c *Client) pullImage(ctx context.Context, ref string) error {
	if c.imageAPI == nil {
		return ErrOwnership
	}
	stream, err := c.imageAPI.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer stream.Close()
	return stream.Wait(ctx)
}
