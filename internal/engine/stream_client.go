// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

func streamClient(endpoint, version string) (*client.Client, error) {
	path := strings.TrimPrefix(endpoint, "unix://")
	if !strings.HasPrefix(endpoint, "unix://") || !filepath.IsAbs(path) {
		return nil, ErrOwnership
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 6, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialer.DialContext(ctx, "unix", path) }}
	api, err := client.New(client.WithHost(endpoint), client.WithAPIVersion(version), client.WithHTTPClient(&http.Client{Transport: transport, CheckRedirect: client.CheckRedirect}), client.WithTimeout(0))
	if err != nil {
		transport.CloseIdleConnections()
	}
	return api, err
}
