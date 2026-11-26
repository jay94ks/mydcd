// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HTTPReadiness probes the original task's explicit address, never a caller's
// arbitrary URL, proxy, redirect destination or host-mounted executable.
type HTTPReadiness struct {
	Path      string
	Port      uint16
	TimeoutMS int `json:",omitempty"`
}

func (p HTTPReadiness) Valid() bool {
	u, err := url.ParseRequestURI(p.Path)
	return err == nil && len(p.Path) <= 1024 && strings.HasPrefix(p.Path, "/") && !strings.HasPrefix(p.Path, "//") && !strings.ContainsAny(p.Path, "\x00\r\n#") && u.Scheme == "" && u.Host == "" && u.Fragment == "" && p.Port != 0 && p.TimeoutMS >= 0 && p.TimeoutMS <= 30000
}

func httpReady(ctx context.Context, s ContainerSpec) bool {
	if s.Readiness == nil || !s.Readiness.Valid() {
		return false
	}
	ip := s.IPv4
	if !ip.IsValid() {
		ip = s.IPv6
	}
	timeout := time.Second
	if s.Readiness.TimeoutMS != 0 {
		timeout = time.Duration(s.Readiness.TimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	status, err := probeHTTP(ctx, ip, "GET", s.Readiness.Path, s.Readiness.Port, false, 4096)
	return err == nil && status == http.StatusOK
}

// Both legacy HTTP readiness and lifecycle healthz consume the same bounded
// transport. Body bytes are discarded, never parsed or published as a Result.
func probeHTTP(ctx context.Context, ip netip.Addr, method, path string, port uint16, tls bool, maxBytes int) (int, error) {
	if ctx == nil {
		return 0, ErrPlacement
	}
	uri, err := probeHTTPURL(ip, method, path, port, tls, maxBytes)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, method, uri, nil)
	if err != nil {
		return 0, err
	}
	reply, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer reply.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(reply.Body, int64(maxBytes)))
	if err != nil || ctx.Err() != nil {
		return 0, errors.Join(err, ctx.Err())
	}
	return reply.StatusCode, nil
}
func probeHTTPURL(ip netip.Addr, method, path string, port uint16, tls bool, maxBytes int) (string, error) {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" || port == 0 || maxBytes < 1 || maxBytes > 1<<20 || method != "GET" && method != "HEAD" {
		return "", ErrPlacement
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\x00\r\n#") || u.IsAbs() || u.Host != "" || u.Fragment != "" {
		return "", ErrPlacement
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(ip.String(), strconv.Itoa(int(port))) + path, nil
}
