// SPDX-License-Identifier: Apache-2.0

// Package servicecall implements one bounded request to a currently authorized
// logical service. Target addresses come exclusively from committed Task data.
package servicecall

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/containerops"
	"golang.org/x/net/http/httpguts"
)

const (
	MaxBody     = 256 << 10
	MaxResponse = 64 << 10
	MaxTimeout  = 30000
	NoReadyTask = "SERVICE_NO_READY_TASK"
	Timeout     = "SERVICE_CALL_TIMEOUT"
	Refused     = "SERVICE_CALL_REFUSED"
	TooLarge    = "SERVICE_CALL_TOO_LARGE"
	TLS         = "SERVICE_CALL_TLS"
	RateLimited = "RATE_LIMITED"
)

var ErrInvalid = errors.New("invalid service call")
var errTLS = errors.New("service TLS handshake failed")

type Request struct {
	App, Service       string
	Port               int
	Path, Method       string
	Headers            map[string]string `json:",omitempty"`
	Body               []byte            `json:",omitempty"`
	TimeoutMS          int
	Scheme             string `json:",omitempty"`
	InsecureSkipVerify bool   `json:",omitempty"`
}

func (q Request) Valid() bool {
	if !lifecycle.ValidID(q.App) || !lifecycle.ValidID(q.Service) || q.Port < 1 || q.Port > 65535 || q.Method != "POST" || q.TimeoutMS < 0 || q.TimeoutMS > MaxTimeout || len(q.Body) > MaxBody || len(q.Path) > 4096 || !strings.HasPrefix(q.Path, "/") || strings.HasPrefix(q.Path, "//") || strings.ContainsAny(q.Path, "\x00\r\n") || q.Scheme != "" && q.Scheme != "http" && q.Scheme != "https" || q.InsecureSkipVerify && q.Scheme != "https" || len(q.Headers) > 32 {
		return false
	}
	u, err := url.ParseRequestURI(q.Path)
	if err != nil || u.Host != "" || u.Scheme != "" || u.User != nil || u.Fragment != "" {
		return false
	}
	budget := 0
	seen := map[string]bool{}
	for key, value := range q.Headers {
		name := http.CanonicalHeaderKey(key)
		if !httpguts.ValidHeaderFieldName(key) || !httpguts.ValidHeaderFieldValue(value) || name != "Content-Type" && (!strings.HasPrefix(name, "X-Mydc-") || len(name) == len("X-Mydc-")) || seen[name] {
			return false
		}
		seen[name] = true
		budget += len(key) + len(value)
	}
	return budget <= 8<<10
}
func (q Request) Duration() time.Duration {
	if q.TimeoutMS == 0 {
		return 10 * time.Second
	}
	return time.Duration(q.TimeoutMS) * time.Millisecond
}

type Target struct {
	Container containerops.Target
	Address   netip.Addr
	Port      uint16
}

func (t Target) Valid() bool {
	return t.Container.Valid() && t.Container.NativeID != "" && t.Address.IsValid() && !t.Address.IsUnspecified() && !t.Address.IsMulticast() && !t.Address.IsLoopback() && !t.Address.IsLinkLocalUnicast() && !t.Address.Is4In6() && t.Address.Zone() == "" && t.Port > 0
}

type Result struct {
	Code       string            `json:",omitempty"`
	Status     int               `json:",omitempty"`
	Headers    map[string]string `json:",omitempty"`
	Body       []byte            `json:",omitempty"`
	Task, Node string            `json:",omitempty"`
	ElapsedMS  int64
}

func (r Result) Valid() bool {
	if r.ElapsedMS < 0 || len(r.Body) > MaxResponse || len(r.Headers) > 1 {
		return false
	}
	for k, v := range r.Headers {
		if k != "Content-Type" || len(v) > 4096 || !httpguts.ValidHeaderFieldValue(v) {
			return false
		}
	}
	if r.Code != "" {
		switch r.Code {
		case NoReadyTask, Timeout, Refused, TooLarge, TLS, RateLimited:
		default:
			return false
		}
		return r.Status == 0 && len(r.Body) == 0 && len(r.Headers) == 0
	}
	return r.Status >= 100 && r.Status <= 599 && r.Task != "" && lifecycle.ValidID(r.Node)
}

// Execute owns no authority: the native adapter must hold the original Task
// lease and current permission through this call. Redirects and proxies are off.
func Execute(ctx context.Context, q Request, target Target, roots *x509.CertPool) (out Result, err error) {
	if !q.Valid() || !target.Valid() || int(target.Port) != q.Port || target.Container.App != q.App || target.Container.Service != q.Service {
		return out, ErrInvalid
	}
	started := time.Now()
	out.Task, out.Node = target.Container.Instance, target.Container.Node
	defer func() { out.ElapsedMS = time.Since(started).Milliseconds() }()
	ctx, cancel := context.WithTimeout(ctx, q.Duration())
	defer cancel()
	scheme := q.Scheme
	if scheme == "" {
		scheme = "http"
	}
	endpoint := net.JoinHostPort(target.Address.String(), strconv.Itoa(q.Port))
	dialer := net.Dialer{Timeout: q.Duration(), KeepAlive: -1}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ResponseHeaderTimeout: q.Duration(), MaxResponseHeaderBytes: 32 << 10, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != endpoint {
			return nil, ErrInvalid
		}
		return dialer.DialContext(ctx, "tcp", endpoint)
	}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != endpoint {
			return nil, ErrInvalid
		}
		conn, err := dialer.DialContext(ctx, "tcp", endpoint)
		if err != nil {
			return nil, err
		}
		secure := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: target.Address.String(), InsecureSkipVerify: q.InsecureSkipVerify, NextProtos: []string{"http/1.1"}})
		if err := secure.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, errors.Join(errTLS, err)
		}
		return secure, nil
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: q.Duration(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u, err := url.Parse(q.Path)
	if err != nil {
		return out, ErrInvalid
	}
	u.Scheme, u.Host = scheme, endpoint
	request, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(q.Body))
	if err != nil {
		return out, ErrInvalid
	}
	for key, value := range q.Headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		out.Code = Refused
		var timeout net.Error
		if ctx.Err() != nil || errors.As(err, &timeout) && timeout.Timeout() {
			out.Code = Timeout
		} else if errors.Is(err, errTLS) {
			out.Code = TLS
		}
		return out, nil
	}
	defer response.Body.Close()
	if response.ContentLength > MaxResponse || len(response.Header.Get("Content-Type")) > 4096 {
		out.Code = TooLarge
		return out, nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponse+1))
	if err != nil {
		out.Code = Refused
		if ctx.Err() != nil {
			out.Code = Timeout
		}
		return out, nil
	}
	if len(body) > MaxResponse {
		out.Code = TooLarge
		return out, nil
	}
	out.Status, out.Body = response.StatusCode, body
	if value := response.Header.Get("Content-Type"); value != "" {
		out.Headers = map[string]string{"Content-Type": value}
	}
	return out, nil
}
