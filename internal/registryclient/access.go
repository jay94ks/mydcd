// SPDX-License-Identifier: Apache-2.0

// Package registryclient performs bounded OCI registry I/O with explicit
// authority-scoped credentials. It owns no catalog, keychain, cache or server.
package registryclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/access"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	registrytransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

const (
	MaxMetadataBytes int64 = 1 << 20
	MaxImageBytes    int64 = 10 << 30
	MaxLayers              = 4096
)

// Error deliberately retains no URL, response body, authentication challenge,
// provider value or wrapped remote error. It is safe for public observations.
type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

func Sanitize(err error) error {
	if err == nil {
		return nil
	}
	// A plain HTTP registry answers the TLS hello in HTTP. Sources are read
	// over HTTPS only, so name that instead of the rejected HTTP fallback.
	if strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
		return &Error{Code: "PLAIN_HTTP"}
	}
	// The SDK's localhost ping can join an HTTPS dial failure with our
	// deliberate rejection of its HTTP fallback. Preserve the actual network
	// failure instead of letting that secondary AUTH_SCOPE hide it.
	var networkError *net.OpError
	if errors.As(err, &networkError) {
		if errors.Is(err, context.Canceled) {
			return &Error{Code: "CANCELLED"}
		}
		if errors.Is(err, context.DeadlineExceeded) || networkError.Timeout() {
			return &Error{Code: "TIMEOUT"}
		}
		return &Error{Code: "UNAVAILABLE"}
	}
	var own *Error
	if errors.As(err, &own) && ValidResultCode(own.Code) {
		return &Error{Code: own.Code}
	}
	if errors.Is(err, context.Canceled) {
		return &Error{Code: "CANCELLED"}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Code: "TIMEOUT"}
	}
	var remoteError *registrytransport.Error
	if errors.As(err, &remoteError) {
		switch remoteError.StatusCode {
		case 401:
			return &Error{Code: "UNAUTHORIZED"}
		case 403:
			return &Error{Code: "DENIED"}
		case 404:
			return &Error{Code: "NOT_FOUND"}
		case 405, 501:
			return &Error{Code: "UNSUPPORTED"}
		case 429:
			// Docker Hub limits anonymous manifest reads per address.
			return &Error{Code: "RATE_LIMITED"}
		}
	}
	return &Error{Code: "UNAVAILABLE"}
}

type privateAuth struct {
	mu                 sync.Mutex
	username, password []byte
	closed             bool
}

func (a *privateAuth) Authorization() (*authn.AuthConfig, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, &Error{Code: "CLOSED"}
	}
	return &authn.AuthConfig{Username: string(a.username), Password: string(a.password)}, nil
}
func (a *privateAuth) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	clear(a.username)
	clear(a.password)
	a.username = nil
	a.password = nil
}
func (*privateAuth) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted registry credential]")
}

type Access struct {
	authority    string
	auth         *privateAuth
	transport    *http.Transport
	bound        *boundTransport
	certificates [][]byte
	once         sync.Once
}

func (*Access) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted registry access]") }
func (*Access) MarshalJSON() ([]byte, error) { return nil, &Error{Code: "PRIVATE_INPUT"} }

// New copies only transient input. CA adds trust to this client's pool; it
// never changes host trust, daemon configuration or another tenant's client.
func New(authority string, username, password, ca []byte) (*Access, error) {
	if _, err := access.CanonicalTrust([]access.TrustRule{{Registry: authority, Repository: "**"}}); err != nil {
		return nil, &Error{Code: "INVALID_SOURCE"}
	}
	if (len(username) == 0) != (len(password) == 0) || len(username) > 1024 || len(password) > 16<<10 || !utf8.Valid(username) || !utf8.Valid(password) || strings.ContainsAny(string(username), ":\x00\r\n") || len(ca) > 64<<10 {
		return nil, &Error{Code: "INVALID_CREDENTIAL"}
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	var certificates [][]byte
	if len(ca) > 0 {
		certificates, err = parseCertificates(ca)
		if err != nil {
			return nil, err
		}
		for _, raw := range certificates {
			cert, _ := x509.ParseCertificate(raw)
			roots.AddCert(cert)
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &idleConn{Conn: c}, nil
	}
	t := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: dial, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 60 * time.Second, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, MaxResponseHeaderBytes: 64 << 10, ForceAttemptHTTP2: true}
	a := &Access{authority: authority, auth: &privateAuth{username: append([]byte(nil), username...), password: append([]byte(nil), password...)}, transport: t, certificates: certificates}
	a.bound = &boundTransport{authority: authority, inner: t}
	return a, nil
}
func (a *Access) Close() {
	if a == nil {
		return
	}
	a.once.Do(func() { a.auth.close(); a.transport.CloseIdleConnections() })
}
func (a *Access) options(ctx context.Context, platform v1.Platform) []remote.Option {
	return []remote.Option{remote.WithContext(ctx), remote.WithAuth(a.auth), remote.WithTransport(a.bound), remote.WithPlatform(platform), remote.WithJobs(1)}
}
func (a *Access) imageReference(raw string) (name.Digest, error) {
	a.auth.mu.Lock()
	closed := a.auth.closed
	a.auth.mu.Unlock()
	if closed {
		return name.Digest{}, &Error{Code: "CLOSED"}
	}
	image, err := access.PinImage(raw)
	if err != nil || image.Registry != a.authority {
		return name.Digest{}, &Error{Code: "AUTHORITY_MISMATCH"}
	}
	ref, err := name.NewDigest(image.Reference, name.StrictValidation)
	if err != nil {
		return name.Digest{}, &Error{Code: "INVALID_IMAGE"}
	}
	return ref, nil
}

type idleConn struct{ net.Conn }

func (c *idleConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}
func (c *idleConn) Write(p []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

// Image verifies the requested manifest digest (including index selection),
// bounds descriptors before any config/blob is read, and keeps lazy layer I/O
// on this same explicit client. The caller must Close after consuming layers.
func (a *Access) Image(ctx context.Context, raw string, platform v1.Platform) (v1.Image, error) {
	ref, err := a.imageReference(raw)
	if err != nil {
		return nil, err
	}
	image, err := remote.Image(ref, a.options(ctx, platform)...)
	if err != nil {
		return nil, Sanitize(err)
	}
	manifest, err := image.Manifest()
	if err != nil {
		return nil, Sanitize(err)
	}
	if manifest.Config.Digest.Algorithm != "sha256" || manifest.Config.Size < 0 || manifest.Config.Size > MaxMetadataBytes || len(manifest.Layers) > MaxLayers {
		return nil, &Error{Code: "IMAGE_BUDGET"}
	}
	total := manifest.Config.Size
	for _, layer := range manifest.Layers {
		if layer.Digest.Algorithm != "sha256" || layer.Size < 0 || layer.Size > MaxImageBytes-total {
			return nil, &Error{Code: "IMAGE_BUDGET"}
		}
		total += layer.Size
	}
	return image, nil
}

type boundTransport struct {
	authority string
	inner     http.RoundTripper
}

func (b *boundTransport) authHost(host string) bool {
	if host == b.authority {
		return true
	}
	return b.authority == "docker.io" && (host == "index.docker.io" || host == "registry-1.docker.io" || host == "auth.docker.io")
}
func (b *boundTransport) RoundTrip(in *http.Request) (*http.Response, error) {
	if in.URL == nil || in.URL.Scheme != "https" || in.URL.User != nil || in.Host != "" && in.Host != in.URL.Host {
		return nil, &Error{Code: "AUTH_SCOPE"}
	}
	// The library strips original registry authorization on blob redirects.
	// Fail closed if a challenge/redirect instead tries to send it elsewhere.
	if !b.authHost(in.URL.Host) && (in.Header.Get("Authorization") != "" || in.Body != nil || in.Method != http.MethodGet && in.Method != http.MethodHead) {
		return nil, &Error{Code: "AUTH_SCOPE"}
	}
	response, err := b.inner.RoundTrip(in)
	if err != nil {
		return nil, err
	}
	// Metadata/credentials remain small. Blob streams are already limited to
	// verified descriptor sizes by the pinned registry SDK; Image validates
	// config/layer budgets before consumption. Preserve that role on redirects.
	original := in
	for n := 0; n < 10 && original.Response != nil && original.Response.Request != nil; n++ {
		original = original.Response.Request
	}
	if !strings.Contains(original.URL.Path, "/blobs/") || response.StatusCode != http.StatusOK {
		response.Body = &boundedBody{ReadCloser: response.Body, left: MaxMetadataBytes}
	}
	return response, nil
}

type boundedBody struct {
	io.ReadCloser
	left int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, &Error{Code: "METADATA_BUDGET"}
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return 0, &Error{Code: "METADATA_BUDGET"}
	}
	return n, err
}
