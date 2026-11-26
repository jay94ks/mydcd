// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestLoginClosedLocalRegistryReportsConnectionFailureWithoutHTTP(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	authority := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	a, err := New(authority, []byte("reader"), []byte("private-test-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if code := ResultCode(a.Login(ctx)); code != "UNAVAILABLE" {
		t.Fatal("closed HTTPS endpoint masked by rejected localhost fallback", code)
	}
}

// Actual HTTPS registry protocol and pinned SDK; in-memory registry storage,
// not a real Docker daemon, MyDC authorization or tenant Vault success.
func TestPrivateRegistryTLSUsesOnlyExplicitOwnedCredentialsAndCA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	backend := oci.New(oci.Logger(log.New(io.Discard, "", 0)))
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		user, pass, ok := r.BasicAuth()
		if !ok || user != "reader" || pass != "private-test-password" {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(401)
			return
		}
		backend.ServeHTTP(w, r)
	}))
	defer server.Close()
	authority := strings.TrimPrefix(server.URL, "https://")
	image, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag(authority+"/team/app:current", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Write(tag, image, remote.WithContext(ctx), remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: "reader", Password: "private-test-password"})), remote.WithTransport(server.Client().Transport), remote.WithJobs(1)); err != nil {
		t.Fatal(err)
	}
	digest, err := image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ref := authority + "/team/app@" + digest.String()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	username, password := []byte("reader"), []byte("private-test-password")
	a, err := New(authority, username, password, ca)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	clear(username)
	clear(password)
	if err = a.Login(ctx); err != nil {
		t.Fatal("explicit registry login", err)
	}
	resolved, err := a.Resolve(ctx, tag.String())
	if err != nil || resolved.Digest != digest.String() || resolved.Pinned != ref || resolved.Registry != authority || resolved.Repository != "team/app" {
		t.Fatal("tag resolution changed source coordinates", resolved, err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", a, a), "private-test-password") {
		t.Fatal("private formatter exposed credential")
	}
	if _, err = json.Marshal(a); err == nil {
		t.Fatal("private access serialized")
	}
	got, err := a.Image(ctx, ref, v1.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH})
	if err != nil {
		t.Fatal(err)
	}
	layers, err := got.Layers()
	if err != nil || len(layers) != 1 {
		t.Fatal("lazy layer metadata", err)
	}
	body, err := layers[0].Compressed()
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, body)
	closeErr := body.Close()
	if err != nil || closeErr != nil {
		t.Fatal("verified lazy blob", err, closeErr)
	}
	before := calls.Load()
	if _, err = a.Image(ctx, "foreign.example/team/app@"+digest.String(), v1.Platform{}); err == nil || calls.Load() != before {
		t.Fatal("authority mismatch reached registry")
	}
	a.Close()
	if _, err = a.Image(ctx, ref, v1.Platform{}); err == nil || calls.Load() != before {
		t.Fatal("closed input reused or performed IO")
	}
	wrong, err := New(authority, []byte("reader"), []byte("wrong"), ca)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if err = wrong.Login(ctx); err == nil || err.Error() != "UNAUTHORIZED" {
		t.Fatal("login did not distinguish 401", err)
	}
	if _, err = wrong.Image(ctx, ref, v1.Platform{}); err == nil || err.Error() != "UNAUTHORIZED" {
		t.Fatal("401 code not sanitized", err)
	}
	untrusted, err := New(authority, []byte("reader"), []byte("private-test-password"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.Close()
	untrustedCalls := calls.Load()
	// The pinned SDK tries HTTP after a localhost TLS failure. The owned
	// transport refuses that fallback before I/O and preserves AUTH_SCOPE.
	if _, err = untrusted.Image(ctx, ref, v1.Platform{}); ResultCode(err) != "AUTH_SCOPE" || calls.Load() != untrustedCalls {
		t.Fatal("missing CA bypassed TLS", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRegistryTransportRejectsForeignCredentialBodiesPlainHTTPAndMetadataOverflow(t *testing.T) {
	var calls int
	transport := &boundTransport{authority: "registry.example", inner: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", int(MaxMetadataBytes)+1))), Header: make(http.Header), Request: r}, nil
	})}
	for _, test := range []struct {
		url, method string
		body        io.Reader
		auth        bool
	}{
		{"http://registry.example/v2/", "GET", nil, false},
		{"https://foreign.example/token", "GET", nil, true},
		{"https://foreign.example/token", "POST", strings.NewReader("password=private-test-password"), false},
	} {
		request, err := http.NewRequest(test.method, test.url, test.body)
		if err != nil {
			t.Fatal(err)
		}
		if test.auth {
			request.SetBasicAuth("reader", "private-test-password")
		}
		if _, err = transport.RoundTrip(request); err == nil || calls != 0 {
			t.Fatal("credentials/plaintext passed scoped transport", err, calls)
		}
	}
	request, _ := http.NewRequest("GET", "https://registry.example/v2/team/app/manifests/current", nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err = io.ReadAll(response.Body); err == nil || err.Error() != "METADATA_BUDGET" {
		t.Fatal("metadata grew past bound", err)
	}
}

func TestPlainHTTPRegistryIsNamed(t *testing.T) {
	if got := ResultCode(errors.Join(errors.New("http: server gave HTTP response to HTTPS client"), &Error{Code: "AUTH_SCOPE"})); got != "PLAIN_HTTP" {
		t.Fatal(got)
	}
}
