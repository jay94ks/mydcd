// SPDX-License-Identifier: Apache-2.0

package mydc

import "testing"

// service-call Scheme https; a non-TLS port is SERVICE_CALL_TLS.
func TestServiceCallHTTPS(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	call := ServiceCallRequest{Tenant: "shop", App: "php-shop", Service: "web", Port: 8443, Path: "/decide", Method: "POST", Scheme: ServiceSchemeHTTPS}

	if r, err := alice.(*fakeConn).callService(ctx, call); err != nil || r.Code != "" || r.Status != 200 || string(r.Body) != `{"ok":true}` {
		t.Fatalf("https on 8443 %+v %v", r, err)
	}
	plain := call
	plain.Port = 8080
	if r, _ := alice.(*fakeConn).callService(ctx, plain); r.Code != ServiceCallTLS || r.Body != nil {
		t.Fatalf("https on plain port %+v", r)
	}
	httpToTLS := call
	httpToTLS.Scheme = ""
	if r, _ := alice.(*fakeConn).callService(ctx, httpToTLS); r.Code != "" || r.Status != 400 {
		t.Fatalf("http on TLS port %+v", r)
	}

	// A private certificate needs InsecureSkipVerify.
	f.SetServiceResponder("shop", "php-shop", "web", func(ServiceCallRequest) ServiceResponse {
		return ServiceResponse{Status: 202, Body: []byte("ok"), TLS: true, Untrusted: true}
	})
	if r, _ := alice.(*fakeConn).callService(ctx, call); r.Code != ServiceCallTLS {
		t.Fatalf("untrusted %+v", r)
	}
	skip := call
	skip.InsecureSkipVerify = true
	if r, _ := alice.(*fakeConn).callService(ctx, skip); r.Code != "" || r.Status != 202 {
		t.Fatalf("skip verify %+v", r)
	}

	for _, bad := range []ServiceCallRequest{
		func() ServiceCallRequest { q := call; q.Scheme = "ftp"; return q }(),
		func() ServiceCallRequest { q := plain; q.Scheme = ""; q.InsecureSkipVerify = true; return q }(),
	} {
		_, err := alice.(*fakeConn).callService(ctx, bad)
		wantCode(t, err, CodeInvalid)
	}
}
