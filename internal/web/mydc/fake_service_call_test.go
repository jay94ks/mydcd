// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"testing"
)

func TestServiceCall(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	call := ServiceCallRequest{Tenant: "shop", App: "php-shop", Service: "web", Port: 8080, Path: "/decide", Method: "POST",
		Headers: map[string]string{"Content-Type": "application/json", "X-MyDC-Event": "cd-approval-required"}, Body: []byte(`{}`)}

	r, err := alice.(*fakeConn).callService(ctx, call)
	if err != nil || r.Code != "" || r.Status != 200 || string(r.Body) != `{"ok":true}` || r.Task != "1" || r.Node != "node-a" {
		t.Fatalf("default %+v %v", r, err)
	}
	var got ServiceCallRequest
	f.SetServiceResponder("shop", "php-shop", "web", func(q ServiceCallRequest) ServiceResponse {
		got = q
		return ServiceResponse{Status: 409, ContentType: "text/plain", Body: []byte("hold"), ElapsedMS: 40}
	})
	if r, _ := alice.(*fakeConn).callService(ctx, call); r.Status != 409 || string(r.Body) != "hold" || got.Path != "/decide" {
		t.Fatalf("responder %+v %+v", r, got)
	}
	f.SetServiceResponder("shop", "php-shop", "web", func(ServiceCallRequest) ServiceResponse { return ServiceResponse{ElapsedMS: 31000} })
	if r, _ := alice.(*fakeConn).callService(ctx, call); r.Code != ServiceCallTimeout {
		t.Fatalf("timeout %+v", r)
	}
	f.SetServiceResponder("shop", "php-shop", "web", func(ServiceCallRequest) ServiceResponse { return ServiceResponse{Refused: true} })
	if r, _ := alice.(*fakeConn).callService(ctx, call); r.Code != ServiceCallRefused {
		t.Fatalf("refused %+v", r)
	}
	f.SetServiceResponder("shop", "php-shop", "web", func(ServiceCallRequest) ServiceResponse {
		return ServiceResponse{Status: 200, Body: make([]byte, ServiceCallMaxResponse+1)}
	})
	if r, _ := alice.(*fakeConn).callService(ctx, call); r.Code != ServiceCallTooLarge || r.Body != nil {
		t.Fatalf("large response %+v", r.Code)
	}
	f.SetServiceResponder("shop", "php-shop", "web", nil)
	big := call
	big.Body = make([]byte, ServiceCallMaxBody+1)
	if r, _ := alice.(*fakeConn).callService(ctx, big); r.Code != ServiceCallTooLarge {
		t.Fatalf("large request %+v", r.Code)
	}

	// Down: no ready task.
	f.SetTaskReady("shop", "php-shop", "web", "1", false)
	if r, _ := alice.(*fakeConn).callService(ctx, call); r.Code != ServiceNoReadyTask {
		t.Fatalf("down %+v", r)
	}
	f.SetTaskReady("shop", "php-shop", "web", "1", true)

	// Input and permission.
	for _, bad := range []func(*ServiceCallRequest){
		func(q *ServiceCallRequest) { q.Method = "GET" },
		func(q *ServiceCallRequest) { q.Path = "http://10.0.0.1/x" },
		func(q *ServiceCallRequest) { q.Headers = map[string]string{"Authorization": "x"} },
		func(q *ServiceCallRequest) { q.TimeoutMS = 30001 },
	} {
		q := call
		bad(&q)
		_, err := alice.(*fakeConn).callService(ctx, q)
		wantCode(t, err, CodeInvalid)
	}
	_, err = bob.(*fakeConn).callService(ctx, call)
	wantCode(t, err, CodeDenied)
	other := call
	other.Tenant, other.App, other.Service = "payments", "payments-api", "api"
	_, err = bob.(*fakeConn).callService(ctx, other)
	wantCode(t, err, CodeDenied)

	// Rate limit per tenant per minute.
	f.SetServiceCallLimit(1)
	if r, _ := alice.(*fakeConn).callService(ctx, call); r.Code != ServiceCallRateLimited {
		t.Fatalf("limit %+v", r)
	}
}
