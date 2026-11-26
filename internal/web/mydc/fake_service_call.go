// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"net/textproto"
	"slices"
	"strings"
)

// REQ-24 in the fake. Fake.SetServiceResponder answers calls to one
// service (default: 200 application/json {"ok":true}, 3 ms). A task is
// ready when observed running and healthy (or without checks); the task on
// the first server of the tenant is chosen first. Fake.SetTaskReady flips
// readiness; Fake.SetServiceCallLimit sets calls per tenant per minute.
// the default answer speaks TLS on ports 443 and 8443 (a trusted
// certificate) and plain HTTP elsewhere; a responder sets
// ServiceResponse.TLS / Untrusted itself. https to a plain port, or to an
// untrusted certificate without InsecureSkipVerify, is SERVICE_CALL_TLS;
// plain http to a TLS port gets the server's 400.

type serviceCalls struct {
	responders map[string]func(ServiceCallRequest) ServiceResponse // tenant/app/service
	perMinute  int
	window     int64 // unix minute
	count      map[string]int
	notReady   map[string]bool // taskKey
}

func (w *world) svcCalls() *serviceCalls {
	if w.svc == nil {
		w.svc = &serviceCalls{responders: map[string]func(ServiceCallRequest) ServiceResponse{}, perMinute: 600, count: map[string]int{}, notReady: map[string]bool{}}
	}
	return w.svc
}

// SetServiceResponder sets the answer of tenant/app/service (nil = default).
func (f *Fake) SetServiceResponder(tenant, app, service string, fn func(ServiceCallRequest) ServiceResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.svcCalls().responders[tenant+"/"+app+"/"+service] = fn
}

// SetServiceCallLimit sets the per-tenant calls per minute.
func (f *Fake) SetServiceCallLimit(perMinute int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.svcCalls().perMinute = perMinute
}

// SetTaskReady marks one task as passing (or failing) its checks for
// service-call.
func (f *Fake) SetTaskReady(tenant, app, service, instance string, ready bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.taskFor(tenant, app, service, instance)
	f.w.svcCalls().notReady[tenant+"/"+app+"/"+service+"/"+instance] = !ready
}

func (c *fakeConn) callService(ctx context.Context, q ServiceCallRequest) (serviceCallResult, error) {
	const m = "service-call"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return serviceCallResult{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canManage(user, q.Tenant) {
		return serviceCallResult{}, fail(m, CodeDenied, "")
	}
	if q.Method != "POST" || q.Port < 1 || q.Port > 65535 || !strings.HasPrefix(q.Path, "/") || strings.Contains(q.Path, "://") ||
		q.TimeoutMS < 0 || q.TimeoutMS > ServiceCallMaxTimeout ||
		q.Scheme != "" && q.Scheme != ServiceSchemeHTTP && q.Scheme != ServiceSchemeHTTPS || q.InsecureSkipVerify && q.Scheme != ServiceSchemeHTTPS {
		return serviceCallResult{}, fail(m, CodeInvalid, "target: POST to /path on a service port, timeout ≤ 30 s")
	}
	for k := range q.Headers {
		k = textproto.CanonicalMIMEHeaderKey(k)
		if k != "Content-Type" && !strings.HasPrefix(k, "X-Mydc-") {
			return serviceCallResult{}, fail(m, CodeInvalid, "header "+k+": only Content-Type and X-MyDC-*")
		}
	}
	a := w.apps[q.Tenant+"/"+q.App]
	if a == nil || !slices.ContainsFunc(a.tasks, func(t Task) bool { return t.Service == q.Service }) {
		return serviceCallResult{}, fail(m, CodeMissing, "no such service")
	}
	if len(q.Body) > ServiceCallMaxBody {
		return serviceCallResult{Code: ServiceCallTooLarge}, nil
	}
	s := w.svcCalls()
	if minute := c.f.now().Unix() / 60; minute != s.window {
		s.window, s.count = minute, map[string]int{}
	}
	if s.count[q.Tenant] >= s.perMinute {
		return serviceCallResult{Code: ServiceCallRateLimited}, nil
	}
	s.count[q.Tenant]++
	var pick *Task
	var order []string
	order = append(order, w.tenantNodes[q.Tenant]...)
	for _, n := range append(order, "") {
		for i := range a.tasks {
			t := &a.tasks[i]
			ready := t.Service == q.Service && t.Observed == "running" && (t.Health == "healthy" || t.Health == "none" || t.Health == "") && !s.notReady[taskKey(*t)]
			if ready && (n == "" || t.Node == n) {
				pick = t
				break
			}
		}
		if pick != nil {
			break
		}
	}
	if pick == nil {
		return serviceCallResult{Code: ServiceNoReadyTask}, nil
	}
	resp := ServiceResponse{Status: 200, ContentType: "application/json", Body: []byte(`{"ok":true}`), ElapsedMS: 3, TLS: q.Port == 443 || q.Port == 8443}
	if fn := s.responders[q.Tenant+"/"+q.App+"/"+q.Service]; fn != nil {
		resp = fn(q)
	}
	out := serviceCallResult{Task: pick.Instance, Node: pick.Node, ElapsedMS: resp.ElapsedMS}
	timeout := q.TimeoutMS
	if timeout == 0 {
		timeout = 10000
	}
	switch {
	case resp.Refused:
		out.Code = ServiceCallRefused
	case q.Scheme == ServiceSchemeHTTPS && (!resp.TLS || resp.Untrusted && !q.InsecureSkipVerify):
		out.Code = ServiceCallTLS
	case q.Scheme != ServiceSchemeHTTPS && resp.TLS:
		out.Status, out.ContentType, out.Body = 400, "text/plain; charset=utf-8", []byte("Client sent an HTTP request to an HTTPS server.\n")
	case resp.ElapsedMS > timeout:
		out.Code, out.ElapsedMS = ServiceCallTimeout, timeout
	case len(resp.Body) > ServiceCallMaxResponse:
		out.Code = ServiceCallTooLarge
	default:
		out.Status, out.ContentType, out.Body = resp.Status, resp.ContentType, slices.Clone(resp.Body)
	}
	return out, nil
}
