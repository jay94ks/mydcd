// SPDX-License-Identifier: Apache-2.0

package mydc

// REQ-24 fake internals (the Conn method is CallService,
// fake_service_real.go): `service-call`, one HTTP request from inside a tenant
// network to an app service, for cluster-internal webhooks. The target is a
// tenant/app/service/port only (no IP or host name), POST only, redirects
// are not followed. mydcd picks a task that passed its checks (same server
// first). Permission: tenant CallService (in the fake: manager) or system
// administrator. Calls are not journaled. A failed call is a Code in the
// result, not an error; permission and input errors are errors.

const (
	ServiceCallMaxBody     = 256 << 10 // request
	ServiceCallMaxResponse = 64 << 10
	ServiceCallMaxTimeout  = 30000 // ms
)

// Codes of serviceCallResult ("" = the service answered).
const (
	ServiceNoReadyTask     = "SERVICE_NO_READY_TASK"
	ServiceCallTimeout     = "SERVICE_CALL_TIMEOUT"
	ServiceCallRefused     = "SERVICE_CALL_REFUSED"
	ServiceCallTooLarge    = "SERVICE_CALL_TOO_LARGE" // request or response over its limit
	ServiceCallRateLimited = "RATE_LIMITED"
	// ServiceCallTLS: Scheme https and the TLS handshake
	// failed (the port does not speak TLS, or the certificate did not
	// verify without InsecureSkipVerify).
	ServiceCallTLS = "SERVICE_CALL_TLS"
)

// Scheme of ServiceCallRequest (REQ-55, mock; "" = http).
const (
	ServiceSchemeHTTP  = "http"
	ServiceSchemeHTTPS = "https"
)

type ServiceCallRequest struct {
	Tenant, App, Service string
	Port                 int
	Path                 string            // starts with "/"
	Method               string            // "POST"
	Headers              map[string]string `json:",omitempty"` // Content-Type, X-MyDC-*
	Body                 []byte            `json:",omitempty"`
	TimeoutMS            int               // 1..30000 (0 = 10000)
	// Scheme / InsecureSkipVerify: REQ-55 (mock). https connects to the
	// task with TLS; the certificate is checked against the tenant CA
	// bundle unless InsecureSkipVerify.
	Scheme             string `json:",omitempty"`
	InsecureSkipVerify bool   `json:",omitempty"`
}

type serviceCallResult struct {
	Code        string `json:",omitempty"`
	Status      int    `json:",omitempty"`
	ContentType string `json:",omitempty"`
	Body        []byte `json:",omitempty"`
	Task        string `json:",omitempty"` // instance
	Node        string `json:",omitempty"`
	ElapsedMS   int
}

// ServiceResponse is what a Fake responder answers. Refused models a
// closed port; ElapsedMS past the request timeout gives the timeout code.
type ServiceResponse struct {
	Status      int
	ContentType string
	Body        []byte
	ElapsedMS   int
	Refused     bool
	// TLS: the port speaks TLS. Untrusted: its certificate is not
	// trusted by the tenant CA bundle (only InsecureSkipVerify gets through).
	TLS, Untrusted bool
}
