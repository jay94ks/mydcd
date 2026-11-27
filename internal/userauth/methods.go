// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Method names one user query and fixes its request and reply types. On the
// wire its request is Request{Schema, Method, Nonce, Params} and its reply
// Reply{Schema, Code, Data}; Params and Data hold exactly P and R.
// See devel/refactor/09-request-reply-union.md.
type Method[P, R any] struct{ Name string }

// methodRule is what the server knows about a typed method.
type methodRule struct {
	// ingress lets a member that runs no workloads serve the method.
	ingress bool
	// sessionless: sent before a session exists (login_methods.go); serve
	// answers it on its own path and never through typedQuery.
	sessionless bool
	decode      func(json.RawMessage) (any, bool)
	run         func(context.Context, Service, cluster.View, access.Session, any) (any, string)
}

var methodRules = map[string]methodRule{}

// validator is implemented by request types with their own field checks.
type validator interface{ Valid() bool }

// define registers a session query. run returns the reply and "ok", or a
// zero reply and a refusal code; refuse adds a symbolic input code to it.
func define[P, R any](m Method[P, R], ingress bool, run func(context.Context, Service, cluster.View, access.Session, P) (R, string)) Method[P, R] {
	if _, exists := methodRules[m.Name]; exists {
		panic("duplicate user method " + m.Name)
	}
	methodRules[m.Name] = methodRule{
		ingress: ingress,
		decode: func(raw json.RawMessage) (any, bool) {
			var p P
			if strict(raw, &p) != nil {
				return nil, false
			}
			if v, ok := any(p).(validator); ok && !v.Valid() {
				return nil, false
			}
			return p, true
		},
		run: func(ctx context.Context, s Service, view cluster.View, session access.Session, p any) (any, string) {
			return run(ctx, s, view, session, p.(P))
		},
	}
	return m
}

// defineSessionless registers a method sent without a session. Only its
// request shape is checked here; serve handles it.
func defineSessionless[P, R any](m Method[P, R]) Method[P, R] {
	if _, exists := methodRules[m.Name]; exists {
		panic("duplicate user method " + m.Name)
	}
	methodRules[m.Name] = methodRule{
		sessionless: true,
		decode: func(raw json.RawMessage) (any, bool) {
			var p P
			if strict(raw, &p) != nil {
				return nil, false
			}
			if v, ok := any(p).(validator); ok && !v.Valid() {
				return nil, false
			}
			return p, true
		},
	}
	return m
}

// refuse joins a refusal code and its symbolic input code (Reply.InputCode,
// for example "conflict" with "COMPACT_VIEW_CHANGED").
func refuse(code, input string) string { return code + " " + input }

// cutRefusal splits what run returned; an input code that is not symbolic is
// dropped, so no free text crosses the boundary.
func cutRefusal(refusal string) (code, input string, ok bool) {
	code, input, ok = strings.Cut(refusal, " ")
	if !validInputCode(input) {
		input = ""
	}
	return code, input, ok
}

// typedMethod says whether r is a typed method, and whether it carries
// nothing but its header and Params.
func (r Request) typedMethod() (methodRule, bool, bool) {
	rule, typed := methodRules[r.Method]
	if !typed {
		return methodRule{}, false, r.Params == nil
	}
	want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Params: r.Params}
	if !reflect.DeepEqual(r, want) || len(r.Params) == 0 {
		return rule, true, false
	}
	_, ok := rule.decode(r.Params)
	return rule, true, ok
}

// typedQuery runs a typed method for a verified session on the leader view.
func (s Service) typedQuery(ctx context.Context, view cluster.View, c access.Catalog, binding userBinding, r Request, envelope Envelope) Reply {
	denied := Reply{Schema: 1, Code: "denied"}
	rule, typed, ok := r.typedMethod()
	if !typed || !ok || rule.sessionless || envelope.Session == nil {
		return denied
	}
	session := *envelope.Session
	policy := s.Policy.Issuer(session.Issuer)
	if session.Key != binding.key || c.VerifySession(session, s.Policy.Cluster, policy, time.Now().Unix()) != nil || access.VerifyRequest(session, binding.challenge, envelope.Body, envelope.Signature) != nil {
		return denied
	}
	p, _ := rule.decode(r.Params)
	result, code := rule.run(ctx, s, view, session, p)
	if code != "ok" {
		code, input, _ := cutRefusal(code)
		return Reply{Schema: 1, Code: code, InputCode: input}
	}
	data, err := json.Marshal(result)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	return Reply{Schema: 1, Code: "ok", Data: data}
}

// Route says which server answered a query and which member relayed it.
type Route struct{ Node, RelayedBy string }

// call sends one typed query and decodes its reply strictly.
func call[P, R any](ctx context.Context, c Client, target sfcp.Peer, session access.Session, m Method[P, R], p P) (R, error) {
	r, _, err := callRoute(ctx, c, target, session, m, p)
	return r, err
}

// callRoute is call that also reports the route the reply took.
func callRoute[P, R any](ctx context.Context, c Client, target sfcp.Peer, session access.Session, m Method[P, R], p P) (R, Route, error) {
	var zero R
	if c.Verify(session) != nil {
		return zero, Route{}, sfcp.ErrAdmission
	}
	if v, ok := any(p).(validator); ok && !v.Valid() {
		return zero, Route{}, sfcp.ErrAdmission
	}
	params, err := json.Marshal(p)
	if err != nil {
		return zero, Route{}, err
	}
	body, err := requestBody(Request{Method: m.Name, Params: params})
	if err != nil {
		return zero, Route{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(conn *sfcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, true)
	if err != nil {
		return zero, Route{}, err
	}
	var result R
	if len(reply.Data) == 0 || strict(reply.Data, &result) != nil {
		return zero, Route{}, sfcp.ErrFrame
	}
	return result, Route{Node: reply.Node, RelayedBy: reply.RelayedBy}, nil
}
