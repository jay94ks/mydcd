// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/loginlog"
)

// The methods a client sends before it has a session (R09 2c). Their
// requests and replies are typed like every other method, but serve answers
// them on their own paths: server-version without a catalog, the logins
// with the connection's binding and, for a private-key login on a member
// that issues no sessions, a relay to the leader (forwardLogin).

// ChallengeQuery asks for a private-key login ticket for Username's key
// UserKey.
type ChallengeQuery struct {
	Username string
	UserKey  [32]byte
}

func (q ChallengeQuery) Valid() bool { return q.Username != "" && q.UserKey != ([32]byte{}) }

// KeyLoginQuery sends a ticket's signed key proof.
type KeyLoginQuery struct {
	Ticket      Ticket
	Proof       access.KeyProof
	LoginClient *loginlog.Client `json:",omitempty"`
}

func (q KeyLoginQuery) Valid() bool { return q.LoginClient == nil || q.LoginClient.Valid() }

// CredentialChallengeQuery asks for a password or token login ticket.
// Credential, when set, names one credential of that method.
type CredentialChallengeQuery struct {
	Username   string
	AuthMethod access.Method
	Credential string `json:",omitempty"`
}

func (q CredentialChallengeQuery) Valid() bool {
	return q.Username != "" && (q.AuthMethod == access.Password || q.AuthMethod == access.Token)
}

// CredentialLoginQuery sends the secret for a credential ticket. The
// request is signed with the session key over its body (credentialLoginBytes).
type CredentialLoginQuery struct {
	Ticket      Ticket
	Secret      []byte
	LoginClient *loginlog.Client `json:",omitempty"`
}

func (q CredentialLoginQuery) Valid() bool {
	return len(q.Secret) > 0 && len(q.Secret) <= 1024 && (q.Ticket.AuthMethod == access.Password || q.Ticket.AuthMethod == access.Token) && (q.LoginClient == nil || q.LoginClient.Valid())
}

var (
	ServerVersionMethod       = defineSessionless(Method[NoParams, ServerVersion]{Name: "server-version"})
	ChallengeMethod           = defineSessionless(Method[ChallengeQuery, Ticket]{Name: "challenge"})
	LoginMethod               = defineSessionless(Method[KeyLoginQuery, access.Session]{Name: "login"})
	CredentialChallengeMethod = defineSessionless(Method[CredentialChallengeQuery, Ticket]{Name: "credential-challenge"})
	CredentialLoginMethod     = defineSessionless(Method[CredentialLoginQuery, access.Session]{Name: "credential-login"})
)

// sessionlessRequest is a request for m with Params p.
func sessionlessRequest[P, R any](m Method[P, R], p P) ([]byte, error) {
	params, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	defer clear(params)
	return requestBody(Request{Method: m.Name, Params: params})
}

// paramsOf decodes r's Params as m's request, when r carries exactly them.
func paramsOf[P, R any](r Request, m Method[P, R]) (P, bool) {
	var zero P
	if r.Method != m.Name {
		return zero, false
	}
	rule, typed, ok := r.typedMethod()
	if !typed || !ok {
		return zero, false
	}
	p, _ := rule.decode(r.Params)
	v, ok := p.(P)
	return v, ok
}

// sessionlessReply is an "ok" reply carrying v.
func sessionlessReply(v any) Reply {
	data, err := json.Marshal(v)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	return Reply{Schema: 1, Code: "ok", Data: data}
}

// replyData decodes an "ok" reply's Data strictly.
func replyData[T any](reply Reply) (T, bool) {
	var v T
	return v, len(reply.Data) != 0 && lenient(reply.Data, &v) == nil
}
