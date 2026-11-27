// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/credentials"
)

// ActionIssueInitialCredential publishes a provider-written password or
// single-use token on an account (its payload is the owner-signed
// credentials.InitialFact; Expected is the account revision).
const ActionIssueInitialCredential = "issue-initial-credential"

// InviteIssue is an invitation's single-use token written by the credential
// provider and not yet on the account: Fact is the issue-initial-credential
// payload, Expected its account revision. Token is the secret code: it goes
// only into the one reply that shows the link, never into logs, bbolt or JSON.
type InviteIssue struct {
	Fact      credentials.InitialFact
	Expected  uint64
	ExpiresAt int64 // Unix seconds
	Token     []byte
}

func (InviteIssue) MarshalJSON() ([]byte, error) { return nil, fmt.Errorf("invite token") }
func (InviteIssue) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted invite]") }

// Destroy clears the token.
func (i *InviteIssue) Destroy() {
	clear(i.Token)
	i.Token = nil
}

// IssueInvite runs the provider step of a single-use token for username
// (system administrator): the server it is connected to writes the verifier
// in its default provider. seconds is one of credentials.TokenSeconds; the
// new credential's ID is InviteCredential(ExpiresAt). The caller then submits
// issue-initial-credential with Fact; on any failure nothing is on the
// account and the token is gone.
func (c *realConn) IssueInvite(ctx context.Context, username string, seconds int64) (InviteIssue, error) {
	const m = "initial-credential-stage"
	u, err := c.UserCredentials(ctx, username)
	if err != nil {
		return InviteIssue{}, err
	}
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return InviteIssue{}, err
	}
	defer done()
	profile, err := c.c.InitialCredentialProfile(ctx, c.peer, s)
	if err != nil {
		return InviteIssue{}, realError(m, err)
	}
	r := credentials.InitialRequest{Schema: 1, Cluster: c.c.Cluster, Owner: [32]byte(c.peer.Key), User: u.ID, Username: u.Username, Profile: profile, Method: access.Token, ExpectedUserRevision: u.Revision, At: time.Now().Unix(), Seconds: seconds}
	r.Credential = InviteCredential(r.ExpiresAt())
	if _, err = rand.Read(r.Operation[:]); err != nil || !r.Valid() {
		return InviteIssue{}, fail(m, CodeInvalid, "invitation")
	}
	reply, err := c.c.StageInitialCredential(ctx, c.peer, s, r, nil)
	if err != nil || reply.InitialCredentialFact == nil || len(reply.InitialCredentialToken) == 0 {
		clear(reply.InitialCredentialToken)
		if err == nil {
			err = fmt.Errorf("the credential provider did not confirm")
		}
		return InviteIssue{}, realError(m, err)
	}
	return InviteIssue{Fact: *reply.InitialCredentialFact, Expected: r.ExpectedUserRevision, ExpiresAt: r.ExpiresAt(), Token: reply.InitialCredentialToken}, nil
}

// InviteCredential is a new credential ID for an invitation that expires at
// expiresAt (Unix seconds): the users list reads its expiry from the ID, and
// a random suffix keeps it apart from earlier ones turned off.
func InviteCredential(expiresAt int64) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return InvitePrefix + strconv.FormatInt(expiresAt, 10) + "-" + hex.EncodeToString(b[:])
}

// InvitePrefix starts every invitation's credential ID.
const InvitePrefix = "invite-"

// InviteExpiry is the expiry InviteCredential put in id, if id is one.
func InviteExpiry(id string) (int64, bool) {
	rest, ok := strings.CutPrefix(id, InvitePrefix)
	exp, suffix, ok2 := strings.Cut(rest, "-")
	if !ok || !ok2 || len(suffix) != 8 {
		return 0, false
	}
	if _, err := hex.DecodeString(suffix); err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	return n, err == nil && n > 0 && strconv.FormatInt(n, 10) == exp
}

// fakeInvite is a token the fake issued and keeps until it is published.
type fakeInvite struct {
	user, credential, token string
}

func (c *fakeConn) IssueInvite(ctx context.Context, username string, seconds int64) (InviteIssue, error) {
	const m = "initial-credential-stage"
	actor, err := c.lockSession(ctx, m)
	if err != nil {
		return InviteIssue{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.admin(actor) {
		return InviteIssue{}, fail(m, CodeDenied, "")
	}
	u := w.byName(username)
	if u == nil {
		return InviteIssue{}, fail(m, CodeMissing, "user")
	}
	r := credentials.InitialRequest{Schema: 1, Cluster: w.cluster, Owner: [32]byte(w.issuer.Public().(ed25519.PublicKey)), User: u.rec.ID, Username: u.rec.Username, Profile: "builtin", Method: access.Token, ExpectedUserRevision: u.rec.Revision, At: c.f.now().Unix(), Seconds: seconds}
	r.Credential = InviteCredential(r.ExpiresAt())
	raw := make([]byte, 32)
	_, _ = rand.Read(r.Operation[:])
	_, _ = rand.Read(raw)
	if !r.Valid() {
		return InviteIssue{}, fail(m, CodeInvalid, "invitation")
	}
	fact, err := credentials.SignInitialFact(r, w.issuer)
	if err != nil {
		return InviteIssue{}, fail(m, CodeInvalid, "invitation")
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if w.invites == nil {
		w.invites = map[string]fakeInvite{}
	}
	w.invites[hex.EncodeToString(r.Operation[:])] = fakeInvite{user: u.rec.ID, credential: r.Credential, token: token}
	return InviteIssue{Fact: fact, Expected: r.ExpectedUserRevision, ExpiresAt: r.ExpiresAt(), Token: []byte(token)}, nil
}
