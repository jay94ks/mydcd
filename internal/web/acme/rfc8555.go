// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/jay94ks/mydcd/internal/web/provlog"
)

// Directory is a real ACME directory (RFC 8555) reached with
// golang.org/x/crypto/acme. It has not been run against Let's Encrypt
// from this code base yet; every request goes through the provider
// diagnostic log so the first real run can be checked.
type Directory struct {
	info CAInfo
	// Log is the provider diagnostic log; Transport reaches the CA (nil:
	// http.DefaultTransport).
	Log       *provlog.Log
	Transport http.RoundTripper
}

// NewDirectory returns a CA for info.Directory. info.Ready is set.
func NewDirectory(info CAInfo, log *provlog.Log, tr http.RoundTripper) *Directory {
	info.Ready = true
	return &Directory{info: info, Log: log, Transport: tr}
}

// LetsEncrypt returns Let's Encrypt staging and production.
func LetsEncrypt(log *provlog.Log) []CA {
	kt := []KeyType{EC256, EC384, RSA2048, RSA3072, RSA4096}
	return []CA{
		NewDirectory(CAInfo{ID: "letsencrypt-staging", Name: "Let's Encrypt (시험용)", Directory: "https://acme-staging-v02.api.letsencrypt.org/directory", Staging: true, CAA: "letsencrypt.org", KeyTypes: kt}, log, nil),
		NewDirectory(CAInfo{ID: "letsencrypt", Name: "Let's Encrypt", Directory: "https://acme-v02.api.letsencrypt.org/directory", CAA: "letsencrypt.org", KeyTypes: kt}, log, nil),
	}
}

// Info implements CA.
func (d *Directory) Info() CAInfo { return d.info }

func (d *Directory) client(key crypto.Signer, account string) *xacme.Client {
	tr := provlog.Transport(d.Transport, d.Log, provlog.Source{Provider: "acme:" + d.info.ID, Conn: account, Redact: redactJWS,
		Headers: []string{"Location", "Link"}, Classify: func(status int, body []byte) string {
			var p struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal(body, &p)
			return strings.TrimPrefix(p.Type, "urn:ietf:params:acme:error:")
		}})
	c := &xacme.Client{Key: key, DirectoryURL: d.info.Directory, UserAgent: "mydc-web",
		HTTPClient: &http.Client{Transport: tr, Timeout: 60 * time.Second}}
	if account != "" {
		c.KID = xacme.KeyID(account)
	}
	return c
}

// redactJWS shows a JWS request as its protected header (without the
// nonce) and decoded payload; the signature is left out. A certificate
// response is shortened to its PEM block count.
func redactJWS(body []byte, isReq bool) string {
	if !isReq {
		if s := string(body); strings.Contains(s, "-----BEGIN CERTIFICATE-----") {
			return fmt.Sprintf("[certificate chain: %d PEM blocks]", strings.Count(s, "-----BEGIN CERTIFICATE-----"))
		}
		return string(body)
	}
	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
	}
	if json.Unmarshal(body, &jws) != nil || jws.Protected == "" {
		return string(body)
	}
	dec := func(s string) any {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return "?"
		}
		if len(raw) == 0 {
			return "" // POST-as-GET
		}
		var v any
		if json.Unmarshal(raw, &v) != nil {
			return string(raw)
		}
		return v
	}
	prot, _ := dec(jws.Protected).(map[string]any)
	delete(prot, "nonce")
	delete(prot, "jwk") // public, but long
	pl := dec(jws.Payload)
	if m, ok := pl.(map[string]any); ok {
		if eab, ok := m["externalAccountBinding"].(map[string]any); ok {
			m["externalAccountBinding"] = map[string]any{"protected": dec(fmt.Sprint(eab["protected"]))}
		}
		if csr, ok := m["csr"].(string); ok {
			m["csr"] = fmt.Sprintf("[CSR, %d bytes]", len(csr))
		}
	}
	out, _ := json.Marshal(map[string]any{"protected": prot, "payload": pl})
	return string(out)
}

// The client library retries 429 and badNonce answers until the context
// ends; these bound one call so a long rate-limit wait fails the order
// instead of holding it.
const (
	callTimeout     = 2 * time.Minute
	validateTimeout = 5 * time.Minute
)

// classify maps x/crypto/acme errors to this package's kinds.
func classify(op string, err error) error {
	if err == nil {
		return nil
	}
	var ae *xacme.Error
	if errors.As(err, &ae) {
		if ae.StatusCode == http.StatusTooManyRequests || strings.HasSuffix(ae.ProblemType, ":rateLimited") {
			return fmt.Errorf("%w: %s: %s", ErrRateLimited, op, ae.Detail)
		}
		return fmt.Errorf("%w: %s: %s (%s)", ErrRejected, op, ae.Detail, ae.ProblemType)
	}
	var az *xacme.AuthorizationError
	if errors.As(err, &az) {
		return fmt.Errorf("%w: %s: %s", ErrRejected, op, az.Error())
	}
	var oe *xacme.OrderError
	if errors.As(err, &oe) {
		return fmt.Errorf("%w: %s: order %s", ErrRejected, op, oe.Status)
	}
	return fmt.Errorf("acme %s: %w", op, err)
}

// Register implements CA. An existing account of key is found again.
func (d *Directory) Register(ctx context.Context, key crypto.Signer, email string, eab *EAB) (string, error) {
	ctx, cancel := context.WithTimeout(provlog.WithOp(ctx, "Register"), callTimeout)
	defer cancel()
	c := d.client(key, "")
	a := &xacme.Account{}
	if email != "" {
		a.Contact = []string{"mailto:" + email}
	}
	if eab != nil {
		a.ExternalAccountBinding = &xacme.ExternalAccountBinding{KID: eab.KeyID, Key: eab.HMAC}
	}
	got, err := c.Register(ctx, a, xacme.AcceptTOS) // the person accepted the terms on screen
	if errors.Is(err, xacme.ErrAccountAlreadyExists) {
		got, err = c.GetReg(ctx, "")
	}
	if err != nil {
		return "", classify("register", err)
	}
	return got.URI, nil
}

// NewOrder implements CA.
func (d *Directory) NewOrder(ctx context.Context, key crypto.Signer, account string, names []string, method Method) (Order, error) {
	ctx, cancel := context.WithTimeout(provlog.WithOp(ctx, "NewOrder"), callTimeout)
	defer cancel()
	c := d.client(key, account)
	ids := make([]xacme.AuthzID, len(names))
	for i, n := range names {
		ids[i] = xacme.AuthzID{Type: "dns", Value: n}
	}
	o, err := c.AuthorizeOrder(ctx, ids)
	if err != nil {
		return Order{}, classify("new order", err)
	}
	out := Order{URL: o.URI, Names: append([]string(nil), names...)}
	for _, u := range o.AuthzURLs {
		az, err := c.GetAuthorization(provlog.WithOp(ctx, "GetAuthorization"), u)
		if err != nil {
			return Order{}, classify("authorization", err)
		}
		name := az.Identifier.Value
		if az.Wildcard {
			name = "*." + name
		}
		if az.Status == xacme.StatusValid {
			continue // still valid from an earlier order: no challenge needed
		}
		typ := pick(method, name)
		var ch *xacme.Challenge
		for _, x := range az.Challenges {
			if x.Type == typ {
				ch = x
			}
		}
		if ch == nil {
			return Order{}, fmt.Errorf("%w: %s offers no %s challenge", ErrRejected, name, typ)
		}
		cc := Challenge{Name: name, Type: typ, URL: ch.URI, Authz: u}
		if typ == HTTP01 {
			ka, err := c.HTTP01ChallengeResponse(ch.Token)
			if err != nil {
				return Order{}, err
			}
			cc.Token, cc.KeyAuth = ch.Token, ka
		} else {
			v, err := c.DNS01ChallengeRecord(ch.Token)
			if err != nil {
				return Order{}, err
			}
			cc.TXTName, cc.TXTValue = ChallengeName(name), v
		}
		out.Challenges = append(out.Challenges, cc)
	}
	return out, nil
}

// Validate implements CA: accept every challenge, then wait until each
// authorization and the order are ready.
func (d *Directory) Validate(ctx context.Context, key crypto.Signer, account string, o Order) error {
	ctx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()
	c := d.client(key, account)
	for _, ch := range o.Challenges {
		if _, err := c.Accept(provlog.WithOp(ctx, "Accept"), &xacme.Challenge{Type: ch.Type, URI: ch.URL}); err != nil {
			return classify("accept "+ch.Name, err)
		}
	}
	for _, ch := range o.Challenges {
		if _, err := c.WaitAuthorization(provlog.WithOp(ctx, "WaitAuthorization"), ch.Authz); err != nil {
			return classify("validate "+ch.Name, err)
		}
	}
	if _, err := c.WaitOrder(provlog.WithOp(ctx, "WaitOrder"), o.URL); err != nil {
		return classify("order", err)
	}
	return nil
}

// Finalize implements CA.
func (d *Directory) Finalize(ctx context.Context, key crypto.Signer, account string, o Order, csr []byte) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(provlog.WithOp(ctx, "Finalize"), callTimeout)
	defer cancel()
	c := d.client(key, account)
	ord, err := c.GetOrder(ctx, o.URL)
	if err != nil {
		return nil, classify("order", err)
	}
	chain, _, err := c.CreateOrderCert(ctx, ord.FinalizeURL, csr, true)
	if err != nil {
		return nil, classify("finalize", err)
	}
	return chain, nil
}

// Revoke implements CA (signed by the account key).
func (d *Directory) Revoke(ctx context.Context, key crypto.Signer, account string, certDER []byte) error {
	ctx, cancel := context.WithTimeout(provlog.WithOp(ctx, "Revoke"), callTimeout)
	defer cancel()
	return classify("revoke", d.client(key, account).RevokeCert(ctx, nil, certDER, xacme.CRLReasonUnspecified))
}
