// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	registrytransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/jay94ks/mydcd/internal/access"
)

// PullTokenChallenge is public registry protocol input, not authority to read
// credentials. The owner verifies it against the registry's actual challenge.
type PullTokenChallenge struct {
	Host, Realm, Service string
	Scopes               []string
}

func (q PullTokenChallenge) Valid(image string) bool {
	return q.ValidForImages([]string{image})
}

func (q PullTokenChallenge) ValidForImages(images []string) bool {
	if len(images) == 0 || len(images) > 8 || len(q.Realm) == 0 || len(q.Realm) > 2048 || len(q.Service) > 1024 || strings.ContainsAny(q.Service, "\x00\r\n") || len(q.Scopes) == 0 || len(q.Scopes) > 8 {
		return false
	}
	allowed := make(map[string]bool, len(images))
	for _, image := range images {
		parsed, err := access.PinImage(image)
		if err != nil || parsed.Reference != image || q.Host != parsed.Registry && !(parsed.Registry == "docker.io" && (q.Host == "registry-1.docker.io" || q.Host == "index.docker.io")) {
			return false
		}
		allowed["repository:"+parsed.Repository+":pull"] = true
	}
	u, err := url.Parse(q.Realm)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	for _, scope := range q.Scopes {
		if !allowed[scope] {
			return false
		}
	}
	for scope := range allowed {
		if !slices.Contains(q.Scopes, scope) {
			return false
		}
	}
	return true
}

// PullToken is transient authenticated transport output. Never persist or log
// it in a job, observation or error. No refresh token/password is returned.
type PullToken struct {
	Token               string
	IssuedAt, ExpiresIn int64
}

func (t PullToken) Valid() bool {
	return len(t.Token) > 0 && len(t.Token) <= 16<<10 && !strings.ContainsAny(t.Token, "\x00\r\n\t ") && t.IssuedAt > 0 && t.IssuedAt <= math.MaxInt64-86400 && t.ExpiresIn > 0 && t.ExpiresIn <= 86400
}

func (PullToken) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted registry pull token]")
}

// FetchPullToken delegates exchange to the pinned OCI library, with the same
// owner-only explicit credential/CA and redirect bounds as ordinary pulls.
// An untrusted BuildKit challenge cannot turn this into a credential oracle.
func (a *Access) FetchPullToken(ctx context.Context, image string, q PullTokenChallenge) (PullToken, error) {
	return a.FetchPullTokenForImages(ctx, []string{image}, q)
}

// All images must already have been authorized for this same credential
// owner. This protocol validator never chooses credentials from a hostname.
func (a *Access) FetchPullTokenForImages(ctx context.Context, images []string, q PullTokenChallenge) (PullToken, error) {
	if !q.ValidForImages(images) {
		return PullToken{}, &Error{Code: "AUTH_SCOPE"}
	}
	for _, image := range images {
		if _, err := a.imageReference(image); err != nil {
			return PullToken{}, err
		}
	}
	ref, err := a.imageReference(images[0])
	if err != nil {
		return PullToken{}, err
	}
	reg, err := name.NewRegistry(ref.Context().RegistryStr(), name.StrictValidation)
	if err != nil {
		return PullToken{}, &Error{Code: "INVALID_IMAGE"}
	}
	challenge, err := registrytransport.Ping(ctx, reg, a.bound)
	if err != nil {
		return PullToken{}, Sanitize(err)
	}
	if challenge == nil || !strings.EqualFold(challenge.Scheme, "bearer") {
		return PullToken{}, &Error{Code: "UNSUPPORTED"}
	}
	if challenge.Insecure || challenge.Parameters["realm"] != q.Realm || challenge.Parameters["service"] != q.Service {
		return PullToken{}, &Error{Code: "AUTH_SCOPE"}
	}
	issuedAt := time.Now().Unix()
	scopes := slices.Clone(q.Scopes)
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	token, err := registrytransport.Exchange(ctx, reg, a.auth, a.bound, scopes, challenge)
	if err != nil {
		return PullToken{}, Sanitize(err)
	}
	if token == nil {
		return PullToken{}, &Error{Code: "UNAUTHORIZED"}
	}
	defer func() { token.RefreshToken = "" }()
	result := PullToken{Token: token.Token, IssuedAt: issuedAt, ExpiresIn: int64(token.ExpiresIn)}
	if token.AccessToken != "" {
		result.Token = token.AccessToken
	}
	if result.ExpiresIn == 0 {
		result.ExpiresIn = 60 // OCI token response default, not an infinite grant
	}
	result.ExpiresIn = min(result.ExpiresIn, 86400)
	if !result.Valid() {
		return PullToken{}, &Error{Code: "UNAUTHORIZED"}
	}
	return result, nil
}
