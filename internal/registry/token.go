// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
)

// Subject is public session provenance inside a signed, registry-only
// credential. The original SFCP proof key/password is never included.
type Subject struct {
	Session *access.Session `json:",omitempty"`
	Task    *TaskSubject    `json:",omitempty"`
	Build   *BuildSubject   `json:",omitempty"`
}

// BuildSubject refers only to an authenticated, committed original image job.
// Empty Image denotes the job's exact output repository; nonempty Image is a
// canonical trusted pull. Current job/authority checks stay at the server.
type BuildSubject struct {
	Tenant, Job    string
	Snapshot, Node [32]byte
	Image          string
}

// TaskSubject fixes accepted app provenance without extending or replaying the
// original user's login session. Current authority is checked by the FSM reader.
type TaskSubject struct {
	Task          deployment.ObjectRef
	Binding, Node [32]byte
	Image         string
}

const MaxGrantSeconds = 300

const TaskUsername = "sfc-task"
const BuildUsername = "sfc-build"

type Grant struct {
	Schema                                  uint8
	Cluster, Issuer                         [32]byte
	Tenant, Registry, Authority, Repository string
	Actions                                 []string
	Subject                                 Subject
	IssuedAt, ExpiresAt                     int64
	Nonce                                   [16]byte
	Signature                               []byte
}

const loginDomain = "sfc-registry-login-1"
const accessDomain = "sfc-registry-access-1"

func grantBytes(g Grant, domain string) []byte {
	g.Signature = nil
	raw, _ := json.Marshal(g)
	return append([]byte(domain+"\x00"), raw...)
}
func (g Grant) valid() bool {
	if g.Schema != 1 || g.Cluster == ([32]byte{}) || g.Issuer == ([32]byte{}) || !scopeName(g.Tenant) || !scopeName(g.Registry) || g.Authority == "" || g.Nonce == ([16]byte{}) || g.IssuedAt <= 0 || g.ExpiresAt <= g.IssuedAt || g.ExpiresAt-g.IssuedAt > MaxGrantSeconds || len(g.Actions) == 0 || len(g.Actions) > 3 || !slices.IsSorted(g.Actions) {
		return false
	}
	if _, err := access.CanonicalTrust([]access.TrustRule{{Registry: g.Authority, Repository: "**"}}); err != nil {
		return false
	}
	for i, action := range g.Actions {
		if i > 0 && action == g.Actions[i-1] {
			return false
		}
		switch action {
		case "login":
			if g.Repository != "" || len(g.Actions) != 1 {
				return false
			}
		case "catalog":
			if g.Repository != "**" || len(g.Actions) != 1 {
				return false
			}
		case "pull", "push":
			if g.Repository == "" {
				return false
			}
		default:
			return false
		}
	}
	if g.Repository != "" && g.Repository != "**" {
		if _, err := repoID(g.Repository); err != nil || strings.Contains(g.Repository, ":") {
			return false
		}
	}
	if session := g.Subject.Session; session != nil {
		return g.Subject.Task == nil && g.Subject.Build == nil && session.Schema == 1 && session.Cluster == g.Cluster && session.ExpiresAt >= g.ExpiresAt
	}
	if build := g.Subject.Build; build != nil {
		if g.Subject.Task != nil || build.Tenant != g.Tenant || !scopeName(build.Job) || build.Snapshot == ([32]byte{}) || build.Node == ([32]byte{}) {
			return false
		}
		if slices.Equal(g.Actions, []string{"login"}) {
			return g.Repository == ""
		}
		if g.Repository == "" || g.Repository == "**" || slices.Contains(g.Actions, "catalog") {
			return false
		}
		if build.Image == "" {
			return true
		}
		image, err := access.PinImage(build.Image)
		return err == nil && image.Reference == build.Image && image.Registry == g.Authority && image.Repository == g.Repository && slices.Equal(g.Actions, []string{"pull"})
	}
	task := g.Subject.Task
	if task == nil || task.Task.Key == "" || task.Task.Revision == 0 || task.Task.Generation == 0 || task.Binding == ([32]byte{}) || task.Node == ([32]byte{}) {
		return false
	}
	image, err := access.PinImage(task.Image)
	if err != nil || image.Reference != task.Image || image.Registry != g.Authority {
		return false
	}
	return slices.Equal(g.Actions, []string{"pull"}) && g.Repository == image.Repository || slices.Equal(g.Actions, []string{"login"}) && g.Repository == ""
}

func issueGrant(g Grant, private ed25519.PrivateKey, domain string) (string, error) {
	if len(private) != ed25519.PrivateKeySize {
		return "", ErrUnauthorized
	}
	g.Schema = 1
	g.Issuer = [32]byte(private.Public().(ed25519.PublicKey))
	if _, err := rand.Read(g.Nonce[:]); err != nil {
		return "", err
	}
	if !g.valid() {
		return "", ErrUnauthorized
	}
	g.Signature = ed25519.Sign(private, grantBytes(g, domain))
	raw, err := json.Marshal(g)
	if err != nil || len(raw) > 8<<10 {
		return "", ErrUnauthorized
	}
	return domain + "." + base64.RawURLEncoding.EncodeToString(raw), nil
}

func parseGrant(raw, domain string, now int64) (Grant, error) {
	var grant Grant
	if !strings.HasPrefix(raw, domain+".") || len(raw) > 12<<10 {
		return grant, ErrUnauthorized
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, domain+"."))
	if err != nil || len(body) > 8<<10 {
		return grant, ErrUnauthorized
	}
	grant, err = schema.Decode[Grant](body)
	if err != nil || !grant.valid() || now < grant.IssuedAt || now >= grant.ExpiresAt || !ed25519.Verify(grant.Issuer[:], grantBytes(grant, domain), grant.Signature) {
		return Grant{}, ErrUnauthorized
	}
	return grant, nil
}

// Login credentials may be used only at the token endpoint, never as access
// tokens or SFCP sessions. These redacted wrappers prevent incidental logging.
type LoginCredential struct{ value string }

func (LoginCredential) MarshalJSON() ([]byte, error) { return nil, ErrUnauthorized }
func (LoginCredential) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted registry credential]")
}
func (c LoginCredential) Bytes() []byte { return []byte(c.value) }
func IssueLogin(g Grant, private ed25519.PrivateKey) (LoginCredential, error) {
	if slices.Contains(g.Actions, "login") {
		return LoginCredential{}, ErrForbidden
	}
	raw, err := issueGrant(g, private, loginDomain)
	return LoginCredential{raw}, err
}
func ParseLogin(raw string, now int64) (Grant, error) { return parseGrant(raw, loginDomain, now) }
func IssueAccess(g Grant, private ed25519.PrivateKey) (TokenResponse, error) {
	raw, err := issueGrant(g, private, accessDomain)
	return TokenResponse{Token: raw, ExpiresIn: g.ExpiresAt - g.IssuedAt}, err
}
func ParseAccess(raw string, now int64) (Grant, error) { return parseGrant(raw, accessDomain, now) }

// Token scope syntax is deliberately one repository. Redundant same-repository
// scope entries are normalized by HTTP; other repositories, refresh grants and
// arbitrary service/audience changes are rejected upstream.
// The optional offline_token boolean hint never causes a refresh token issue.
func RequestedScope(raw string) (string, []string, error) {
	if raw == "" {
		return "", []string{"login"}, nil
	}
	if raw == "registry:catalog:*" {
		return "**", []string{"catalog"}, nil
	}
	parts := strings.Split(raw, ":")
	if len(parts) != 3 || parts[0] != "repository" || parts[1] == "**" {
		return "", nil, ErrForbidden
	}
	if _, err := repoID(parts[1]); err != nil {
		return "", nil, ErrForbidden
	}
	actions := strings.Split(parts[2], ",")
	slices.Sort(actions)
	if len(actions) < 1 || len(actions) > 2 {
		return "", nil, ErrForbidden
	}
	for i, action := range actions {
		if action != "pull" && action != "push" || i > 0 && action == actions[i-1] {
			return "", nil, ErrForbidden
		}
	}
	return parts[1], actions, nil
}

func (g Grant) Allows(repo, action string) bool {
	if action == "login" {
		return true
	} // Current subject authority is still required.
	return (g.Repository == "**" || g.Repository == repo) && slices.Contains(g.Actions, action)
}
func (g Grant) Matches(cluster [32]byte, spec Specification) bool {
	return g.Cluster == cluster && g.Tenant == spec.Tenant && g.Registry == spec.ID && g.Authority == spec.Authority
}
