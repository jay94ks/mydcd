// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/distribution/reference"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

// ContextSpec contains public configuration and Vault references only. Git
// credentials are selected by the existing node-local credential profile.
type ContextSpec struct {
	Tenant, ID, Kind string
	Root             nodestorage.Reference
	Dockerfile       string
	Arguments        map[string]string `json:",omitempty"`
	Secrets          []SecretMount     `json:",omitempty"`
	Repository       string
	Tags             []string
	Platforms        []string
	Git              *GitContext `json:",omitempty"`
}
type SecretMount struct{ ID, Realm, Secret, Key string }
type GitContext struct {
	Repository, Ref, Path, CredentialProfile string
	Automatic                                bool
}

func (c ContextSpec) Validate() error {
	if !lifecycle.ValidID(c.Tenant) || !lifecycle.ValidID(c.ID) || c.Root.Validate() != nil || !ContextPath(c.Dockerfile) || c.Kind != "upload" && c.Kind != "git" && c.Kind != "draft" || (c.Kind == "git") != (c.Git != nil) || len(c.Arguments) > 128 || len(c.Secrets) > 32 || len(c.Tags) == 0 || len(c.Tags) > 16 || len(c.Platforms) == 0 || len(c.Platforms) > 16 || len(c.Repository) > 255 || c.Repository == "" {
		return ErrInvalid
	}
	name, err := reference.ParseNormalizedNamed("build.invalid/" + c.Repository)
	if err != nil || name.String() != "build.invalid/"+c.Repository || !reference.IsNameOnly(name) {
		return ErrInvalid
	}
	budget := 0
	for key, value := range c.Arguments {
		if key == "" || key == "BUILDKIT_SYNTAX" || len(key) > 128 || strings.Contains(key, "=") || strings.IndexFunc(key+value, unicode.IsControl) >= 0 {
			return ErrInvalid
		}
		budget += len(key) + len(value)
		if budget > 16<<10 {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, s := range c.Secrets {
		if !lifecycle.ValidID(s.ID) || s.Realm != "" && !lifecycle.ValidID(s.Realm) || !lifecycle.ValidID(s.Secret) || s.Key == "" || len(s.Key) > 256 || strings.IndexFunc(s.Key, unicode.IsControl) >= 0 || seen[s.ID] {
			return ErrInvalid
		}
		seen[s.ID] = true
	}
	seen = map[string]bool{}
	for _, tag := range c.Tags {
		// These are the only tag substitutions, resolved from the accepted
		// immutable version/commit, never from arbitrary command output.
		sample := strings.ReplaceAll(strings.ReplaceAll(tag, "{version}", "1"), "{commit}", strings.Repeat("a", 40))
		if seen[tag] {
			return ErrInvalid
		}
		if _, err := reference.WithTag(name, sample); err != nil {
			return ErrInvalid
		}
		seen[tag] = true
	}
	seen = map[string]bool{}
	for _, platform := range c.Platforms {
		if !ValidPlatform(platform) || seen[platform] {
			return ErrInvalid
		}
		seen[platform] = true
	}
	if g := c.Git; g != nil {
		u, err := url.Parse(g.Repository)
		if err != nil || len(g.Repository) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || g.Ref == "" || len(g.Ref) > 256 || strings.IndexFunc(g.Ref, unicode.IsControl) >= 0 || g.Path != "." && !ContextPath(g.Path) || g.CredentialProfile != "" && !lifecycle.ValidID(g.CredentialProfile) {
			return ErrInvalid
		}
	}
	return nil
}
func (c ContextSpec) Under(p Policy) bool {
	return c.Validate() == nil && c.Tenant == p.Tenant && slices.ContainsFunc(p.Nodes, func(n NodeRoot) bool { return n.Node == c.Root.Node && n.Root == c.Root }) && allPlatforms(c.Platforms, p.Platforms)
}
func allPlatforms(required, allowed []string) bool {
	for _, p := range required {
		if !slices.Contains(allowed, p) {
			return false
		}
	}
	return true
}
func (c ContextSpec) Own() ContextSpec {
	args := make(map[string]string, len(c.Arguments))
	for key, value := range c.Arguments {
		args[key] = value
	}
	if c.Arguments != nil {
		c.Arguments = args
	}
	c.Secrets = slices.Clone(c.Secrets)
	c.Tags = slices.Clone(c.Tags)
	c.Platforms = slices.Clone(c.Platforms)
	if c.Git != nil {
		value := *c.Git
		c.Git = &value
	}
	return c
}
