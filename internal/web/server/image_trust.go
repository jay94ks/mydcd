// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Image trust (UI-82 '신뢰 출처'): the tenant's set-trust rules with where
// each came from and which current images each admits (REQ-45
// `image-trust` PublicRead), and set-trust itself (Expected = the tenant revision).
// sfcd checks trust at every pull; the web only shows the list sfcd gives
// and, for a proposed rule set, which of those uses lose every admitting
// rule.

type trustRuleView struct {
	Index      int    `json:"index"`
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	// Origin: default (Docker Hub, a new workspace's rule) / builtin (a
	// built-in registry of this workspace) / direct (added by hand).
	Origin string `json:"origin"`
	// Pull: how images are fetched from this source: registry-credential
	// (built-in) / anonymous (no external login yet, REQ-17).
	Pull string              `json:"pull"`
	Uses []sfc.ImageTrustUse `json:"uses"`
	// Only: uses that no other rule admits; removing this rule makes them
	// untrusted.
	Only int `json:"only"`
}

type trustView struct {
	Tenant    string              `json:"tenant"`
	Revision  uint64              `json:"revision"`
	Rules     []trustRuleView     `json:"rules"`
	Uses      []sfc.ImageTrustUse `json:"uses"`
	Untrusted []sfc.ImageTrustUse `json:"untrusted"`
}

func registryAuthorities(ctx context.Context, c sfc.Conn, tenant string) (map[string]bool, error) {
	out := map[string]bool{}
	after := ""
	for {
		p, err := c.Registries(ctx, tenant, after)
		if err != nil {
			return nil, err
		}
		for _, r := range p.Items {
			if !r.Deleted {
				out[r.Spec.Authority] = true
			}
		}
		if p.Next == "" {
			return out, nil
		}
		after = p.Next
	}
}

func buildTrustView(t sfc.ImageTrust, builtin map[string]bool) trustView {
	v := trustView{Tenant: t.Tenant, Revision: t.Revision, Rules: []trustRuleView{}, Uses: t.Uses, Untrusted: []sfc.ImageTrustUse{}}
	if v.Uses == nil {
		v.Uses = []sfc.ImageTrustUse{}
	}
	for i, r := range t.Rules {
		rv := trustRuleView{Index: i, Registry: r.Registry, Repository: r.Repository, Origin: "direct", Pull: "anonymous", Uses: []sfc.ImageTrustUse{}}
		switch {
		case builtin[r.Registry]:
			rv.Origin, rv.Pull = "builtin", "registry-credential"
		case r.Registry == "docker.io" && r.Repository == "**":
			rv.Origin = "default"
		}
		for _, u := range v.Uses {
			if slices.Contains(u.Rules, i) {
				rv.Uses = append(rv.Uses, u)
				if len(u.Rules) == 1 {
					rv.Only++
				}
			}
		}
		v.Rules = append(v.Rules, rv)
	}
	for _, u := range v.Uses {
		if len(u.Rules) == 0 {
			v.Untrusted = append(v.Untrusted, u)
		}
	}
	return v
}

func (s *Server) readTrust(ctx context.Context, c sfc.Conn, tenant string) (sfc.ImageTrust, trustView, error) {
	t, err := readImageTrust(ctx, c, tenant)
	if err != nil {
		return t, trustView{}, err
	}
	builtin, err := registryAuthorities(ctx, c, tenant)
	if err != nil {
		return t, trustView{}, err
	}
	return t, buildTrustView(t, builtin), nil
}

// GET /t/{t}/image-trust → {tenant, revision, rules:[{index, registry,
// repository, origin, pull, uses, only}], uses, untrusted}.
func (s *Server) handleImageTrust(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (trustView, error) {
		_, v, err := s.readTrust(ctx, c, r.PathValue("t"))
		return v, err
	})
}

type trustRulesReq []struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
}

func (q trustRulesReq) rules() ([]access.TrustRule, error) {
	out := []access.TrustRule{}
	for _, r := range q {
		out = append(out, access.TrustRule{Registry: r.Registry, Repository: r.Repository})
	}
	rules, err := access.CanonicalTrust(out)
	if err != nil {
		return nil, invalid("rules: registry host[:port] (lowercase) and repository path or **, no duplicates")
	}
	if len(rules) == 0 {
		return nil, nil
	}
	return rules, nil
}

// lost: the uses whose admitting rules are all in remove.
func lost(t sfc.ImageTrust, remove []access.TrustRule) []sfc.ImageTrustUse {
	out := []sfc.ImageTrustUse{}
	for _, u := range t.Uses {
		if len(u.Rules) == 0 {
			continue
		}
		kept := slices.ContainsFunc(u.Rules, func(i int) bool { return i < len(t.Rules) && !slices.Contains(remove, t.Rules[i]) })
		if !kept {
			out = append(out, u)
		}
	}
	return out
}

// POST /t/{t}/image-trust/preview {remove:[{registry, repository}]} →
// {affected:[use]}: the current uses that lose every admitting rule when
// those rules are removed. Added rules are not counted (the warning errs on
// the safe side).
func (s *Server) handleImageTrustPreview(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Remove trustRulesReq `json:"remove"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	remove, err := req.Remove.rules()
	if err != nil {
		s.writeOpOutcome(w, ws, nil, 0, err)
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		t, err := readImageTrust(ctx, c, r.PathValue("t"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"affected": lost(t, remove)}, nil
	})
}

// PATCH /t/{t}/image-trust {opId, add:[rule], remove:[rule], expected?}
// → set-trust {Tenant, Add, Remove} with Expected = the tenant revision.
// Only the changed rules travel; a rule added that is already trusted, or
// removed that is not, fails the CAS.
func (s *Server) handleSetTrust(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string        `json:"opId"`
		Add      trustRulesReq `json:"add"`
		Remove   trustRulesReq `json:"remove"`
		Expected uint64        `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant := r.PathValue("t")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		add, err := req.Add.rules()
		if err != nil {
			return "", nil, 0, "", err
		}
		remove, err := req.Remove.rules()
		if err != nil {
			return "", nil, 0, "", err
		}
		if len(add) == 0 && len(remove) == 0 {
			return "", nil, 0, "", invalid("add or remove: at least one rule")
		}
		expected := req.Expected
		if expected == 0 {
			t, err := readImageTrust(ctx, c, tenant)
			if err != nil {
				return "", nil, 0, "", err
			}
			expected = t.Revision
		}
		change := control.TrustChange{Tenant: tenant}
		if len(add) > 0 {
			change.Add = add
		}
		if len(remove) > 0 {
			change.Remove = remove
		}
		return sfc.ActionSetTrust, change, expected, "image-trust", nil
	})
}
