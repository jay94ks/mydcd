// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/deployment"
)

// vaultAncestors: id and every group above it in the realm (root excluded).
func (w *world) vaultAncestors(realm, id string) []string {
	var out []string
	for seen := map[string]bool{}; id != "" && id != realm && !seen[id]; {
		seen[id] = true
		out = append(out, id)
		i := slices.IndexFunc(w.vault, func(v VaultView) bool { return v.Realm == realm && v.ID == id })
		if i < 0 {
			break
		}
		id = w.vault[i].Parent
	}
	return out
}

// vaultSecretsUnder: the secret objects a selector of id delivers (id itself
// when it is a secret; every object under it, or tagged with it, when a
// group; everything when id is the realm root).
func (w *world) vaultSecretsUnder(realm, id string) []string {
	var out []string
	for _, v := range w.vault {
		if v.Realm != realm || v.Kind != "object" || v.Status == "retired" {
			continue
		}
		if id == realm || v.ID == id || v.Group == id || slices.Contains(w.vaultAncestors(realm, v.Parent), id) {
			out = append(out, v.ID)
		}
	}
	slices.Sort(out)
	return out
}

// vaultUsages: app services whose current definition names, in
// x-mydc.secrets_from (tenant scope), the object or something that
// delivers it or is under it.
func (w *world) vaultUsages(realm, id string) []VaultUsage {
	covered := w.vaultSecretsUnder(realm, id)
	var out []VaultUsage
	for _, k := range sortedKeys(w.apps) {
		a := w.apps[k]
		if a.view.Tenant != realm || len(a.sources) == 0 {
			continue
		}
		var d struct {
			Services map[string]struct {
				XMydc struct {
					Node    string                   `yaml:"node"`
					Sources deployment.SecretSources `yaml:"secrets_from"`
				} `yaml:"x-mydc"`
			} `yaml:"services"`
		}
		if yaml.Unmarshal(a.sources[len(a.sources)-1].Document, &d) != nil {
			continue
		}
		for _, svc := range sortedKeys(d.Services) {
			s := d.Services[svc]
			for _, src := range s.XMydc.Sources {
				sel := src.Secret + src.Group
				if src.Scope == "cluster" || sel == "" {
					continue
				}
				var got []string
				for _, sid := range w.vaultSecretsUnder(realm, sel) {
					if slices.Contains(covered, sid) {
						got = append(got, sid)
					}
				}
				if len(got) == 0 && sel != id {
					continue
				}
				out = append(out, VaultUsage{App: a.view.App, Deployment: a.view.Deployment, Service: svc, Node: s.XMydc.Node,
					Selector: sel, Secrets: got, Live: !a.view.Retiring})
			}
		}
	}
	return out
}

func (w *world) vaultLiveUse(realm, id string) bool {
	return slices.ContainsFunc(w.vaultUsages(realm, id), func(u VaultUsage) bool { return u.Live })
}

// vaultUsages: the vault-usages rows PublicRead pages. ManageSecrets
// in the realm (or a system administrator); the object must exist (the root
// group = the realm).
func (c *fakeConn) vaultUsages(ctx context.Context, realm, id, after string) (Page[VaultUsage], error) {
	const m = "vault-usages"
	if err := checkAfter(m, after); err != nil {
		return Page[VaultUsage]{}, err
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return Page[VaultUsage]{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.admin(user) && !w.canManage(user, realm) {
		return Page[VaultUsage]{}, fail(m, CodeDenied, "")
	}
	if id != realm && !slices.ContainsFunc(w.vault, func(v VaultView) bool { return v.Realm == realm && v.ID == id }) {
		return Page[VaultUsage]{}, fail(m, CodeMissing, "")
	}
	items := w.vaultUsages(realm, id)
	return paginate(items, func(u VaultUsage) string { return u.App + "/" + u.Service + "/" + u.Selector }, after, c.f.pageSize, w.root), nil
}
