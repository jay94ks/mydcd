// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"slices"
	"strings"

	"github.com/distribution/reference"
)

// imageTrust: the image-trust rows PublicRead pages (REQ-45; the
// per-method mock is gone since the daemon reads PublicRead). The rules and the images of live app tasks and
// standalone containers, matched as access.CheckImageTrust matches
// (exact repository or "**").
func (c *fakeConn) imageTrust(ctx context.Context, tenant string) (ImageTrust, error) {
	const m = "image-trust"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return ImageTrust{}, err
	}
	defer c.unlock()
	w := c.f.w
	out := ImageTrust{Tenant: tenant, Revision: w.tenantRev[tenant], Rules: slices.Clone(w.trust[tenant]), Uses: []ImageTrustUse{}}
	add := func(u ImageTrustUse, image string) {
		n, err := reference.ParseNormalizedNamed(image)
		if err != nil {
			return
		}
		u.Image = reference.TagNameOnly(n).String()
		u.Rules = []int{}
		for i, r := range out.Rules {
			if r.Registry == reference.Domain(n) && (r.Repository == "**" || r.Repository == reference.Path(n)) {
				u.Rules = append(u.Rules, i)
			}
		}
		if !slices.ContainsFunc(out.Uses, func(o ImageTrustUse) bool {
			return o.App == u.App && o.Service == u.Service && o.Standalone == u.Standalone && o.Image == u.Image
		}) {
			out.Uses = append(out.Uses, u)
		}
	}
	for _, a := range w.apps {
		if a.view.Tenant != tenant || a.view.Retiring {
			continue
		}
		for _, t := range a.tasks {
			add(ImageTrustUse{App: a.view.App, Deployment: a.view.Deployment, Service: t.Service}, t.Image)
		}
	}
	for _, e := range w.standalones {
		if e.view.Tenant == tenant {
			add(ImageTrustUse{Standalone: e.view.Name}, e.view.Image)
		}
	}
	slices.SortFunc(out.Uses, func(a, b ImageTrustUse) int {
		return strings.Compare(a.App+"/"+a.Service+"/"+a.Standalone+"/"+a.Image, b.App+"/"+b.Service+"/"+b.Standalone+"/"+b.Image)
	})
	return out, nil
}
