// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"slices"
)

// volumeUsers: app services whose current definition mounts the volume and
// standalone containers that mount it; app "" = every app.
func (w *world) volumeUsers(tenant, volume, app string) []VolumeUser {
	var out []VolumeUser
	for _, k := range sortedKeys(w.apps) {
		a := w.apps[k]
		if a.view.Tenant != tenant || a.view.Retiring || len(a.sources) == 0 || app != "" && a.view.App != app {
			continue
		}
		d, err := parseApp(a.sources[len(a.sources)-1].Document)
		if err != nil {
			continue
		}
		for _, svc := range sortedKeys(d.Services) {
			s := d.Services[svc]
			i := slices.IndexFunc(parseMounts(s.Volumes), func(m standaloneMount) bool { return m.Volume == volume })
			if i < 0 {
				continue
			}
			u := VolumeUser{Kind: NetworkUserService, App: a.view.App, Service: svc, Node: s.XSfc.Node, ReadOnly: !parseMounts(s.Volumes)[i].RW}
			for _, t := range a.tasks {
				if t.Service == svc && t.Observed != "exited" {
					u.Selection = append(u.Selection, ContainerSelection{App: t.App, Service: t.Service, Instance: t.Instance})
				}
			}
			u.Attached = len(u.Selection) > 0
			out = append(out, u)
		}
	}
	if app != "" {
		return out
	}
	for _, k := range sortedKeys(w.standalones) {
		e := w.standalones[k]
		if e.view.Tenant != tenant || e.removed() {
			continue
		}
		i := slices.IndexFunc(e.spec.Mounts, func(m standaloneMount) bool { return m.Volume == volume })
		if i < 0 {
			continue
		}
		u := VolumeUser{Kind: NetworkUserStandalone, Standalone: e.view.Name, Node: e.view.Node, ReadOnly: !e.spec.Mounts[i].RW, Attached: e.view.State == "running"}
		if u.Attached {
			u.Selection = []ContainerSelection{{Standalone: e.view.Name}}
		}
		out = append(out, u)
	}
	return out
}

// volumeUsers: the REQ-37 volume-users rows PublicRead pages.
func (c *fakeConn) volumeUsers(ctx context.Context, tenant, volume, app string) (VolumeUsers, error) {
	const m = "volume-users"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return VolumeUsers{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !slices.ContainsFunc(w.volumes, func(v volumeRow) bool { return v.Tenant == tenant && v.Name == volume }) {
		return VolumeUsers{}, fail(m, CodeMissing, "")
	}
	return VolumeUsers{Tenant: tenant, Volume: volume, Users: w.volumeUsers(tenant, volume, app), ObservedAt: c.f.now().Unix()}, nil
}
