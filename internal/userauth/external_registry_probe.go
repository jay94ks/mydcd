// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (s Service) externalRegistryProbe(ctx context.Context, view cluster.View, q Request, session access.Session) Reply {
	if s.ExternalRegistryProber == nil || q.ExternalRegistryProbe == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	read, err := s.Policy.PlanExternalRegistryProbe(view.State, session, time.Now().Unix(), q.Tenant, *q.ExternalRegistryProbe)
	if err != nil {
		return Reply{Schema: 1, Code: "denied"}
	}
	data, err := s.ExternalRegistryProber(ctx, read)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	result, err := schema.Decode[control.ExternalRegistryProbeResult](data)
	if err != nil || !result.Valid(read) {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	now := time.Now().Unix()
	owner, err := s.Policy.ExternalRegistryProbeOwner(latest.State, read, now)
	if err != nil || owner != result.Owner || result.At > now || now-result.At > 30 {
		return Reply{Schema: 1, Code: "denied"}
	}
	return Reply{Schema: 1, Code: "ok", Tenant: q.Tenant, ExternalRegistryProbe: &result}
}

func (c Client) ProbeExternalRegistry(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.ExternalRegistryProbeQuery) (control.ExternalRegistryProbeResult, error) {
	if tenant == "" || !q.Valid() {
		return control.ExternalRegistryProbeResult{}, sfcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "registry-login-test", Tenant: tenant, ExternalRegistryProbe: &q})
	if err != nil {
		return control.ExternalRegistryProbeResult{}, err
	}
	result := reply.ExternalRegistryProbe
	if result == nil || reply.Tenant != tenant || result.Selection.Tenant != tenant || result.Selection.ID != q.ID || result.Selection.Generation == 0 {
		return control.ExternalRegistryProbeResult{}, sfcp.ErrFrame
	}
	image := q.Image
	if image != "" {
		// The server returns canonical coordinates; reuse the same parser as
		// the source policy rather than accepting a different raw spelling.
		image, _, _, err = registryclient.Normalize(image)
		if err != nil {
			return control.ExternalRegistryProbeResult{}, sfcp.ErrFrame
		}
	}
	read := control.ExternalRegistryProbeRead{Session: session, Selection: result.Selection, Image: image}
	if !result.Valid(read) {
		return control.ExternalRegistryProbeResult{}, sfcp.ErrFrame
	}
	return *result, nil
}
