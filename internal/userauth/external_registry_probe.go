// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// ExternalRegistryProbeQuery asks the source's bound server to log in to
// it, and optionally to read one image.
type ExternalRegistryProbeQuery struct {
	Tenant string
	Query  control.ExternalRegistryProbeQuery
}

func (q ExternalRegistryProbeQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid()
}

// RegistryLoginTestMethod runs the probe on the owner, then checks on a fresh
// view that the same server still owns the source and the result is recent.
var RegistryLoginTestMethod = define(Method[ExternalRegistryProbeQuery, control.ExternalRegistryProbeResult]{Name: "registry-login-test"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q ExternalRegistryProbeQuery) (control.ExternalRegistryProbeResult, string) {
	var zero control.ExternalRegistryProbeResult
	if s.ExternalRegistryProber == nil {
		return zero, "unavailable"
	}
	read, err := s.Policy.PlanExternalRegistryProbe(view.State, session, time.Now().Unix(), q.Tenant, q.Query)
	if err != nil {
		return zero, "denied"
	}
	data, err := s.ExternalRegistryProber(ctx, read)
	if err != nil {
		return zero, "unavailable"
	}
	result, err := schema.Decode[control.ExternalRegistryProbeResult](data)
	if err != nil || !result.Valid(read) {
		return zero, "unavailable"
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return zero, "unavailable"
	}
	now := time.Now().Unix()
	owner, err := s.Policy.ExternalRegistryProbeOwner(latest.State, read, now)
	if err != nil || owner != result.Owner || result.At > now || now-result.At > 30 {
		return zero, "denied"
	}
	return result, "ok"
})

func (c Client) ProbeExternalRegistry(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.ExternalRegistryProbeQuery) (control.ExternalRegistryProbeResult, error) {
	result, err := call(ctx, c, peer, session, RegistryLoginTestMethod, ExternalRegistryProbeQuery{Tenant: tenant, Query: q})
	if err != nil {
		return control.ExternalRegistryProbeResult{}, err
	}
	if result.Selection.Tenant != tenant || result.Selection.ID != q.ID || result.Selection.Generation == 0 {
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
	return result, nil
}
