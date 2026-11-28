// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// CDProbeQuery asks the selected server to read a Git source once with its
// own installed profiles; the reply's Data is the deployment.GitProbeResult.
type CDProbeQuery struct {
	Tenant string
	Probe  deployment.GitProbeRequest
}

func (q CDProbeQuery) Valid() bool { return q.Tenant != "" && q.Probe.Valid() }

// CDProbeMethod is answered on the server the client selected, never on the
// leader and never through a relay: the credentials it reads are local to
// that provider.
var CDProbeMethod = defineRoute(Method[CDProbeQuery, deployment.GitProbeResult]{Name: "cd-probe"}, false)

// cdProbeReply runs an authorized probe on this server's view.
func (s Service) cdProbeReply(ctx context.Context, view cluster.View, session access.Session, request Request) Reply {
	q, ok := paramsOf(request, CDProbeMethod)
	if !ok {
		return Reply{Schema: 1, Code: "denied"}
	}
	if s.CDProber == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	out, err := s.CDProber(ctx, control.CDProbeRead{Session: session, Tenant: q.Tenant, Query: q.Probe, Epoch: view.State.ModuleEpoch()})
	if err != nil {
		return imageBuildError(err)
	}
	if !out.Valid() {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	return dataReply("ok", out)
}

func (c Client) ProbeCD(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q deployment.GitProbeRequest) (deployment.GitProbeResult, error) {
	query := CDProbeQuery{Tenant: tenant, Probe: q}
	if c.Verify(session) != nil || !query.Valid() {
		return deployment.GitProbeResult{}, sfcp.ErrAdmission
	}
	params, err := json.Marshal(query)
	if err != nil {
		return deployment.GitProbeResult{}, err
	}
	body, err := requestBody(Request{Method: CDProbeMethod.Name, Params: params})
	if err != nil {
		return deployment.GitProbeResult{}, err
	}
	// Installed Git profiles stay on the explicitly selected provider, so a
	// not-leader answer is not followed.
	reply, _, err := c.exchange(ctx, peer, func(conn *sfcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, false)
	if err != nil {
		return deployment.GitProbeResult{}, err
	}
	var result deployment.GitProbeResult
	if len(reply.Data) == 0 || lenient(reply.Data, &result) != nil || !result.Valid() {
		return deployment.GitProbeResult{}, sfcp.ErrFrame
	}
	return result, nil
}
