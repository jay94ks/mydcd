// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"regexp"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/servicecall"
)

// REQ-24/55 and REQ-56 in sfcd's real shape (docs/reference/
// service-diagnostics.md, unix-sockets.md): User `service-call` Params{Tenant,
// Call servicecall.Request, Input {Length, Digest}} with the
// body as kind 4 input → Reply.Data servicecall.Result, and User
// `cd-probe` Params{Tenant, Probe deployment.GitProbeRequest} →
// Reply.Data deployment.GitProbeResult. Same names as the SDK
// (userauth.Client.CallService / ProbeCD). The fake runs the old mocks'
// behaviour (fake_service_call.go, fake_cd_probe.go, now private) behind
// the real types and validation:
//   - service-call is one POST: the fake never retries; a Code is a
//     result, not an error. Result.Headers holds Content-Type only; an
//     error result has no Status/Headers/Body.
//   - cd-probe answers a 40-hex Commit; an error result has Code and Node
//     only. too-large: the file is over 4 MiB.

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (c *fakeConn) CallService(ctx context.Context, tenant string, q servicecall.Request) (servicecall.Result, error) {
	const m = "service-call"
	if len(q.Body) > servicecall.MaxBody {
		return servicecall.Result{Code: servicecall.TooLarge}, nil
	}
	if tenant == "" || !q.Valid() {
		return servicecall.Result{}, fail(m, CodeInvalid, "service call")
	}
	old, err := c.callService(ctx, ServiceCallRequest{Tenant: tenant, App: q.App, Service: q.Service, Port: q.Port, Path: q.Path, Method: q.Method,
		Headers: q.Headers, Body: q.Body, TimeoutMS: q.TimeoutMS, Scheme: q.Scheme, InsecureSkipVerify: q.InsecureSkipVerify})
	if err != nil {
		return servicecall.Result{}, err
	}
	out := servicecall.Result{Code: old.Code, ElapsedMS: int64(old.ElapsedMS)}
	if old.Code == "" {
		out.Status, out.Body, out.Task, out.Node = old.Status, old.Body, old.Task, old.Node
		if old.ContentType != "" {
			out.Headers = map[string]string{"Content-Type": old.ContentType}
		}
	}
	return out, nil
}

func (c *fakeConn) ProbeCD(ctx context.Context, tenant string, q deployment.GitProbeRequest) (deployment.GitProbeResult, error) {
	const m = "cd-probe"
	if tenant == "" || !q.Valid() {
		return deployment.GitProbeResult{}, fail(m, CodeInvalid, "cd probe")
	}
	old, err := c.probeCD(ctx, cdProbeRequest{Tenant: tenant, App: q.App, Repository: q.Repository, Branch: q.Branch, Path: q.Path, Credential: q.Credential})
	if err != nil {
		return deployment.GitProbeResult{}, err
	}
	out := deployment.GitProbeResult{Code: old.Code, Node: old.Node}
	if out.Code == "" {
		if old.Size > deployment.GitProbeMaxBytes {
			out.Code = "too-large"
			return out, nil
		}
		out.Commit, out.Size = old.Commit, old.Size
		if !hex40.MatchString(out.Commit) {
			d := fakeDigest("git-commit", old.Commit)
			out.Commit = hexOf(d[:20])
		}
	}
	return out, nil
}
