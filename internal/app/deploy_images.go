// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
)

// A deploy whose tasks name image tags resolves each tag once, on the leader,
// before those tasks are prepared, and records the digests in the deploy
// (Execution.ResolveImages); every container the deploy creates uses them.

const deployImageTimeout = 30 * time.Second

// resolveDeployImages starts the resolution of app's tags unless one is
// already running on this server.
func (r *Runtime) resolveDeployImages(app control.AppView, e deployment.Execution) {
	tags := e.TagImages()
	r.startJob(&r.deployImageJob, app.Operation.ID, func(op string) {
		ctx, cancel := context.WithTimeout(r.ctx, deployImageTimeout*time.Duration(len(tags)))
		defer cancel()
		images, err := r.deployImageResolutions(ctx, app, op, tags)
		if err != nil {
			log.Printf("deploy %s/%s: image tags not resolved yet: %v", app.Tenant, app.App, err)
			return
		}
		v, err := r.Engine().Read(ctx, false)
		if err != nil {
			return
		}
		latest, ok := r.appView(v, app.Tenant, app.App)
		if !ok || latest.Operation.ID != op {
			return
		}
		report := r.newAppProgress(v, latest, "resolve-images", "", nil)
		report.Images = images
		if err = r.sendAppProgress(ctx, report); err != nil {
			log.Printf("deploy %s/%s: image tag resolutions not recorded: %v", app.Tenant, app.App, err)
		}
	})
}

var errDeployImageRetry = errors.New("image resolve was cancelled")

func (r *Runtime) deployImageResolutions(ctx context.Context, app control.AppView, op string, tags []string) ([]deployment.ImageResolution, error) {
	out := make([]deployment.ImageResolution, 0, len(tags))
	for _, ref := range tags {
		v, err := r.Engine().Read(ctx, false)
		if err != nil {
			return nil, err
		}
		read, err := r.controlPolicy.PlanDeployImageResolve(v.State, time.Now().Unix(), app.Tenant, control.ImageResolveDeploy{App: app.App, Operation: op}, control.ImageResolveQuery{Ref: ref}, r.Identity.Public)
		if err != nil {
			return nil, err
		}
		got := deployment.ImageResolution{Ref: ref}
		code := read.Target.Code
		if code == "" {
			result, err := r.resolveImage(ctx, read)
			switch {
			case err != nil:
				code = "UNAVAILABLE" // the reader could not be asked
			case result.Code == "OK" && result.Image != nil:
				got.Digest = result.Image.Pinned
			default:
				code = result.Code
			}
		}
		if got.Digest == "" {
			if got.Code = deployment.ResolutionCode(code); got.Code == "" {
				return nil, errDeployImageRetry
			}
		}
		out = append(out, got)
	}
	return out, nil
}

// appView is app's current view in v.
func (r *Runtime) appView(v cluster.View, tenant, app string) (control.AppView, bool) {
	apps, err := r.controlPolicy.ReadApps(v.State)
	if err != nil {
		return control.AppView{}, false
	}
	for _, a := range apps.Records() {
		if a.Tenant == tenant && a.App == app {
			return a, true
		}
	}
	return control.AppView{}, false
}
