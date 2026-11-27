// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) imageBuildBaseTrustOwner(ctx context.Context, original control.ImageBuildBaseRead) (registryclient.RegistryTrust, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	read, err := r.controlPolicy.CurrentImageBuildBaseMaterial(view.State, original, time.Now().Unix())
	if err != nil || read.Target.Owner != r.Identity.Public || read.Target.Managed != nil {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	_, authority, _, err := registryclient.Normalize(read.Target.Normalized)
	if err != nil {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	trust := registryclient.RegistryTrust{Authority: authority}
	if read.Target.External != nil {
		work, err := r.externalRegistryWork(ctx, *read.Target.External)
		if err != nil || work.Inputs.ReadSet != read.Target.ExternalReadSet {
			return registryclient.RegistryTrust{}, sfcp.ErrAdmission
		}
		release, err := r.acquireExternalReader(work)
		if err != nil {
			return registryclient.RegistryTrust{}, err
		}
		defer release()
		if work.Reader.Spec.CA != nil {
			client, err := r.sourceRegistryClient(ctx, work)
			if err != nil {
				return registryclient.RegistryTrust{}, registryclient.Sanitize(err)
			}
			trust = client.PublicTrust()
			client.Close()
		}
	}
	view, err = r.currentView(ctx)
	if err != nil || view.Local {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	if err := r.controlPolicy.ValidateImageBuildBaseTrust(view.State, original, trust, time.Now().Unix()); err != nil {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	return trust, nil
}

func (r *Runtime) currentImageBuildRegistryTrust(ctx context.Context, original control.ImageBuildRegistryPermit) (control.ImageBuildRegistryPermit, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.ImageBuildRegistryPermit{}, sfcp.ErrAdmission
	}
	return r.controlPolicy.CurrentImageBuildRegistryTrust(view.State, original, time.Now().Unix())
}

func (r *Runtime) imageBuildRegistryTrustOwner(ctx context.Context, original control.ImageBuildRegistryPermit) (registryclient.RegistryTrust, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	permit, err := r.currentImageBuildRegistryTrust(ctx, original)
	if err != nil || permit.Run.Owner != r.Identity.Public {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	trust, err := func() (registryclient.RegistryTrust, error) {
		r.registryMu.Lock()
		defer r.registryMu.Unlock()
		key := permit.Run.Spec.Key()
		row, exists := r.registryRecords[key]
		live := r.registrySessions[key]
		if !exists || row.Run == nil || row.Generation != permit.Run.Generation || row.Spec != permit.Run.Spec || row.IOClosed || row.Phase != "serving" || live == nil || live.server == nil {
			return registryclient.RegistryTrust{}, sfcp.ErrAdmission
		}
		fingerprint, chain := live.server.Trust()
		if fingerprint != permit.Run.Ready.Certificate {
			return registryclient.RegistryTrust{}, sfcp.ErrAdmission
		}
		return registryclient.RegistryTrust{Authority: row.Spec.Authority, Certificates: chain, Fingerprint: fingerprint}, nil
	}()
	if err != nil {
		return registryclient.RegistryTrust{}, err
	}
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	if err := r.controlPolicy.ValidateImageBuildRegistryTrust(view.State, original, trust, time.Now().Unix()); err != nil {
		return registryclient.RegistryTrust{}, err
	}
	return trust, nil
}

func (r *Runtime) imageBuildRegistryTrust(ctx context.Context, permit control.ImageBuildRegistryPermit) (registryclient.RegistryTrust, error) {
	if permit.Subject.Node != r.Identity.Public {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	var trust registryclient.RegistryTrust
	var err error
	if permit.Run.Owner == r.Identity.Public {
		trust, err = r.imageBuildRegistryTrustOwner(ctx, permit)
	} else {
		peer, known := r.Mesh.Peer(sfcp.Identity(permit.Run.Owner))
		if !known || !peer.Member {
			return registryclient.RegistryTrust{}, sfcp.ErrAdmission
		}
		raw, _ := json.Marshal(permit)
		reply, cause := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-build-registry-tls-owner", Input: raw})
		if cause != nil || reply.Code != "ok" {
			return registryclient.RegistryTrust{}, sfcp.ErrAdmission
		}
		trust, err = schema.Decode[registryclient.RegistryTrust](reply.Data)
	}
	if err != nil {
		return registryclient.RegistryTrust{}, err
	}
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	if err := r.controlPolicy.ValidateImageBuildRegistryTrust(view.State, permit, trust, time.Now().Unix()); err != nil {
		return registryclient.RegistryTrust{}, err
	}
	return trust, nil
}

func (r *Runtime) imageBuildBaseTrust(ctx context.Context, spec imagebuild.JobSpec, source imagebuild.Source) (registryclient.RegistryTrust, error) {
	read, err := r.imageBuildBaseWork(ctx, spec, source)
	if err != nil {
		return registryclient.RegistryTrust{}, err
	}
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	if _, err := r.controlPolicy.CurrentImageBuildBaseMaterial(view.State, read, time.Now().Unix()); err != nil {
		return registryclient.RegistryTrust{}, err
	}
	if read.Target.Managed != nil {
		permit, err := r.imageBuildRegistryPermit(ctx, spec, "pull", read.Target.Normalized)
		if err != nil {
			return registryclient.RegistryTrust{}, err
		}
		return r.imageBuildRegistryTrust(ctx, permit)
	}
	var trust registryclient.RegistryTrust
	if read.Target.Owner == r.Identity.Public {
		trust, err = r.imageBuildBaseTrustOwner(ctx, read)
	} else {
		peer, known := r.Mesh.Peer(sfcp.Identity(read.Target.Owner))
		if !known || !peer.Member {
			return registryclient.RegistryTrust{}, sfcp.ErrAdmission
		}
		raw, _ := json.Marshal(read)
		reply, cause := cluster.CallManagement(ctx, r.Mesh, r.Identity, spec.Cluster, peer, cluster.ManagementRequest{Method: "image-build-base-tls-owner", Input: raw})
		if cause != nil || reply.Code != "ok" {
			return registryclient.RegistryTrust{}, sfcp.ErrAdmission
		}
		trust, err = schema.Decode[registryclient.RegistryTrust](reply.Data)
	}
	_, authority, _, normalizeErr := registryclient.Normalize(read.Target.Normalized)
	if err != nil || normalizeErr != nil || !trust.Valid() || trust.Authority != authority || trust.Fingerprint != ([32]byte{}) {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	view, err = r.currentView(ctx)
	if err != nil || view.Local {
		return registryclient.RegistryTrust{}, sfcp.ErrAdmission
	}
	if err := r.controlPolicy.ValidateImageBuildBaseTrust(view.State, read, trust, time.Now().Unix()); err != nil {
		return registryclient.RegistryTrust{}, err
	}
	return trust, nil
}

func (r *Runtime) imageBuildTrust(ctx context.Context, spec imagebuild.JobSpec) ([]registryclient.RegistryTrust, error) {
	work, err := r.imageBuildJobWork(ctx, spec)
	if err != nil || !work.Allowed || work.Run.Phase != "running" {
		return nil, sfcp.ErrAdmission
	}
	var roots []registryclient.RegistryTrust
	seen := map[string]bool{}
	total := 0
	for _, input := range work.Run.Inputs {
		_, host, repository, err := registryclient.Normalize(input.Image)
		if err != nil {
			return nil, err
		}
		key := host + "/" + repository
		if seen[key] {
			continue
		}
		seen[key] = true
		trust, err := r.imageBuildBaseTrust(ctx, spec, input.Source)
		if err != nil {
			return nil, err
		}
		pem, err := trust.PEM()
		if err != nil || len(pem) > imagebuild.MaxBuildTrustBytes-total {
			return nil, imagebuild.ErrSourceFetch
		}
		total += len(pem)
		roots = append(roots, trust)
	}
	return roots, nil
}
