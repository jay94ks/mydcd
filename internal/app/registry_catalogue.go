// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	oci "github.com/google/go-containerregistry/pkg/registry"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) registryCatalogueOwner(ctx context.Context, read control.RegistryCatalogueRead) (control.RegistryCatalogueResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	view, err := r.currentView(ctx)
	if err != nil {
		return control.RegistryCatalogueResult{}, sfcp.ErrAdmission
	}
	current, err := r.controlPolicy.CurrentRegistryCatalogue(view.State, read, time.Now().Unix())
	if err != nil || current.Target.Owner != r.Identity.Public {
		return control.RegistryCatalogueResult{}, sfcp.ErrAdmission
	}
	var page registryclient.CataloguePage
	if run := current.Target.Managed; run != nil {
		if _, _, err = r.registryCurrent(ctx, *run); err != nil {
			return control.RegistryCatalogueResult{}, err
		}
		page, err = func() (registryclient.CataloguePage, error) {
			r.registryMu.Lock()
			defer r.registryMu.Unlock()
			row, ok := r.registryRecords[run.Spec.Key()]
			live := r.registrySessions[run.Spec.Key()]
			if !ok || row.Phase != "serving" || row.Run == nil || row.Run.Generation != run.Generation || row.Run.SpecRevision != run.SpecRevision || row.Run.Spec != run.Spec || row.IOClosed || live == nil || live.store == nil || live.server == nil {
				return registryclient.CataloguePage{}, &registryclient.Error{Code: "UNAVAILABLE"}
			}
			return live.store.Metadata.Catalogue(ctx, run.Spec.Authority, current.Query.Repository, current.Basis(), current.After)
		}()
	} else {
		work, cause := r.externalRegistryWork(ctx, *current.Target.External)
		if cause != nil || work.Inputs.ReadSet != current.Target.ReadSet {
			return control.RegistryCatalogueResult{}, sfcp.ErrAdmission
		}
		release, cause := r.acquireExternalReader(work)
		if cause != nil {
			return control.RegistryCatalogueResult{}, cause
		}
		defer release()
		client, cause := r.sourceRegistryClient(ctx, work)
		if cause != nil {
			return control.RegistryCatalogueResult{}, cause
		}
		defer client.Close()
		page, err = client.Catalogue(ctx, current.Query.Repository, current.Basis(), current.After, func(repo string) bool {
			return r.controlPolicy.RegistryCatalogueRepositoryAllowed(view.State, current, repo)
		})
	}
	if err != nil {
		code := registryclient.ResultCode(err)
		if errors.Is(err, registryclient.ErrCatalogueChanged) {
			code = "CATALOGUE_CHANGED"
		}
		if errors.Is(err, oci.ErrNameUnknown) || errors.Is(err, oci.ErrNotFound) {
			code = "NOT_FOUND"
		}
		page = registryclient.CataloguePage{Schema: 1, Authority: current.Target.Authority, Repository: current.Query.Repository, Code: code}
	}
	latest, cause := r.currentView(ctx)
	if cause != nil {
		return control.RegistryCatalogueResult{}, sfcp.ErrAdmission
	}
	current, cause = r.controlPolicy.CurrentRegistryCatalogue(latest.State, read, time.Now().Unix())
	if cause != nil {
		return control.RegistryCatalogueResult{}, sfcp.ErrAdmission
	}
	result := control.RegistryCatalogueResult{Kind: read.Query.Kind, ID: read.Query.ID, Page: page}
	if !result.Valid(current) {
		return control.RegistryCatalogueResult{}, sfcp.ErrAdmission
	}
	return result, nil
}

func (r *Runtime) registryCatalogue(ctx context.Context, read control.RegistryCatalogueRead) (control.RegistryCatalogueResult, error) {
	view, err := r.currentView(ctx)
	if err != nil {
		return control.RegistryCatalogueResult{}, sfcp.ErrAdmission
	}
	current, err := r.controlPolicy.CurrentRegistryCatalogue(view.State, read, time.Now().Unix())
	if err != nil {
		return control.RegistryCatalogueResult{}, err
	}
	if current.Target.Owner == r.Identity.Public {
		return r.registryCatalogueOwner(ctx, current)
	}
	peer, ok := r.Mesh.Peer(sfcp.Identity(current.Target.Owner))
	if !ok || !peer.Member {
		return control.RegistryCatalogueResult{}, sfcp.ErrAdmission
	}
	body, _ := json.Marshal(current)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "registry-catalog-owner", Input: body})
	if err != nil || reply.Code != "ok" {
		return control.RegistryCatalogueResult{}, sfcp.ErrAdmission
	}
	result, err := schema.Decode[control.RegistryCatalogueResult](reply.Data)
	if err != nil || !result.Valid(current) {
		return control.RegistryCatalogueResult{}, sfcp.ErrAdmission
	}
	return result, nil
}
