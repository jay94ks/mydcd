// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"runtime"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) sourceRegistryClient(ctx context.Context, work control.ExternalRegistryWork) (*registryclient.Access, error) {
	var username, password, ca []byte
	var values []secrets.Fetched
	defer func() {
		for _, value := range values {
			for _, data := range value.Values {
				clear(data)
			}
		}
	}()
	selection := control.ExternalRegistryReadSelection{Tenant: work.Reader.Spec.Tenant, ID: work.Reader.Spec.ID, Generation: work.Reader.Generation}
	for _, input := range work.Inputs.Entries {
		q := control.AppInputFetch{Schema: 1, Consumer: r.Identity.Public, Binding: control.AppBindingRequest{At: time.Now().Unix()}, ReadSet: work.Inputs.ReadSet, MinimumIndex: work.Index, Realm: input.Realm, Secret: input.Leaf.Secret, ExternalRegistry: &selection}
		value, err := r.fetchAppInputLeaf(ctx, q, input.Provider)
		values = append(values, value)
		if err != nil {
			return nil, err
		}
		if secrets.ValidateFetched(secrets.UsePlan{Leaves: []secrets.Leaf{input.Leaf}}, []secrets.Fetched{value}, 128<<10) != nil {
			return nil, sfcp.ErrAdmission
		}
		if c := work.Reader.Spec.Credential; c != nil && c.Realm == input.Realm && c.ID == input.Leaf.Secret {
			username, password = value.Values[c.UsernameKey], value.Values[c.PasswordKey]
		}
		if c := work.Reader.Spec.CA; c != nil && c.Realm == input.Realm && c.ID == input.Leaf.Secret {
			ca = value.Values[c.Key]
		}
	}
	if work.Reader.Spec.Credential != nil && (len(username) == 0 || len(password) == 0) || work.Reader.Spec.CA != nil && len(ca) == 0 {
		return nil, sfcp.ErrAdmission
	}
	latest, err := r.externalRegistryWork(ctx, selection)
	if err != nil || latest.Inputs.ReadSet != work.Inputs.ReadSet {
		return nil, sfcp.ErrAdmission
	}
	return registryclient.New(work.Reader.Spec.Authority, username, password, ca)
}

func (r *Runtime) probeExternalRegistry(ctx context.Context, read control.ExternalRegistryProbeRead) (control.ExternalRegistryProbeResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.ExternalRegistryProbeResult{}, sfcp.ErrAdmission
	}
	owner, err := r.controlPolicy.ExternalRegistryProbeOwner(view.State, read, time.Now().Unix())
	if err != nil || owner != r.Identity.Public {
		return control.ExternalRegistryProbeResult{}, sfcp.ErrAdmission
	}
	work, err := r.externalRegistryWork(ctx, read.Selection)
	if err != nil {
		return control.ExternalRegistryProbeResult{}, err
	}
	release, err := r.acquireExternalReader(work)
	if err != nil {
		return control.ExternalRegistryProbeResult{}, err
	}
	defer release()
	client, err := r.sourceRegistryClient(ctx, work)
	if err != nil {
		return control.ExternalRegistryProbeResult{}, err
	}
	defer client.Close()
	result := control.ExternalRegistryProbeResult{Selection: read.Selection, Owner: owner, At: time.Now().Unix(), Code: "OK"}
	if err = client.Login(ctx); err != nil {
		result.Code = registryclient.Sanitize(err).Error()
	} else if read.Image != "" {
		image, err := client.Resolve(ctx, read.Image)
		if err != nil {
			result.Code = registryclient.Sanitize(err).Error()
		} else {
			pull, err := client.CheckPull(ctx, image, v1.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH})
			if err != nil {
				result.Code = registryclient.Sanitize(err).Error()
			} else {
				result.Image = &image
				result.Pull = &pull
			}
		}
	}
	latest, err := r.currentView(ctx)
	if err != nil || latest.Local {
		return control.ExternalRegistryProbeResult{}, sfcp.ErrAdmission
	}
	current, err := r.controlPolicy.ExternalRegistryProbeOwner(latest.State, read, time.Now().Unix())
	if err != nil || current != owner {
		return control.ExternalRegistryProbeResult{}, sfcp.ErrAdmission
	}
	if _, err = r.externalRegistryWork(ctx, read.Selection); err != nil {
		return control.ExternalRegistryProbeResult{}, sfcp.ErrAdmission
	}
	result.At = time.Now().Unix()
	if !result.Valid(read) {
		return control.ExternalRegistryProbeResult{}, sfcp.ErrAdmission
	}
	return result, nil
}
func (r *Runtime) externalRegistryProbe(ctx context.Context, read control.ExternalRegistryProbeRead) (json.RawMessage, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return nil, sfcp.ErrAdmission
	}
	owner, err := r.controlPolicy.ExternalRegistryProbeOwner(view.State, read, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if owner == r.Identity.Public {
		result, err := r.probeExternalRegistry(ctx, read)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	peer, ok := r.Mesh.Peer(sfcp.Identity(owner))
	if !ok || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	body, _ := json.Marshal(read)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "external-registry-probe", Input: body})
	if err != nil || reply.Code != "ok" {
		return nil, sfcp.ErrAdmission
	}
	result, err := schema.Decode[control.ExternalRegistryProbeResult](reply.Data)
	if err != nil || !result.Valid(read) || result.Owner != owner {
		return nil, sfcp.ErrAdmission
	}
	return json.Marshal(result)
}
