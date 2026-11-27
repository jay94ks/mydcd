// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/containerops"
	"io"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) imageBuildSecretInputs(ctx context.Context, spec imagebuild.JobSpec) (control.ImageBuildSecretInputs, error) {
	selection := control.ImageBuildSecretSelection{Tenant: spec.Tenant, Job: spec.ID, Snapshot: spec.Digest()}
	q := control.ImageBuildSecretRequest{Selection: selection, At: time.Now().Unix()}
	raw, _ := json.Marshal(q)
	reply, err := r.appCall(ctx, "image-build-secret-inputs", raw)
	if err != nil {
		return control.ImageBuildSecretInputs{}, err
	}
	work, err := schema.Decode[control.ImageBuildSecretInputs](reply.Data)
	if err != nil || reply.Local || work.Selection != selection || work.Index == 0 || work.Epoch == 0 || work.Inputs.ReadSet == ([32]byte{}) || len(work.Inputs.Entries) > len(spec.Context.Secrets) {
		return control.ImageBuildSecretInputs{}, sfcp.ErrAdmission
	}
	view, err := r.Engine().ReadAtLeast(ctx, work.Index)
	if err != nil || view.State.ModuleEpoch() != work.Epoch {
		return control.ImageBuildSecretInputs{}, sfcp.ErrAdmission
	}
	q.At = time.Now().Unix()
	current, err := r.controlPolicy.ImageBuildSecretInputs(view.State, r.Identity.Public, q)
	if err != nil || current.Inputs.ReadSet != work.Inputs.ReadSet {
		return control.ImageBuildSecretInputs{}, sfcp.ErrAdmission
	}
	return work, nil
}

// Borrow provider I/O lifetime without turning the finite build into an app.
// Values stay ephemeral until the common SDK TAR writer has joined. The native
// job/root owner retains its own durable references through actual cleanup.
// The caller owns the returned log filter. Native AttachLogs forks independent
// stdout/stderr matchers; destroy this parent after attach returns. Each fork
// finishes only on normal EOF and is destroyed after its reader has joined.
func (r *Runtime) stageImageBuildSecrets(ctx context.Context, spec imagebuild.JobSpec, native *imagebuild.NativeJobs, logs io.Writer) (*containerops.Redactor, error) {
	r.inputLife.RLock()
	defer r.inputLife.RUnlock()
	if native == nil || logs == nil || r.ctx.Err() != nil {
		return nil, sfcp.ErrAdmission
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	work, err := r.imageBuildSecretInputs(ctx, spec)
	if err != nil {
		return nil, err
	}
	var fetched []secrets.Fetched
	defer func() {
		for _, v := range fetched {
			for _, data := range v.Values {
				clear(data)
			}
		}
	}()
	for _, input := range work.Inputs.Entries {
		q := control.AppInputFetch{Schema: 1, Consumer: r.Identity.Public, Binding: control.AppBindingRequest{At: time.Now().Unix()}, ReadSet: work.Inputs.ReadSet, MinimumIndex: work.Index, Realm: input.Realm, Secret: input.Leaf.Secret, ImageBuild: &work.Selection}
		v, err := r.fetchAppInputLeaf(ctx, q, input.Provider)
		fetched = append(fetched, v)
		if err != nil {
			return nil, err
		}
		if secrets.ValidateFetched(secrets.UsePlan{Leaves: []secrets.Leaf{input.Leaf}}, []secrets.Fetched{v}, 128<<10) != nil {
			return nil, sfcp.ErrAdmission
		}
	}
	var values []imagebuild.SecretValue
	for _, ref := range spec.Context.Secrets {
		found := false
		for i, input := range work.Inputs.Entries {
			if input.Realm != ref.Realm || input.Leaf.Secret != ref.Secret {
				continue
			}
			data, exists := fetched[i].Values[ref.Key]
			if !exists {
				return nil, sfcp.ErrAdmission
			}
			values = append(values, imagebuild.SecretValue{Reference: ref, Value: data})
			found = true
		}
		if !found {
			return nil, sfcp.ErrAdmission
		}
	}
	latest, err := r.imageBuildSecretInputs(ctx, spec)
	if err != nil || latest.Inputs.ReadSet != work.Inputs.ReadSet {
		return nil, sfcp.ErrAdmission
	}
	var masks []containerops.RedactionValue
	for _, value := range values {
		masks = append(masks, containerops.RedactionValue{Reference: value.Reference.Realm + "/" + value.Reference.Secret + "#" + value.Reference.Key, Value: value.Value})
	}
	redactor, err := containerops.NewRedactor(logs, masks)
	if err != nil {
		return nil, err
	}
	record, err := native.Record(spec)
	if err != nil {
		redactor.Destroy()
		return nil, err
	}
	if record.Solve != nil && record.Solve.SourceContent {
		// The original source owners perform registry TLS. The finite daemon
		// consumes only its private OCI session stores, without merging CAs.
		err = native.StageControlsTLS(ctx, spec, values, nil)
	} else if record.Solve != nil && record.Solve.TLS {
		roots, trustErr := r.imageBuildTrust(ctx, spec)
		if trustErr != nil {
			redactor.Destroy()
			return nil, trustErr
		}
		err = native.StageControlsTLS(ctx, spec, values, roots)
	} else {
		err = native.StageControls(ctx, spec, values)
	}
	if err != nil {
		redactor.Destroy()
		return nil, err
	}
	return redactor, nil
}
