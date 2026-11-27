// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/workload"
)

const maxAppInputBytes = 64 << 10

func (r *Runtime) appInputPermit(ctx context.Context, request control.AppBindingRequest) (control.AppBindingPermit, error) {
	request.At = time.Now().Unix()
	raw, _ := json.Marshal(request)
	reply, err := r.appCall(ctx, "app-binding-permit", raw)
	if err != nil {
		return control.AppBindingPermit{}, err
	}
	permit, err := schema.Decode[control.AppBindingPermit](reply.Data)
	if err != nil || permit.Task != request.Task || permit.ReadSet == ([32]byte{}) || permit.CommandIndex == 0 || permit.MaxConsumers < 1 {
		return control.AppBindingPermit{}, deployment.ErrInputs
	}
	b, err := deployment.DecodeBinding(permit.Binding)
	if err != nil || b.Digest() != request.Digest || b.Needs().Use.NodeKey != r.Identity.Public {
		return control.AppBindingPermit{}, deployment.ErrInputs
	}
	return permit, nil
}

func (r *Runtime) appProjectionStore() (*deployment.ProjectionStore, error) {
	r.inputMu.Lock()
	defer r.inputMu.Unlock()
	if r.projections != nil {
		return r.projections, nil
	}
	if r.installation == nil || r.ctx.Err() != nil {
		return nil, deployment.ErrInputs
	}
	gate := func(ctx context.Context, b deployment.Binding) error {
		v, err := r.Engine().Read(ctx, false)
		if err != nil {
			return err
		}
		a, err := r.controlPolicy.ReadApps(v.State)
		if err != nil {
			return err
		}
		source, ok := a.BindingSource(b.Digest())
		if !ok {
			return deployment.ErrInputs
		}
		_, err = r.appInputPermit(ctx, control.AppBindingRequest{Task: source.Task, Digest: b.Digest()})
		return err
	}
	store, err := deployment.OpenProjections(filepath.Join(r.nativeRoot, "workload", "inputs"), r.controlPolicy.Cluster, r.Identity.Public, maxAppInputBytes, gate)
	if err != nil {
		return nil, err
	}
	r.projections = store
	return store, nil
}

// PrepareAppInputs is the node owner boundary consumed by the managed app
// controller. No user-provided values or host paths enter this API. The same
// original Binding/read-set and current quorum gates surround real provider
// reads, Materialize, filesystem publication and subsequent native borrowing.
func (r *Runtime) PrepareAppInputs(ctx context.Context, request control.AppBindingRequest) (workload.InputRef, error) {
	r.inputLife.RLock()
	defer r.inputLife.RUnlock()
	if r.ctx.Err() != nil {
		return workload.InputRef{}, deployment.ErrInputs
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	request.At = time.Now().Unix()
	// The first permit only gates finding an already published projection;
	// the one before Materialize below is always asked fresh.
	permit, reused := r.reusableAppInputPermit(ctx, request)
	if !reused {
		link, _ := r.leaderLink()
		asked := time.Now()
		var err error
		permit, err = r.appInputPermit(ctx, request)
		if err != nil {
			r.forgetAppInputPermit(request)
			return workload.InputRef{}, err
		}
		r.rememberAppInputPermit(request, permit, link, asked)
	}
	b, err := deployment.DecodeBinding(permit.Binding)
	if err != nil || permit.Inputs.Key == "" || !b.Needs().HasSources() {
		return workload.InputRef{}, deployment.ErrInputs
	}
	ref := workload.InputRef{Key: permit.Inputs.Key, Generation: request.Task.Generation, Binding: request.Digest}
	store, err := r.appProjectionStore()
	if err != nil {
		return ref, err
	}
	if ready, err := store.Ready(ctx, ref); err != nil || ready {
		return ref, err
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return ref, err
	}
	reads, err := r.controlPolicy.AppInputReads(v.State, r.commandIdentity().Public, request, permit)
	if err != nil {
		return ref, err
	}
	var values []deployment.Fetched
	defer func() {
		for _, v := range values {
			for _, data := range v.Value.Values {
				clear(data)
			}
		}
	}()
	seen := map[string]bool{}
	for _, read := range reads {
		for _, leaf := range read.Plan.Leaves {
			id := read.Realm + "/" + leaf.Secret
			if seen[id] {
				continue
			}
			seen[id] = true
			var profile secrets.WriteProfile
			for _, p := range read.Profiles {
				if p.ID == leaf.Reference.Profile {
					profile = p
					break
				}
			}
			if profile.Key == ([32]byte{}) {
				return ref, secrets.ErrProvider
			}
			fetch := control.AppInputFetch{Schema: 1, Consumer: r.commandIdentity().Public, Binding: request, ReadSet: permit.ReadSet, MinimumIndex: permit.CommandIndex, Realm: read.Realm, Secret: leaf.Secret}
			value, err := r.fetchAppInputLeaf(ctx, fetch, profile)
			if err != nil {
				return ref, err
			}
			values = append(values, deployment.Fetched{Realm: read.Realm, Value: value})
		}
	}
	request.At = time.Now().Unix()
	latest, err := r.appInputPermit(ctx, request)
	if err != nil || latest.ReadSet != permit.ReadSet || latest.Task != permit.Task || latest.Inputs != permit.Inputs {
		return ref, deployment.ErrInputs
	}
	v, err = r.Engine().Read(ctx, false)
	if err != nil {
		return ref, err
	}
	stage, err := r.controlPolicy.MaterializeAppInputs(v.State, r.commandIdentity().Public, request, latest, values, maxAppInputBytes)
	if err != nil {
		return ref, err
	}
	defer stage.Destroy()
	return store.Publish(ctx, b, stage, latest.Inputs.Revision, latest.MaxConsumers)
}

// appInputPermitReuse bounds how long PrepareAppInputs lets an earlier
// permit for the same binding stand for a new one.
const appInputPermitReuse = 30 * time.Second

type appInputPermitEntry struct {
	permit control.AppBindingPermit
	asked  time.Time
	link   leaderLink
}

func appInputPermitKey(request control.AppBindingRequest) string {
	return fmt.Sprintf("%s/%d/%d/%x", request.Task.Key, request.Task.Generation, request.Task.Revision, request.Digest)
}

// reusableAppInputPermit returns the last permit for request when the leader
// would answer the same: it was asked less than appInputPermitReuse ago over
// a leader link (same leader and term) that has not broken since, and this
// replica has applied nothing after the permit's command index. A committed
// change of any kind, a leader change or a broken link asks again.
func (r *Runtime) reusableAppInputPermit(ctx context.Context, request control.AppBindingRequest) (control.AppBindingPermit, bool) {
	r.inputPermitMu.Lock()
	entry, ok := r.inputPermits[appInputPermitKey(request)]
	r.inputPermitMu.Unlock()
	if !ok || time.Since(entry.asked) >= appInputPermitReuse {
		return control.AppBindingPermit{}, false
	}
	if l, linked := r.leaderLink(); !linked || !l.heldSince(entry.link, entry.asked) {
		return control.AppBindingPermit{}, false
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil || v.State.Index() != entry.permit.CommandIndex {
		return control.AppBindingPermit{}, false
	}
	return entry.permit, true
}

func (r *Runtime) rememberAppInputPermit(request control.AppBindingRequest, permit control.AppBindingPermit, link leaderLink, asked time.Time) {
	r.inputPermitMu.Lock()
	defer r.inputPermitMu.Unlock()
	if r.inputPermits == nil {
		r.inputPermits = map[string]appInputPermitEntry{}
	}
	for key, old := range r.inputPermits {
		if time.Since(old.asked) >= appInputPermitReuse {
			delete(r.inputPermits, key)
		}
	}
	r.inputPermits[appInputPermitKey(request)] = appInputPermitEntry{permit: permit, asked: asked, link: link}
}

func (r *Runtime) forgetAppInputPermit(request control.AppBindingRequest) {
	r.inputPermitMu.Lock()
	delete(r.inputPermits, appInputPermitKey(request))
	r.inputPermitMu.Unlock()
}

// RetireAppInputs settles files only after the original owner's positive Task
// closure and the projection's actual pins0/Gone. Shared Release still needs
// every separate Volume proof. It intentionally works after permission revoke.
func (r *Runtime) RetireAppInputs(ctx context.Context, request control.AppBindingRequest, stopped deployment.Observation) (deployment.Closure, error) {
	r.inputLife.RLock()
	defer r.inputLife.RUnlock()
	return r.retireAppInputs(ctx, request, stopped)
}
func (r *Runtime) retireAppInputs(ctx context.Context, request control.AppBindingRequest, stopped deployment.Observation) (deployment.Closure, error) {
	if r.ctx.Err() != nil {
		return deployment.Closure{}, deployment.ErrInputs
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return deployment.Closure{}, err
	}
	request.At = time.Now().Unix()
	source, err := r.controlPolicy.AppInputClosure(v.State, r.commandIdentity().Public, request, stopped)
	if err != nil || source.Inputs.Key == "" || source.Inputs.Revision == math.MaxUint64 {
		return deployment.Closure{}, deployment.ErrInputs
	}
	store, err := r.appProjectionStore()
	if err != nil {
		return deployment.Closure{}, err
	}
	ref := workload.InputRef{Key: source.Inputs.Key, Generation: source.Task.Generation, Binding: request.Digest}
	gone, err := store.Gone(ref)
	if err != nil {
		return deployment.Closure{}, err
	}
	if !gone {
		if err = store.Drain(ctx, ref, source.Inputs.Revision+1); err != nil {
			return deployment.Closure{}, err
		}
	}
	if gone, err := store.Gone(ref); err != nil || !gone {
		return deployment.Closure{}, errors.Join(deployment.ErrInputs, err)
	}
	return store.SecretClosure(ref, r.Identity.Private)
}
