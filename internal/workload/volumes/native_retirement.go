// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"errors"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/moby/moby/client"
)

type nativeRetirement struct {
	Schema     uint8
	Name, Spec string
}

// Retire runs only for an explicitly deleted original Apply. Before deleting
// it, persist positive observation of its exact fixed name/labels. An absent
// never-observed Create remains Unknown: a late SDK call may still create it.
// Generic A2 handles Prepared abort and Drain/remaining consumers first.
func (d nativeDriver) Retire(ctx context.Context, key string, op reconcile.Operation, raw []byte, save func([]byte) error) (bool, error) {
	_, id, err := d.parameters(key, op)
	if err != nil || op.Kind != reconcile.Apply || op.Phase != reconcile.Retiring {
		return false, errors.Join(reconcile.ErrOperation, err)
	}
	want := nativeRetirement{Schema: 1, Name: id.Name, Spec: id.Labels["org.mydc.spec"]}
	observed := false
	if len(raw) > 0 {
		proof, e := schema.Decode[nativeRetirement](raw)
		if e != nil || proof != want {
			return false, reconcile.ErrOperation
		}
		observed = true
	}
	got, err := d.engine.API.VolumeInspect(ctx, id.Name, client.VolumeInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		return observed, nil
	}
	if err != nil {
		return false, err
	}
	if !matchNative(got.Volume, id) {
		return false, engine.ErrOwnership
	}
	if !observed {
		proof, _ := json.Marshal(want)
		if err = save(proof); err != nil {
			return false, err
		}
	}
	if _, err = d.engine.API.VolumeRemove(ctx, id.Name, client.VolumeRemoveOptions{}); err != nil {
		return false, err
	}
	if _, err = d.engine.API.VolumeInspect(ctx, id.Name, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
		return false, errors.Join(reconcile.ErrPending, err)
	}
	return true, nil
}
