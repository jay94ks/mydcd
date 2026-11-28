// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	dockernet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// TaskIdentityResource is the resource a Task's native identity (name and
// org.sfc.spec label) is derived from: the spec without its extra network
// attachments. Those can then change in place under the same container. A
// Task with no extra attachments keeps its original bytes and identity.
func TaskIdentityResource(r reconcile.Resource) reconcile.Resource {
	s, err := DecodeContainer(r.Spec)
	if err != nil {
		return r
	}
	return taskIdentity(r, s)
}

// taskIdentity is TaskIdentityResource over an already decoded spec, for
// callers inside DecodeContainer's own validation.
func taskIdentity(r reconcile.Resource, s ContainerSpec) reconcile.Resource {
	if len(s.Attachments) == 0 {
		return r
	}
	s.Attachments = nil
	raw, err := json.Marshal(s)
	if err != nil {
		return r
	}
	r.Spec = string(raw)
	return r
}

// InPlace: the same generation of one Task whose only difference is its set
// of extra network attachments. Attachments kept on both sides must be
// identical (same Bridge pin, addresses and routes); the primary network and
// everything else are part of the identity and so equal. Tasks with Volumes
// keep their per-operation activation and are replaced instead.
func (d *DockerDriver) InPlace(applied, target reconcile.Resource) bool {
	return inPlaceAttachments(applied, target)
}

func inPlaceAttachments(applied, target reconcile.Resource) bool {
	if !applied.Present || !target.Present || applied.Generation != target.Generation || applied.Spec == target.Spec {
		return false
	}
	a, errA := DecodeContainer(applied.Spec)
	b, errB := DecodeContainer(target.Spec)
	if errA != nil || errB != nil || len(a.Volumes)+len(a.RemoteVolumes)+len(b.Volumes)+len(b.RemoteVolumes) != 0 {
		return false
	}
	if TaskIdentityResource(applied).Spec != TaskIdentityResource(target).Spec {
		return false
	}
	before := map[string]TaskAttachment{}
	for _, x := range a.Attachments {
		before[x.Bridge] = x
	}
	for _, y := range b.Attachments {
		if x, kept := before[y.Bridge]; kept && !reflect.DeepEqual(x, y) {
			return false
		}
	}
	return true
}

// syncAttachments brings an existing same-generation container to the target
// attachment set: it pins and connects attachments the target adds, then
// disconnects and returns the pins of attachments it drops. A repeat after a
// lost reply finds the work done: connect is skipped for a present endpoint,
// and a dropped pin is returned only after its endpoint is gone.
func (d *DockerDriver) syncAttachments(ctx context.Context, s ContainerSpec, id engine.Identity, target reconcile.Resource, got container.InspectResponse) (container.InspectResponse, error) {
	if d.previous == nil || !inPlaceAttachments(*d.previous, target) {
		return got, nil
	}
	old, err := DecodeContainer(d.previous.Spec)
	if err != nil {
		return got, err
	}
	if got.NetworkSettings == nil {
		return got, engine.ErrOwnership
	}
	leases, err := d.acquireNetworks(ctx, s, id)
	if err != nil {
		return got, err
	}
	changed := false
	for i, a := range s.Networks() {
		if i == 0 || taskEndpoint(got.NetworkSettings, leases[i]) != nil {
			continue
		}
		for _, address := range []netip.Addr{a.IPv4, a.IPv6} {
			if address.IsValid() && !allowedTaskAddress(address, leases[i].Spec) {
				return got, network.ErrPolicy
			}
		}
		ipam := &dockernet.EndpointIPAMConfig{IPv4Address: a.IPv4, IPv6Address: a.IPv6}
		if err = ctx.Err(); err != nil {
			return got, err
		}
		if _, err = d.Engine.API.NetworkConnect(ctx, leases[i].NetworkID, client.NetworkConnectOptions{Container: got.ID, EndpointConfig: &dockernet.EndpointSettings{IPAMConfig: ipam}}); err != nil {
			return got, err
		}
		changed = true
	}
	kept := map[string]bool{}
	for _, a := range s.Networks() {
		kept[a.Bridge] = true
	}
	consumer := containerConsumer(id)
	var errs []error
	for _, a := range old.Attachments {
		if kept[a.Bridge] {
			continue
		}
		bridges := d.bridgeManager(old, a.BridgeOwner)
		if bridges == nil {
			errs = append(errs, engine.ErrOwnership)
			continue
		}
		lease, inspectErr := bridges.InspectConsumer(ctx, a.Bridge, consumer, a.BridgeGeneration)
		if errors.Is(inspectErr, reconcile.ErrLease) {
			// No pin: an earlier attempt disconnected and then returned it.
			continue
		}
		if inspectErr != nil {
			errs = append(errs, inspectErr)
			continue
		}
		if taskEndpoint(got.NetworkSettings, lease) != nil {
			if _, err = d.Engine.API.NetworkDisconnect(ctx, lease.NetworkID, client.NetworkDisconnectOptions{Container: got.ID}); err != nil {
				errs = append(errs, err)
				continue
			}
			changed = true
		}
		if err = bridges.ReturnConsumer(a.Bridge, consumer, a.BridgeGeneration); err != nil {
			errs = append(errs, err)
		}
	}
	if err = errors.Join(errs...); err != nil {
		return got, err
	}
	if !changed {
		return got, nil
	}
	fresh, err := d.Engine.API.ContainerInspect(ctx, got.ID, client.ContainerInspectOptions{})
	return fresh.Container, err
}

// AttachmentClosed reports whether an extra attachment that an in-place Apply
// detached is fully closed on this node: the settled Applied target of that
// generation no longer carries its Bridge, and its pin is returned. The pin
// is returned only after the engine endpoint is gone (syncAttachments), so
// this is the owner's witness for releasing the attachment's fixed addresses.
func (m *Manager) AttachmentClosed(ctx context.Context, key string, generation uint64, detached TaskAttachment) (bool, error) {
	r, err := m.journal.Read(key)
	if err != nil {
		return false, err
	}
	if generation == 0 || detached.Bridge == "" || detached.BridgeGeneration == 0 || r.State.Pending != nil || !r.State.Applied.Present || r.State.Applied.Generation != generation || r.State.Applied != r.State.Desired.Resource {
		return false, nil
	}
	s, err := DecodeContainer(r.State.Applied.Spec)
	if err != nil {
		return false, err
	}
	for _, a := range s.Networks() {
		if a.Bridge == detached.Bridge {
			return false, nil
		}
	}
	bridges := m.driver.bridgeManager(s, detached.BridgeOwner)
	if bridges == nil {
		return false, engine.ErrOwnership
	}
	// Any pin of this consumer, at any Bridge generation, keeps it open:
	// InspectConsumer's ErrLease also means a pin at another generation.
	journal, ok := bridges.(interface {
		View(string) (reconcile.Record, error)
	})
	if !ok {
		return false, engine.ErrOwnership
	}
	id, err := m.driver.Engine.Identity("container", key, TaskIdentityResource(r.State.Applied))
	if err != nil {
		return false, err
	}
	record, err := journal.View(detached.Bridge)
	if err != nil {
		return false, err
	}
	_, held := record.Consumers[containerConsumer(id)]
	return !held, nil
}
