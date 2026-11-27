// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"errors"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

func (s *Activations) MountSource(key string, scope Scope, owner Owner, generation uint64, binding string) (string, bool, error) {
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return "", false, ErrActivation
	}
	return s.mountSource(key, scope, owner, generation, binding)
}

// Caller holds the activation entries. Fixed volumes are engine "sfc"
// volumes: the engine never resolves a host path for them, it asks sfcd for
// the held directory on Mount. So the SDK transport needs no bind-source
// guard; this only proves each binding still holds its original pin and
// that the projection is the original data before Create or Start.
func (s *Activations) bindClient(ctx context.Context, rows []activationBatchEntry) (*client.Client, func(), error) {
	for _, row := range rows {
		if !row.r.Scope.TenantManaged() {
			continue
		}
		if row.e.store.native.fixed == nil {
			return nil, nil, ErrActivation
		}
		b := row.d.Bindings[row.i]
		if b.Closed || b.Lease.Pin.Token == 0 {
			return nil, nil, ErrActivation
		}
		if _, _, err := row.e.store.native.MountSource(row.r.NativeKey, row.r.Scope, row.r.Consumer.Owner, row.r.NativeGeneration, row.r.NativeBinding); err != nil {
			return nil, nil, err
		}
		_, h, err := row.e.store.native.fixed.BindSource(ctx, b.Lease)
		if err != nil {
			return nil, nil, err
		}
		_ = h.Close()
	}
	return s.client.API, func() {}, nil
}

// API source metadata is not evidence of what a separate runtime namespace
// mounted. Check the live process before settling Start or publishing Ready.
// Retirement deliberately does not require this active-use proof.
func (s *Activations) checkFixedProcess(ctx context.Context, rows []activationBatchEntry, got container.InspectResponse) error {
	var sources []engine.BindSource
	var handles []*nodestorage.DirectoryHandle
	defer func() {
		for _, h := range handles {
			_ = h.Close()
		}
	}()
	for _, row := range rows {
		if !row.r.Scope.TenantManaged() {
			continue
		}
		if row.e.store.native.fixed == nil || got.State == nil || !got.State.Running || got.State.Pid <= 0 {
			return ErrActivation
		}
		b := row.d.Bindings[row.i]
		if b.Closed || b.Lease.Pin.Token == 0 {
			return ErrActivation
		}
		_, h, err := row.e.store.native.fixed.InspectBindSource(ctx, b.Lease)
		if err != nil {
			return err
		}
		handles = append(handles, h)
		target := ""
		for _, m := range got.Mounts {
			if m.Type == mount.TypeVolume && m.Name == row.r.Consumer.Owner.Native && m.Driver == EngineVolumeDriver && m.RW == row.r.Consumer.Writable {
				if target != "" {
					return ErrActivation
				}
				target = m.Destination
			}
		}
		if target == "" {
			return ErrActivation
		}
		sources = append(sources, engine.BindSource{Path: target, DirectoryFD: h.FD()})
	}
	if len(sources) == 0 {
		return nil
	}
	return engine.CheckProcessBindSources(got.State.Pid, sources)
}

// CreateAll consumes the original whole-task no-Create checkpoint and calls
// Docker once, using exact pinned fixed bind sources when present. Keeping this
// inside the existing barrier avoids a second fixed-volume execution protocol.
func (s *Activations) CreateAll(ctx context.Context, refs []Activation, options client.ContainerCreateOptions) error {
	refs, err := activationBatch(refs)
	if err != nil {
		return err
	}
	s.life.RLock()
	defer s.life.RUnlock()
	rows, unlock, err := s.lockBatch(refs)
	if err != nil {
		return err
	}
	defer unlock()
	id, err := s.taskIdentity(refs[0])
	if err != nil || options.Config == nil || options.HostConfig == nil || !id.Matches(options.Name, options.Config.Labels) {
		return errors.Join(ErrActivation, err)
	}
	for _, row := range rows {
		b := row.d.Bindings[row.i]
		if !b.CreatePrepared || b.Closed || b.Started || b.NativeID != "" || b.Lease.Pin.Token == 0 {
			return ErrActivation
		}
		source, bind, err := row.e.store.native.MountSource(row.r.NativeKey, row.r.Scope, row.r.Consumer.Owner, row.r.NativeGeneration, row.r.NativeBinding)
		if err != nil {
			return err
		}
		count := 0
		for _, m := range options.HostConfig.Mounts {
			if m.Type != mount.TypeVolume || m.Source != source || m.ReadOnly == row.r.Consumer.Writable || m.VolumeOptions == nil || !m.VolumeOptions.NoCopy || m.VolumeOptions.Subpath != "" || len(m.VolumeOptions.Labels) != 0 {
				continue
			}
			driver := m.VolumeOptions.DriverConfig
			if !bind && driver == nil || bind && driver != nil && driver.Name == EngineVolumeDriver && len(driver.Options) == 0 {
				count++
			}
		}
		if count != 1 {
			return ErrActivation
		}
		if bind && options.HostConfig.RestartPolicy.Name != "" && options.HostConfig.RestartPolicy.Name != "no" {
			return ErrActivation
		}
	}
	api, closeAPI, err := s.bindClient(ctx, rows)
	if err != nil {
		return err
	}
	defer closeAPI()
	for i := range rows {
		rows[i].d.Bindings[rows[i].i].CreatePrepared = false
	}
	if err = s.saveBatch(rows); err != nil {
		return err
	}
	_, err = api.ContainerCreate(ctx, options)
	if errors.Is(err, engine.ErrBindBeforeRequest) {
		// This is an explicit transport fact, not absence/timeout inference.
		// Preserve the original operation/pins; only restore its no-Create
		// checkpoint because no API bytes could reach the Engine.
		for i := range rows {
			rows[i].d.Bindings[rows[i].i].CreatePrepared = true
		}
		return errors.Join(err, s.saveBatch(rows))
	}
	return err
}
