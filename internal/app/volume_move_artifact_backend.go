// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"os"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type runtimeMoveBackend struct{ r *Runtime }

func (d runtimeMoveBackend) Authorize(ctx context.Context, b moveArtifactIntent, cleanup bool) error {
	kind := "read"
	if cleanup {
		kind = "cleanup"
	}
	permit, err := d.r.volumeMovePermit(ctx, b.Job, kind)
	if err != nil {
		return err
	}
	if permit.Reader == nil || *permit.Reader != b.Reader {
		return sfcp.ErrAdmission
	}
	return nil
}
func (d runtimeMoveBackend) Source(ctx context.Context, b moveArtifactIntent) (volumes.ColdSource, error) {
	source, err := d.r.activations.ColdSource(ctx, b.Job.Source)
	if err != nil || !backupSourceMatches(source, control.VolumeBackupBinding{Scope: b.Job.Binding.Scope, Source: b.Job.Source, Compatibility: b.Job.Binding.Compatibility}) {
		return volumes.ColdSource{}, errors.Join(errBackupArtifact, err)
	}
	return source, nil
}
func (d runtimeMoveBackend) Export(ctx context.Context, b moveArtifactIntent, out *os.File) (volumes.ArchiveReceipt, error) {
	permit, err := d.r.volumeMovePermit(ctx, b.Job, "read")
	if err != nil {
		return volumes.ArchiveReceipt{}, err
	}
	if permit.Move.Fence == nil || permit.Reader == nil || *permit.Reader != b.Reader {
		return volumes.ArchiveReceipt{}, sfcp.ErrAdmission
	}
	return d.r.activations.ExportMoveCold(ctx, b.Job.Source, *permit.Move.Fence, b.Reader, func(ctx context.Context, ready volumes.NativeReady, c volumes.Consumer) error {
		if control.VolumeNativeDigest(ready) != control.VolumeNativeDigest(b.Job.Source) || c != b.Reader {
			return sfcp.ErrAdmission
		}
		return d.Authorize(ctx, b, false)
	}, out, b.Job.Options())
}
func (d runtimeMoveBackend) CloseReader(ctx context.Context, b moveArtifactIntent) error {
	return d.r.nativeVolumes.CloseCold(ctx, b.Job.Source, b.Reader, b.Job.Options())
}
