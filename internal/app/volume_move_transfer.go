// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"io"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type moveTransferSelection struct {
	Schema    uint8
	Selection control.VolumeMoveSelection
	Binding   [32]byte
}

func (r *Runtime) serveVolumeTransfers() error {
	artifacts := r.backupArtifacts
	if artifacts == nil {
		return nil
	}
	return r.Mesh.OnVolumeTransfer(func(ctx context.Context, s *sfcp.Session, q sfcp.VolumeTransferRequest) (sfcp.VolumeSource, error) {
		selection, err := schema.Decode[moveTransferSelection](q.Metadata)
		if err != nil || selection.Schema != 1 || selection.Selection.Scope.Cluster != r.controlPolicy.Cluster {
			return sfcp.VolumeSource{}, sfcp.ErrAdmission
		}
		view, err := r.Engine().Read(ctx, false)
		if err != nil {
			return sfcp.VolumeSource{}, err
		}
		registry, err := r.controlPolicy.Volumes(view.State)
		if err != nil {
			return sfcp.VolumeSource{}, err
		}
		job, _, ok := registry.Move(selection.Selection)
		if !ok || job.Digest() != selection.Binding || !r.acceptsResourceOwner(ctx, job.Binding.Source.Node, job.Binding.Source.Key) || q.ExpiresAt != job.ExpiresAt {
			return sfcp.VolumeSource{}, sfcp.ErrAdmission
		}
		members, err := r.controlPolicy.Members(view.State)
		if err != nil || !members.OwnsResource([32]byte(s.Peer().Key), job.Binding.Target.Key) {
			return sfcp.VolumeSource{}, sfcp.ErrAdmission
		}
		owner, local := r.nativeOwner(job.Binding.Source.Key)
		if !local || owner.backupArtifacts == nil {
			return sfcp.VolumeSource{}, sfcp.ErrAdmission
		}
		sourceArtifacts := owner.backupArtifacts
		permit, err := owner.volumeMovePermit(ctx, job, "read")
		if err != nil || permit.Reader == nil || permit.Move.Phase != volumes.Copying || permit.Move.Manifest == nil || permit.Move.Manifest.Artifact != q.Artifact || permit.Move.Manifest.Bytes != q.Bytes {
			return sfcp.VolumeSource{}, sfcp.ErrAdmission
		}
		intent := moveArtifactIntent{Schema: 1, Job: job, Reader: *permit.Reader}
		receipt := permit.Move.Manifest.ArchiveReceipt()
		return sfcp.VolumeSource{Lifetime: owner.ctx, WithFile: func(ctx context.Context, read func(io.ReadSeeker) error) error {
			return sourceArtifacts.withMoveFile(ctx, intent, receipt, read)
		}, Authorize: func(ctx context.Context) error {
			current, err := owner.volumeMovePermit(ctx, job, "read")
			if err != nil {
				return err
			}
			if current.Reader == nil || *current.Reader != intent.Reader || current.Move.Phase != volumes.Copying || current.Move.Manifest == nil || current.Move.Manifest.ArchiveReceipt() != receipt {
				return sfcp.ErrAdmission
			}
			return nil
		}}, nil
	})
}

func moveTransferMetadata(job control.VolumeMove) []byte {
	raw, _ := json.Marshal(moveTransferSelection{Schema: 1, Selection: job.Selection(), Binding: job.Digest()})
	return raw
}
