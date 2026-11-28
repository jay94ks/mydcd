// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) volumeMoveInputPermit(ctx context.Context, selection control.VolumeMoveSelection) (control.VolumeMovePermit, error) {
	body, _ := json.Marshal(control.VolumeMovePermitRequest{Selection: selection, Kind: "prepare-inputs"})
	reply, err := r.appCall(ctx, "volume-move-permit", body)
	if err != nil {
		return control.VolumeMovePermit{}, err
	}
	permit, err := schema.Decode[control.VolumeMovePermit](reply.Data)
	if err != nil || reply.Local || reply.RaftIndex == 0 || permit.Job.Verify() != nil || permit.Job.Selection() != selection || permit.Inputs == nil || permit.Inputs.ReadSet == ([32]byte{}) || permit.Inputs.CommandIndex == 0 {
		return control.VolumeMovePermit{}, sfcp.ErrAdmission
	}
	return permit, nil
}

// Native readback stays on the actual consumer. Only the original target may
// request it; its own fresh quorum permit never delegates another node's reads.
func (r *Runtime) observeVolumeMoveInputs(ctx context.Context, caller [32]byte, request control.VolumeMoveInputProbe) (out control.VolumeMoveInputProof, failure error) {
	stage := "freshness"
	defer func() {
		if failure != nil && (r.ctx == nil || r.ctx.Err() == nil) {
			log.Printf("volume move input observation failed: move=%q stage=%s", request.Selection.ID, stage)
		}
	}()
	now := time.Now().Unix()
	if request.At < 0 || !access.Recent(request.At, now, 30) || request.ReadSet == ([32]byte{}) || request.MinimumIndex == 0 {
		return out, sfcp.ErrAdmission
	}
	r.inputLife.RLock()
	defer r.inputLife.RUnlock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	stage = "quorum-permit"
	permit, err := r.volumeMoveInputPermit(ctx, request.Selection)
	if err != nil || caller != permit.Job.Binding.Target.Key || permit.Inputs == nil || permit.Inputs.ReadSet != request.ReadSet || permit.Inputs.CommandIndex < request.MinimumIndex {
		return out, sfcp.ErrAdmission
	}
	stage = "replica"
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return out, err
	}
	stage = "readset"
	inputs, err := r.controlPolicy.VolumeMovePreparationInputs(view.State, r.Identity.Public, permit, time.Now().Unix())
	if err != nil {
		return out, err
	}
	observedAt := time.Now().Unix()
	stage = "native-resources"
	if err = r.checkMoveResourceReads(ctx, view, inputs.Resources); err != nil {
		return out, err
	}
	reads := inputs.Reads
	var values []deployment.Fetched
	defer func() {
		for _, value := range values {
			for _, data := range value.Value.Values {
				clear(data)
			}
		}
	}()
	seen := map[string]bool{}
	stage = "provider-read"
	for _, read := range reads {
		if read.Plan.Use.NodeKey != r.Identity.Public {
			continue
		}
		for _, leaf := range read.Plan.Leaves {
			key := read.Realm + "/" + leaf.Secret
			if seen[key] {
				continue
			}
			provider, ok := leafProvider(read.Profiles, leaf)
			if !ok {
				return out, secrets.ErrProvider
			}
			selection := request.Selection
			fetch := control.AppInputFetch{Schema: 1, Consumer: r.Identity.Public, ReadSet: request.ReadSet, MinimumIndex: permit.Inputs.CommandIndex, Realm: read.Realm, Secret: leaf.Secret, Move: &selection}
			value, err := r.fetchAppInputLeaf(ctx, fetch, provider)
			if err != nil {
				return out, err
			}
			seen[key] = true
			values = append(values, deployment.Fetched{Realm: read.Realm, Value: value})
		}
	}
	stage = "recheck-permit"
	latest, err := r.volumeMoveInputPermit(ctx, request.Selection)
	if err != nil || latest.Inputs == nil || latest.Inputs.ReadSet != request.ReadSet || latest.Job.Digest() != permit.Job.Digest() {
		return out, sfcp.ErrAdmission
	}
	stage = "recheck-replica"
	view, err = r.Engine().Read(ctx, false)
	if err != nil {
		return out, err
	}
	now = time.Now().Unix()
	stage = "values"
	if err = r.controlPolicy.CheckMoveInputValues(view.State, r.Identity.Public, latest, now, values, maxAppInputBytes); err != nil {
		return out, err
	}
	stage = "final-permit"
	fresh, err := r.volumeMoveInputPermit(ctx, request.Selection)
	if err != nil || fresh.Inputs == nil || fresh.Inputs.ReadSet != request.ReadSet || fresh.Job.Digest() != latest.Job.Digest() {
		return out, sfcp.ErrAdmission
	}
	now = time.Now().Unix()
	stage = "proof-freshness"
	if observedAt > now || now-observedAt > 30 {
		return out, sfcp.ErrAdmission
	}
	out = control.VolumeMoveInputProof{Schema: 1, Selection: request.Selection, Binding: latest.Job.Digest(), ReadSet: request.ReadSet, Consumer: r.Identity.Public, At: observedAt}
	out.Signature = ed25519.Sign(r.Identity.Private, control.VolumeMoveInputProofBytes(out))
	return out, nil
}

func (r *Runtime) prepareVolumeMoveInputs(ctx context.Context, job control.VolumeMove) ([32]byte, int64, error) {
	permit, err := r.volumeMoveInputPermit(ctx, job.Selection())
	if err != nil {
		return [32]byte{}, 0, fmt.Errorf("input authorization: %w", err)
	}
	if permit.Job.Digest() != job.Digest() {
		return [32]byte{}, 0, fmt.Errorf("original input job differs: %w", sfcp.ErrAdmission)
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return [32]byte{}, 0, err
	}
	inputs, err := r.controlPolicy.VolumeMovePreparationInputs(view.State, r.Identity.Public, permit, time.Now().Unix())
	if err != nil {
		return [32]byte{}, 0, err
	}
	owners := map[[32]byte]string{}
	for _, row := range inputs.Resources {
		if old, ok := owners[row.Owner]; ok && old != row.Node {
			return [32]byte{}, 0, sfcp.ErrAdmission
		}
		owners[row.Owner] = row.Node
	}
	for _, read := range inputs.Reads {
		use := read.Plan.Use
		if old, ok := owners[use.NodeKey]; ok && old != use.Node {
			return [32]byte{}, 0, sfcp.ErrAdmission
		}
		owners[use.NodeKey] = use.Node
	}
	var proofs []control.VolumeMoveInputProof
	for owner, node := range owners {
		request := control.VolumeMoveInputProbe{Selection: job.Selection(), ReadSet: permit.Inputs.ReadSet, MinimumIndex: permit.Inputs.CommandIndex, At: time.Now().Unix()}
		var proof control.VolumeMoveInputProof
		if owner == r.Identity.Public {
			proof, err = r.observeVolumeMoveInputs(ctx, r.Identity.Public, request)
		} else {
			peer, ok := r.Mesh.Peer(sfcp.Identity(owner))
			if !ok || !peer.Member || peer.ID != node {
				return [32]byte{}, 0, sfcp.ErrAdmission
			}
			raw, _ := json.Marshal(request)
			reply, callErr := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "volume-move-inputs-observe", Input: raw})
			err = callErr
			if err == nil {
				proof, err = schema.Decode[control.VolumeMoveInputProof](reply.Data)
			}
		}
		if err != nil {
			return [32]byte{}, 0, fmt.Errorf("input observation on %s: %w", node, err)
		}
		if err = proof.Verify(job, permit.Inputs.ReadSet, owner, time.Now().Unix()); err != nil {
			return [32]byte{}, 0, err
		}
		proofs = append(proofs, proof)
	}
	latest, err := r.volumeMoveInputPermit(ctx, job.Selection())
	if err != nil {
		return [32]byte{}, 0, fmt.Errorf("final input authorization: %w", err)
	}
	if latest.Inputs == nil || latest.Job.Digest() != job.Digest() || latest.Inputs.ReadSet != permit.Inputs.ReadSet {
		return [32]byte{}, 0, fmt.Errorf("authorized input read set changed: %w", sfcp.ErrAdmission)
	}
	observedAt := time.Now().Unix()
	for _, proof := range proofs {
		if err := proof.Verify(job, latest.Inputs.ReadSet, proof.Consumer, time.Now().Unix()); err != nil {
			return [32]byte{}, 0, err
		}
		if proof.At < observedAt {
			observedAt = proof.At
		}
	}
	return latest.Inputs.ReadSet, observedAt, nil
}
