// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
)

type tunnelReceipt struct {
	Schema                 uint8
	Cluster, Owner, Target [32]byte
	Operation              string
	Sent                   bool
	Result                 *control.TunnelResult `json:",omitempty"`
}

var errTunnelProgress = errors.New("original reconnect progress view changed")

func tunnelReceiptKey(operation string) string {
	hash := sha256.Sum256([]byte(operation))
	return "maintenance/tunnel/" + hex.EncodeToString(hash[:])
}
func (r *Runtime) saveTunnelReceipt(receipt tunnelReceipt) error {
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > 8<<10 {
		return sfcp.ErrAdmission
	}
	return r.reports.Write(map[string][]byte{tunnelReceiptKey(receipt.Operation): raw})
}
func (r *Runtime) loadTunnelReceipt(work control.TunnelWork) (tunnelReceipt, error) {
	receipt := tunnelReceipt{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Target: work.Plan.Target, Operation: work.Operation}
	raw, err := r.reports.GetBounded(tunnelReceiptKey(work.Operation), 8<<10)
	if errors.Is(err, storage.ErrMissing) {
		return receipt, nil
	}
	if err != nil {
		return receipt, err
	}
	stored, err := schema.Decode[tunnelReceipt](raw)
	if err != nil || stored.Schema != 1 || stored.Cluster != receipt.Cluster || stored.Owner != receipt.Owner || stored.Target != receipt.Target || stored.Operation != receipt.Operation || stored.Result != nil && (!stored.Sent || !stored.Result.Valid(work.Plan)) {
		return receipt, sfcp.ErrAdmission
	}
	return stored, nil
}
func (r *Runtime) tunnelWork(ctx context.Context, operation string) (control.TunnelWork, error) {
	raw, _ := json.Marshal(control.TunnelWorkRequest{Operation: operation})
	reply, err := r.appCall(ctx, "tunnel-reconnect-work", raw)
	if err != nil {
		return control.TunnelWork{}, err
	}
	work, err := schema.Decode[control.TunnelWork](reply.Data)
	if err != nil || work.Schema != 1 || work.Cluster != r.controlPolicy.Cluster || work.Owner != r.Identity.Public || work.Operation != operation || !work.Plan.Valid() || work.Plan.Owner != work.Owner || work.Plan.Cluster != work.Cluster || work.Index == 0 || reply.Local || reply.RaftIndex == 0 || reply.CommandIndex < work.Index {
		return work, sfcp.ErrAdmission
	}
	return work, nil
}
func (r *Runtime) tunnelReport(ctx context.Context, work control.TunnelWork, action string, result *control.TunnelResult) error {
	report := control.TunnelReport{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Operation: work.Operation, Action: action, Expected: work.Expected, RootRevision: work.RootRevision, Epoch: work.Epoch, At: uint64(time.Now().Unix()), Result: result}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.TunnelReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "tunnel-reconnect-report", raw)
	if err == nil && (reply.Committed == nil || reply.Committed.Result.Code != state.Applied) {
		return errTunnelProgress
	}
	return err
}
func tunnelError(err error) string {
	s := strings.ToValidUTF8(err.Error(), "?")
	if len(s) > 512 {
		s = s[:512]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
func (r *Runtime) runTunnelReconnect(operation string) {
	ctx := r.ctx
	work, err := r.tunnelWork(ctx, operation)
	if err != nil {
		return
	}
	if work.State == "queued" {
		action := "begin"
		var result *control.TunnelResult
		if !work.Allowed {
			action = "cancel"
			result = &control.TunnelResult{State: "failed", Code: "authority-revoked", PairID: work.Plan.PairID}
		}
		if r.tunnelReport(ctx, work, action, result) != nil || action == "cancel" {
			return
		}
	}
	work, err = r.tunnelWork(ctx, operation)
	if err != nil || work.State != "running" {
		return
	}
	if _, err = r.Engine().ReadAtLeast(ctx, work.Index); err != nil {
		return
	}
	receipt, err := r.loadTunnelReceipt(work)
	if err != nil {
		log.Printf("tunnel reconnect receipt unavailable: operation=%s cause=%v", operation, err)
		return
	}
	peer, known := r.Mesh.Peer(sfcp.Identity(work.Plan.PeerKey))
	if receipt.Result == nil && receipt.Sent && known {
		if link, ok := r.Mesh.LinkObservation(work.Plan.Node, peer); ok && link.State != "down" && link.LastHandshakeAt >= work.Plan.Observation.Link.LastHandshakeAt {
			receipt.Result = &control.TunnelResult{State: "already-connected", PairID: work.Plan.PairID, HandshakeAt: link.LastHandshakeAt, KeptExisting: true}
		}
	}
	if receipt.Result == nil {
		// Once sent, missing positive evidence plus revoked authority stays
		// unknown. A new Dial never borrows an expired/currently denied grant.
		if !work.Allowed {
			if receipt.Sent {
				return
			}
			receipt.Sent = true
			receipt.Result = &control.TunnelResult{State: "failed", Code: "authority-revoked", PairID: work.Plan.PairID}
		} else {
			work, err = r.tunnelWork(ctx, operation)
			if err != nil || !work.Allowed || work.State != "running" {
				return
			}
			receipt.Sent = true
			if err = r.saveTunnelReceipt(receipt); err != nil {
				return
			}
			if !known || peer.ID != work.Plan.Peer || peer.Endpoint != work.Plan.Endpoint {
				receipt.Result = &control.TunnelResult{State: "failed", Code: "peer-changed", PairID: work.Plan.PairID}
			} else {
				call, cancel := context.WithTimeout(ctx, 15*time.Second)
				result, callErr := r.Mesh.ReconnectBrokenMember(call, work.Plan.Node, peer)
				cancel()
				if callErr != nil {
					if ctx.Err() != nil {
						return
					} // keep original sent record for recovery
					receipt.Result = &control.TunnelResult{State: "failed", Code: "dial-failed", Error: tunnelError(callErr), PairID: work.Plan.PairID}
				} else {
					receipt.Result = &control.TunnelResult{State: result.State, PairID: result.PairID, HandshakeAt: result.HandshakeAt, KeptExisting: result.KeptExisting}
				}
			}
		}
	}
	if receipt.Result == nil || !receipt.Result.Valid(work.Plan) {
		return
	}
	if err = r.saveTunnelReceipt(receipt); err != nil {
		return
	}
	if ctx.Err() != nil {
		return
	}
	work, err = r.tunnelWork(ctx, operation)
	if err != nil || work.State != "running" {
		return
	}
	_ = r.tunnelReport(ctx, work, "finish", receipt.Result)
}
func (r *Runtime) advanceTunnelReconnects(ctx context.Context) {
	if r.reports == nil || ctx.Err() != nil {
		return
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return
	}
	jobs, err := r.controlPolicy.TunnelReconnections(v.State)
	if err != nil {
		return
	}
	for _, row := range jobs.Records {
		if row.Plan.Owner != r.Identity.Public || row.State != "queued" && row.State != "running" {
			continue
		}
		r.startJob(&r.tunnelJob, row.Operation, r.runTunnelReconnect)
		return
	}
}
