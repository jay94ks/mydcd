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
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
)

var errDeliverySourceCAS = errors.New("delivery source checkpoint changed")

// A failed fresh read is not a policy revocation. Preserve the original fetch
// ticket and its partial upload until a later existing poll obtains authority.
// This cannot authorize fetch/parts or retry an app/native mutation.
func deliveryReadAuthorityUncertain(err error) bool {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, raft.ErrNotLeader, raft.ErrLeadershipLost, raft.ErrRaftShutdown, raft.ErrEnqueueTimeout, cluster.ErrRecovering, errNoAppLeader, errAppLeaderPeerUnavailable} {
		if errors.Is(err, cause) {
			return true
		}
	}
	var remote *cluster.ManagementError
	if errors.As(err, &remote) && remote != nil {
		switch remote.Code {
		case "not-leader", "unavailable", "unknown", "transport":
			return true
		}
	}
	return false
}

func handleDeliveryReadAuthorityFailure(err error, reject func() error) error {
	if err == nil || reject == nil {
		return deployment.ErrSource
	}
	if deliveryReadAuthorityUncertain(err) {
		return err
	}
	return errors.Join(err, reject())
}

func (r *Runtime) deliveryPermit(ctx context.Context, tenant, app string, ticket *deployment.DeliveryFetch) (control.AppDeliveryPermit, error) {
	raw, _ := json.Marshal(control.AppDeliveryRequest{Tenant: tenant, App: app, Ticket: ticket, TargetCAS: true})
	reply, err := r.appCall(ctx, "app-delivery-permit", raw)
	if err != nil {
		return control.AppDeliveryPermit{}, err
	}
	permit, err := schema.Decode[control.AppDeliveryPermit](reply.Data)
	if err != nil || permit.Schema != 1 || permit.Cluster != r.controlPolicy.Cluster || permit.Reader != r.Identity.Public || permit.Scope.Tenant != tenant || permit.Scope.App != app || permit.Revision == 0 || permit.Epoch == 0 || permit.Target == nil || *permit.Target == ([32]byte{}) || ticket != nil && (permit.Ticket == nil || *permit.Ticket != *ticket) {
		return control.AppDeliveryPermit{}, deployment.ErrSource
	}
	return permit, nil
}
func (r *Runtime) deliveryProgress(ctx context.Context, permit control.AppDeliveryPermit, progress control.AppDeliveryProgress) error {
	progress.Schema, progress.Kind, progress.Cluster, progress.Reporter = 1, "app-delivery", r.controlPolicy.Cluster, r.Identity.Public
	progress.Tenant, progress.App, progress.Expected = permit.Scope.Tenant, permit.Scope.App, permit.Revision
	progress.TargetCAS = true
	progress.Target = permit.Target
	progress.RootRevision, progress.Epoch, progress.At = permit.RootRevision, permit.Epoch, uint64(time.Now().Unix())
	progress.Signature = ed25519.Sign(r.commandIdentity().Private, control.AppDeliveryProgressBytes(progress))
	raw, _ := json.Marshal(progress)
	reply, err := r.appCall(ctx, "app-delivery-progress", raw)
	if err != nil {
		log.Printf("delivery source report failed: tenant=%s app=%s action=%s cause=%s", permit.Scope.Tenant, permit.Scope.App, progress.Action, checkerAuthorityErrorCode(err))
		return err
	}
	if reply.Committed != nil && reply.Committed.Result.Code == state.ConditionFailed && reply.Committed.Result.Revision != permit.RootRevision {
		// Positive rejection before the reducer: re-read the same ticket and
		// upload progress. This is not an unknown app/native resubmission.
		log.Printf("delivery source report CAS rejected: tenant=%s app=%s action=%s expected_root=%d observed_root=%d", permit.Scope.Tenant, permit.Scope.App, progress.Action, permit.RootRevision, reply.Committed.Result.Revision)
		return errDeliverySourceCAS
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		code := state.Invalid
		if reply.Committed != nil {
			code = reply.Committed.Result.Code
		}
		log.Printf("delivery source report not applied: tenant=%s app=%s action=%s code=%d", permit.Scope.Tenant, permit.Scope.App, progress.Action, code)
		return errors.New("delivery source progress not committed")
	}
	return nil
}

// sourceFailure closes only a read-only source ticket/upload. It cannot settle
// an app mutation/Unknown/native pin. Current source authority may be revoked;
// the exact old pending ticket remains mandatory for this metadata cleanup.
func (r *Runtime) deliverySourceFailure(ctx context.Context, tenant, app string, ticket deployment.DeliveryFetch, code string) error {
	v, err := r.currentView(ctx)
	if err != nil {
		return err
	}
	apps, err := r.controlPolicy.ReadApps(v.State)
	if err != nil {
		return err
	}
	d, exists := apps.Delivery(tenant, app)
	if !exists {
		return deployment.ErrSource
	}
	current, pending := d.FetchTicket()
	if !pending || current != ticket {
		return nil
	}
	permit := control.AppDeliveryPermit{Scope: d.Inventory().Scope(), Revision: d.Revision(), RootRevision: v.State.Object(control.AppsKey).Revision, Epoch: v.State.ModuleEpoch()}
	if target, ok := apps.DeliverySourceTarget(tenant, app); ok {
		permit.Target = &target
	}
	return r.deliveryProgress(ctx, permit, control.AppDeliveryProgress{Action: "source-error", Ticket: &ticket, Error: code})
}

func (r *Runtime) receiveDeliverySource(ctx context.Context, permit control.AppDeliveryPermit) error {
	r.deliverySourceActive.Add(1)
	defer r.deliverySourceActive.Add(-1)
	if permit.Ticket == nil {
		return deployment.ErrSource
	}
	ticket := *permit.Ticket
	// Mark local work before refreshing admission. A stale permit obtained
	// before isolation must not start fetch after a zero-activity observation.
	current, err := r.deliveryPermit(ctx, permit.Scope.Tenant, permit.Scope.App, &ticket)
	if err != nil {
		log.Printf("delivery source pre-fetch permit failed: tenant=%s app=%s cause=%s", permit.Scope.Tenant, permit.Scope.App, checkerAuthorityErrorCode(err))
		return err
	}
	permit = current
	pinned := ""
	if permit.Input != nil {
		pinned = permit.Input.Commit
	}
	input, err := r.fetchGitCommit(ctx, permit.Scope.Tenant, permit.Policy, ticket, pinned)
	if err != nil {
		log.Printf("delivery source fetch failed: tenant=%s app=%s cause=%s", permit.Scope.Tenant, permit.Scope.App, checkerAuthorityErrorCode(err))
		return errors.Join(err, r.deliverySourceFailure(ctx, permit.Scope.Tenant, permit.Scope.App, ticket, "fetch"))
	}
	commit, path, body := input.Content()
	defer clear(body)
	if path != permit.Policy.Source.Path {
		return deployment.ErrSource
	}
	digest := sha256.Sum256(body)
	for {
		current, err := r.deliveryPermit(ctx, permit.Scope.Tenant, permit.Scope.App, &ticket)
		if err != nil {
			log.Printf("delivery source upload permit failed: tenant=%s app=%s cause=%s", permit.Scope.Tenant, permit.Scope.App, checkerAuthorityErrorCode(err))
			return err
		}
		if current.Input == nil {
			identity, _ := json.Marshal(struct {
				Scope  deployment.AppScope
				Ticket deployment.DeliveryFetch
				Commit string
				Digest [32]byte
			}{current.Scope, ticket, commit, digest})
			hash := sha256.Sum256(identity)
			id := "cd-" + hex.EncodeToString(hash[:20])
			source := control.AppDeliveryInput{Ticket: ticket, Upload: id, Commit: commit}
			begin := control.AppUploadBegin{Tenant: current.Scope.Tenant, App: current.Scope.App, Deployment: current.Scope.Deployment, ID: id, Length: len(body), Digest: digest}
			if err = r.deliveryProgress(ctx, current, control.AppDeliveryProgress{Action: "input", Ticket: &ticket, Input: &source, Begin: &begin}); err != nil {
				if errors.Is(err, errDeliverySourceCAS) {
					continue
				}
				return err
			}
			continue
		}
		progress := current.Upload
		if current.Input.Ticket != ticket || current.Input.Commit != commit || progress == nil || progress.ID != current.Input.Upload || progress.Length != len(body) || progress.Digest != digest {
			// Another valid reader may have won the original ticket first.
			// Never overwrite its pinned commit or reinterpret its partial bytes.
			return deployment.ErrSource
		}
		if len(progress.Missing) == 0 {
			err = r.deliveryProgress(ctx, current, control.AppDeliveryProgress{Action: "received", Ticket: &ticket})
			if errors.Is(err, errDeliverySourceCAS) {
				continue
			}
			return err
		}
		index := progress.Missing[0]
		at := index * deployment.ArtifactPartBytes
		if at < 0 || at >= len(body) {
			return deployment.ErrSource
		}
		part := control.AppUploadPart{Tenant: current.Scope.Tenant, ID: progress.ID, Index: index, Data: body[at:min(at+deployment.ArtifactPartBytes, len(body))]}
		if err = r.deliveryProgress(ctx, current, control.AppDeliveryProgress{Action: "part", Ticket: &ticket, Part: &part}); err != nil {
			if errors.Is(err, errDeliverySourceCAS) {
				continue
			}
			return err
		}
	}
}

// This loop handles source reads only. Accepted app steps/retirement stay on
// the existing app owner loops; no second deployment executor lives here.
func (r *Runtime) deliverySourceLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	next := map[string]time.Time{}
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		}
		if !r.Engine().IsLeader() {
			continue
		}
		ctx, cancel := context.WithTimeout(r.ctx, 5*time.Minute)
		// Scheduling may use a local committed view; the actual source permit
		// and every progress publication still require a fresh quorum read.
		v, err := r.Engine().Read(ctx, false)
		if err != nil {
			cancel()
			continue
		}
		apps, err := r.controlPolicy.ReadApps(v.State)
		if err != nil {
			cancel()
			continue
		}
		records := apps.Records()
		live := make(map[string]bool, len(records))
		for _, app := range records {
			live[app.Tenant+"/"+app.App] = true
		}
		for key := range next {
			if !live[key] {
				delete(next, key)
			}
		}
		for _, app := range records {
			key := app.Tenant + "/" + app.App
			if time.Now().Before(next[key]) {
				continue
			}
			d, exists := apps.Delivery(app.Tenant, app.App)
			if !exists {
				continue
			}
			policy := d.Policy()
			next[key] = time.Now().Add(time.Duration(policy.Poll) * time.Second)
			permit, err := r.deliveryPermit(ctx, app.Tenant, app.App, nil)
			if err != nil {
				log.Printf("delivery source authority failed: tenant=%s app=%s uncertain=%t cause=%s", app.Tenant, app.App, deliveryReadAuthorityUncertain(err), checkerAuthorityErrorCode(err))
				_ = handleDeliveryReadAuthorityFailure(err, func() error {
					if ticket, pending := d.FetchTicket(); pending {
						return r.deliverySourceFailure(ctx, app.Tenant, app.App, ticket, "policy")
					}
					return nil
				})
				continue
			}
			if permit.Ticket == nil {
				if err = r.deliveryProgress(ctx, permit, control.AppDeliveryProgress{Action: "fetch"}); err != nil {
					continue
				}
				permit, err = r.deliveryPermit(ctx, app.Tenant, app.App, nil)
				if err != nil {
					continue
				}
			}
			if err := r.receiveDeliverySource(ctx, permit); err != nil {
				log.Printf("delivery source receive failed: tenant=%s app=%s cause=%s", app.Tenant, app.App, checkerAuthorityErrorCode(err))
			}
			if ctx.Err() != nil {
				break
			}
		}
		cancel()
	}
}
