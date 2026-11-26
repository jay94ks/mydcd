// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log"
	"math"
	"time"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/imagesource"
	"github.com/jay94ks/mydcd/internal/observability"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/storage"
)

func (r *Runtime) registryPullAuth(auth engine.RegistryAuth, source imagesource.Source) engine.RegistryAuth {
	return auth.WithPullObserver(func(outcome registryclient.PullOutcome) {
		// Do not use the caller's expired I/O context to discard a completed result.
		// Close waits for managed work before closing this existing report DB.
		ctx, cancel := context.WithTimeout(r.ctx, 2*time.Second)
		defer cancel()
		if err := r.recordRegistryPull(ctx, source, outcome); err != nil {
			log.Print("registry pull observation unavailable") // code-only; no remote error
		}
	})
}

func (r *Runtime) recordRegistryPull(ctx context.Context, source imagesource.Source, outcome registryclient.PullOutcome) error {
	if !outcome.Valid() || r.reports == nil || source.Validate() != nil {
		return observability.ErrReport
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	directory, err := r.controlPolicy.Members(v.State)
	if err != nil || !directory.MemberKey(r.Identity.Public) {
		return observability.ErrReport
	}
	now := uint64(time.Now().UnixMilli())
	report := observability.Report{Kind: "node-observation", Schema: 1, Cluster: r.controlPolicy.Cluster, Node: r.Engine().ObservedNodeID(), Key: r.Identity.Public, Index: v.State.Index(), At: now,
		RegistryPull: &observability.RegistryPull{Tenant: source.Tenant, Authority: source.Authority, Source: source.ID, Stage: outcome.Stage, Code: outcome.Code, CompletedAt: now, Sequence: 1}}
	key := "node-observation/" + report.Node + "/" + report.Source()
	r.reportMu.Lock()
	defer r.reportMu.Unlock()
	old, err := r.reports.GetBounded(key, observability.MaxReportBytes)
	if err == nil {
		previous, err := observability.Decode(old)
		if err != nil || previous.RegistryPull == nil || previous.Key == report.Key && previous.RegistryPull.Sequence == math.MaxUint64 {
			return observability.ErrReport
		}
		if previous.Key == report.Key {
			report.RegistryPull.Sequence = previous.RegistryPull.Sequence + 1
		}
		// A backwards wall clock is not a later completion witness.
		if previous.Key == report.Key && previous.RegistryPull.CompletedAt > now {
			return observability.ErrReport
		}
	} else if !errors.Is(err, storage.ErrMissing) {
		return err
	}
	report.Signature = ed25519.Sign(r.Identity.Private, observability.SigningBytes(report))
	if !report.Valid() {
		return observability.ErrReport
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return r.storeValidatedNodeObservation(report, raw)
}
