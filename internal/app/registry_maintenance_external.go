// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) runExternalRegistryMaintenance(ctx context.Context, work control.RegistryMaintenanceWork, local registryMaintenanceReceipt) {
	if work.Change.External == nil || work.Action != "delete-registry-image" {
		return
	}
	if local.Result != nil {
		r.finishRegistryMaintenance(ctx, work, local)
		return
	}
	if local.Sent {
		// The remote OCI API has no Seafield Cluster operation receipt. A later 404 cannot
		// distinguish the original effect from another writer's delete/re-push.
		// Preserve the original pending target/fence and never issue DELETE again.
		// The source reader may independently close after its real local I/O join;
		// its signed closure retains the original evidence without a new fetch.
		_ = r.registryMaintenanceReport(ctx, work, "uncertain", nil)
		return
	}
	noEffect := func(code string) {
		local.Result = &control.RegistryMaintenanceResult{Code: code, At: uint64(time.Now().UnixMilli())}
		r.finishRegistryMaintenance(ctx, work, local)
	}
	if !work.Allowed {
		noEffect("DENIED")
		return
	}
	if work.InUse {
		noEffect("IMAGE_IN_USE")
		return
	}
	if !strings.HasPrefix(work.Change.Reference, "sha256:") {
		noEffect("UNSUPPORTED") // no portable atomic tag/digest CAS in OCI DELETE
		return
	}
	target := work.Change.External
	source, err := r.externalRegistryWork(ctx, target.Selection)
	if err != nil || source.Inputs.ReadSet != target.ReadSet {
		return
	}
	release, err := r.acquireExternalReader(source)
	if err != nil {
		return
	}
	defer release()
	client, err := r.sourceRegistryClient(ctx, source)
	if err != nil {
		return
	}
	defer client.Close()
	beforeCode := ""
	outcome := client.DeleteManifest(ctx, work.Change.Authority()+"/"+work.Change.Repository+"@"+work.Change.Digest, func(call context.Context) error {
		fresh, err := r.registryMaintenanceWork(call, work.Operation, nil)
		if err != nil {
			return err
		}
		if fresh.State != "running" || fresh.Change.DigestValue() != local.Target {
			return sfcp.ErrAdmission
		}
		if !fresh.Allowed {
			beforeCode = "DENIED"
			return sfcp.ErrAdmission
		}
		if fresh.InUse {
			beforeCode = "IMAGE_IN_USE"
			return sfcp.ErrAdmission
		}
		// No external network mutation can precede this synchronous local fact.
		local.Sent = true
		return r.saveRegistryMaintenance(local)
	})
	if !outcome.Valid() {
		return
	}
	if outcome.Code == "UNKNOWN" {
		_ = r.registryMaintenanceReport(ctx, work, "uncertain", nil)
		return
	}
	if !outcome.Attempted {
		if beforeCode != "" {
			noEffect(beforeCode)
		} else {
			noEffect(outcome.Code)
		}
		return
	}
	// This fact comes from the original HTTP response, not a replay/HEAD or a
	// raw server body. Scope/operation/target are included in its public digest.
	result := nativeMaintenanceResult(outcome.Code, outcome.At, struct {
		Cluster, Owner, Target [32]byte
		Operation              string
		Outcome                registryclient.DeleteOutcome
	}{work.Cluster, work.Owner, local.Target, work.Operation, outcome}, 0)
	local.Result = &result
	r.finishRegistryMaintenance(ctx, work, local)
}
