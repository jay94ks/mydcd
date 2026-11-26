// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"math"
	"strings"

	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/secrets"
)

// Size-only envelopes reserve room for future terminal evidence. They are
// never signed, returned, persisted or accepted as execution/closure facts.
// Admitting a job that cannot later store its cleanup proof would strand pins.
func imageBuildRecordBudget(row ImageBuildJobRecord) bool {
	if row.Run.Terminal() {
		raw, err := json.Marshal(row)
		return err == nil && len(raw) <= 64<<10
	}
	spec := row.Run.Spec
	inputs := 0
	if row.Run.Phase == "queued" && !row.Run.Cancel {
		inputs = (16 << 10) + 32 // complete JSON plus field name/comma, once
	}
	maxHash := [32]byte{}
	for i := range maxHash {
		maxHash[i] = 255
	}
	closure := imagebuild.JobClosure{Schema: 1, Job: spec.Digest(), Native: maxHash, At: math.MaxInt64, Signature: make([]byte, ed25519.SignatureSize), Result: imagebuild.JobResult{Code: "OK", Image: spec.OutputRepository() + "@sha256:" + strings.Repeat("f", 64), Bytes: imagebuild.MaxExpandedBytes}}
	report := ImageBuildJobReport{Schema: 1, Kind: "job", Cluster: spec.Cluster, Owner: spec.Scope.Root.Key, Tenant: spec.Tenant, Job: spec.ID, Action: "complete", Expected: math.MaxUint64, RootRevision: math.MaxUint64, Epoch: math.MaxUint64, At: math.MaxInt64, Closure: &closure, Signature: make([]byte, ed25519.SignatureSize)}
	for _, grant := range row.Grants {
		u := grant.Use
		report.Secrets = append(report.Secrets, secrets.UseGone{Purpose: u.Purpose, Cluster: spec.Cluster, Realm: grant.Realm, Tenant: u.Tenant, App: u.App, Deployment: u.Deployment, Consumer: grant.Consumer, Generation: grant.Generation, NodeKey: spec.Scope.Root.Key, Selection: grant.Selection, Lifetime: grant.Lifetime, Stopped: true, MountsGone: true, Signature: make([]byte, ed25519.SignatureSize)})
	}
	if row.Begin == nil && inputs > 0 {
		begin := report
		begin.Action, begin.Closure, begin.Secrets = "begin", nil, nil
		row.Begin = &begin
	}
	row.Run.Phase, row.Run.Revision, row.Run.Closure = "failed", math.MaxUint64, &closure
	row.OwnerSteps, row.Progress = 3, &report
	raw, err := json.Marshal(row)
	return err == nil && len(raw)+inputs <= 64<<10
}
