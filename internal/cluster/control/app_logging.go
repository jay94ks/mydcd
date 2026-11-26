// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/workload"
)

// AppLogClearImpact exposes only public ownership/stop information. In
// particular it does not serialize Claim.Command, Secret input or grants.
type AppLogClearImpact struct {
	Key, Kind, Node, NativeID, StartedAt, LogDriver string
	Generation, Revision                            uint64
	Retained                                        bool
}

// AppLogClearPlan is a read-only impact plan. Neither producing nor accepting
// its bytes removes anything: execution still requires explicit recreation
// consent, a signed management operation and the existing retirement journal.
type AppLogClearPlan struct {
	Schema                          uint8
	Tenant, App                     string
	InventoryRevision               uint64
	Target                          [32]byte
	SourcePlan                      [32]byte
	SourceCandidate, SourceArtifact [32]byte
	Container                       containerops.Target
	LogDriver                       string
	Impact                          []AppLogClearImpact
}

type AppLogClearQuery struct {
	Selection containerops.Selection
	Operation string
}

func (q AppLogClearQuery) Valid(plan bool) bool {
	if plan {
		return q.Operation == "" && q.Selection.Valid()
	}
	return q.Selection.Service == "" && q.Selection.Instance == "" && (lifecycle.ValidID(q.Selection.App) && q.Selection.Standalone == "" || q.Selection.App == "" && lifecycle.ValidID(q.Selection.Standalone)) && lifecycle.ValidID(q.Operation)
}

// PlanAppLogClear uses the same selection and dependency closure as the owner
// paths. Fresh signed driver/native facts are mandatory; daemon defaults and
// old metadata are not inferred to be local log storage.
func (p Policy) PlanAppLogClear(s state.State, session access.Session, at int64, tenant string, selection containerops.Selection) (AppLogClearPlan, error) {
	var out AppLogClearPlan
	var err error
	p, err = p.Current(s)
	if err != nil {
		return out, err
	}
	target, err := p.containerSelectionTarget(s, session, at, tenant, selection)
	if err != nil {
		return out, err
	}
	catalog, err := p.Catalog(s)
	if err != nil || catalog.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Deploy, target.Node) != nil {
		return out, access.ErrDenied
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return out, err
	}
	entry, found := apps.entries[appKey(tenant, target.App)]
	if !found || (entry.Standalone != nil) != (selection.Standalone != "") || entry.Down != nil || entry.PendingSync != nil {
		return out, containerops.ErrTarget
	}
	claims, err := entry.Inventory.PreviewRetirement([]string{target.Instance}, false)
	if err != nil {
		return out, err
	}
	if current, active := entry.Inventory.Execution(); active {
		for _, step := range current.Steps() {
			if catalog.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, tenant, step.Action(), step.Node) != nil {
				return out, access.ErrDenied
			}
		}
	}
	members, err := p.Members(s)
	if err != nil {
		return out, err
	}
	execution, active := entry.Inventory.Execution()
	if !active {
		return out, containerops.ErrTarget
	}
	out = AppLogClearPlan{Schema: 1, Tenant: tenant, App: target.App, InventoryRevision: entry.Inventory.Revision(), Container: target, SourcePlan: execution.Blueprint().Digest()}
	out.SourceCandidate, out.SourceArtifact = out.SourcePlan, execution.Blueprint().AppInputDigest()
	if entry.Delivery != nil {
		selected, ok := entry.Delivery.Selection()
		if !ok {
			return AppLogClearPlan{}, containerops.ErrTarget
		}
		out.SourceCandidate, out.SourceArtifact = selected.Candidate, selected.Artifact
	}
	for _, claim := range claims {
		impact := AppLogClearImpact{Key: claim.Step.Key, Kind: claim.Step.Kind, Node: claim.Step.Node, Generation: claim.Result.Generation, Revision: claim.Result.Revision, Retained: claim.Step.Retain}
		if claim.Step.Kind == "task" {
			if !members.WorkKey(claim.Step.Owner) || catalog.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Deploy, claim.Step.Node) != nil {
				return AppLogClearPlan{}, access.ErrDenied
			}
			current := s.Object(claim.Step.Key)
			if !current.Present || current.Generation != claim.Result.Generation || current.Revision != claim.Result.Revision {
				return AppLogClearPlan{}, containerops.ErrTarget
			}
			fact := claim.Observation
			if fact == nil || fact.Native == "" || fact.StartedAt <= 0 || fact.Released || !fact.Live(uint64(at)) {
				return AppLogClearPlan{}, containerops.ErrTarget
			}
			impact.NativeID, impact.StartedAt, impact.LogDriver = fact.Native, time.Unix(0, fact.StartedAt).UTC().Format(time.RFC3339Nano), fact.LogDriver
			if claim.Step.Key == target.Instance {
				if fact.Native != target.NativeID || impact.StartedAt != target.StartedAt {
					return AppLogClearPlan{}, containerops.ErrTarget
				}
				out.LogDriver = fact.LogDriver
			}
		}
		out.Impact = append(out.Impact, impact)
	}
	if out.LogDriver == "" {
		return AppLogClearPlan{}, containerops.ErrTarget
	}
	if !containerops.LocalLogDriver(out.LogDriver) {
		return AppLogClearPlan{}, workload.ErrLogPolicy
	}
	// Health heartbeats may advance InventoryRevision without changing the
	// command's actual destruction target. Bind concrete native lifetimes and
	// the original app goal, omitting only this volatile planning ordinal.
	out.Target = logClearTarget(out, entry.downTarget())
	return out, nil
}

func logClearTarget(plan AppLogClearPlan, origin [32]byte) [32]byte {
	fingerprint := plan
	fingerprint.InventoryRevision, fingerprint.Target = 0, [32]byte{}
	input := struct {
		Plan   AppLogClearPlan
		Origin [32]byte
	}{fingerprint, origin}
	raw, _ := json.Marshal(input)
	return sha256.Sum256(append([]byte("mydc-app-log-clear-target-1\x00"), raw...))
}
