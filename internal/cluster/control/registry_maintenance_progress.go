// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registryclient"
)

type RegistryMaintenanceReport struct {
	Schema                            uint8
	Cluster, Owner                    [32]byte
	Operation, Action                 string
	Expected, RootRevision, Epoch, At uint64
	Result                            *RegistryMaintenanceResult `json:",omitempty"`
	Signature                         []byte
}

func RegistryMaintenanceReportBytes(r RegistryMaintenanceReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-registry-maintenance-report-1\x00"), raw...)
}
func (r RegistryMaintenanceReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Owner[:]), Epoch: r.Epoch, Key: RegistryMaintenanceKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func (p Policy) registryMaintenanceReport(s state.State, cmd state.Command) (RegistryMaintenanceReport, error) {
	var r RegistryMaintenanceReport
	if cmd.Kind != state.ModuleReport || cmd.Key != RegistryMaintenanceKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || r.Expected == 0 || r.At == 0 || r.At > math.MaxInt64 || !ed25519.Verify(r.Owner[:], RegistryMaintenanceReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	if err != nil || want != cmd {
		return r, ErrCatalog
	}
	jobs, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return r, err
	}
	row, ok := jobs.Record(r.Operation)
	if !ok || row.Change.OwnerKey() != r.Owner || p.currentImageCacheOwner(s, row.Change.NodeID(), r.Owner) != nil {
		return r, access.ErrDenied
	}
	if r.Action == "begin" || r.Action == "uncertain" {
		if r.Result != nil {
			return r, ErrCatalog
		}
	} else if r.Action == "complete" {
		if r.Result == nil || !RegistryMaintenanceResultFor(row.Change, *r.Result) || row.State == "unknown" && r.Result.Native == ([32]byte{}) {
			return r, ErrCatalog
		}
	} else {
		return r, ErrCatalog
	}
	return r, nil
}
func (p Policy) ResolveRegistryMaintenanceReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r RegistryMaintenanceReport
	if canonical(raw, &r) != nil || r.Owner != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := r.Command()
	if err != nil {
		return cmd, err
	}
	_, err = p.registryMaintenanceReport(s, cmd)
	return cmd, err
}
func (p Policy) reduceRegistryMaintenanceReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	report, err := p.registryMaintenanceReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	jobs, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return nil, state.Invalid
	}
	for i, row := range jobs.Records {
		if row.Change.Operation != report.Operation {
			continue
		}
		if row.Revision != report.Expected || row.Revision == ^uint64(0) {
			return nil, state.ConditionFailed
		}
		if report.Action == "begin" {
			if row.State != "queued" {
				return nil, state.ConditionFailed
			}
			row.State = "running"
		} else if report.Action == "uncertain" {
			if row.State != "running" || row.Change.External == nil {
				return nil, state.ConditionFailed
			}
			row.State = "unknown"
		} else {
			if row.State != "running" && row.State != "unknown" {
				return nil, state.ConditionFailed
			}
			row.Result = report.Result
			row.State = "failed"
			if report.Result.Code == "OK" || report.Result.Code == "ALREADY_ABSENT" {
				row.State = "done"
			}
		}
		row.Revision++
		row.At = max(row.At, report.At)
		jobs.Records[i] = row
		return p.registryMaintenanceCheckpoint(s, jobs)
	}
	return nil, state.ConditionFailed
}

type RegistryMaintenanceWorkRequest struct {
	Operation string
	At        int64
	Images    []string `json:",omitempty"`
}
type RegistryMaintenanceWork struct {
	Schema                               uint8
	Cluster, Owner                       [32]byte
	Operation, Action, State             string
	Revision, RootRevision, Epoch, Index uint64
	Change                               RegistryMaintenanceChange
	Allowed, InUse                       bool
}

func (p Policy) RegistryMaintenanceWork(s state.State, caller [32]byte, q RegistryMaintenanceWorkRequest) (RegistryMaintenanceWork, error) {
	p, err := p.Current(s)
	if err != nil {
		return RegistryMaintenanceWork{}, err
	}
	if q.At <= 0 || len(q.Images) > 32 {
		return RegistryMaintenanceWork{}, access.ErrDenied
	}
	jobs, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return RegistryMaintenanceWork{}, err
	}
	row, ok := jobs.Record(q.Operation)
	if !ok || row.Change.OwnerKey() != caller || p.currentImageCacheOwner(s, row.Change.NodeID(), caller) != nil {
		return RegistryMaintenanceWork{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return RegistryMaintenanceWork{}, err
	}
	images := q.Images
	if row.Origin.Change.Action == "delete-registry-image" {
		images = maintenanceDeleteRefs(row.Change)
	}
	for _, image := range q.Images {
		if _, _, _, err := registryclient.Normalize(image); err != nil {
			return RegistryMaintenanceWork{}, access.ErrInvalid
		}
	}
	used, err := p.maintenanceImagesInUse(s, row.Change.Tenant, images)
	if err != nil {
		return RegistryMaintenanceWork{}, err
	}
	scopeAllowed := true
	if row.Change.Prune != nil {
		for _, image := range q.Images {
			_, authority, repo, err := registryclient.Normalize(image)
			if err != nil || authority != row.Change.Authority() || !row.Change.PruneRepository(repo) && !(row.Change.External == nil && row.Change.Prune.Conditions.GC) {
				scopeAllowed = false
			}
			if row.Change.External != nil {
				selected, cause := p.ExternalRegistryForImage(s, row.Change.Tenant, access.Image{Registry: authority, Repository: repo})
				if cause != nil || selected == nil || selected.ID != row.Change.RegistryID() {
					scopeAllowed = false
				}
			}
		}
	}
	if row.Change.Prune != nil && row.Change.Prune.Conditions.GC && c.OperationAllowed(row.Origin.Session, "gc-registry") != nil {
		scopeAllowed = false
	}
	allowed := scopeAllowed && row.State != "unknown" && p.registryMaintenanceAuth(c, row.Origin.Session, row.Origin.At, row.Origin.Change.Action, row.Change.Tenant, row.Change.NodeID(), true) == nil && p.maintenanceCurrentRun(s, row.Change, q.At) == nil
	return RegistryMaintenanceWork{Schema: 1, Cluster: p.Cluster, Owner: caller, Operation: q.Operation, Action: row.Origin.Change.Action, State: row.State, Revision: row.Revision, RootRevision: s.Object(RegistryMaintenanceKey).Revision, Epoch: s.ModuleEpoch(), Index: s.Index(), Change: row.Change, Allowed: allowed, InUse: used}, nil
}

type RegistryMaintenanceStatus struct {
	Schema                                 uint8
	Tenant, Operation, Action, User, State string
	Revision, RootRevision, At             uint64
	Change                                 RegistryMaintenanceChange
	Result                                 *RegistryMaintenanceResult `json:",omitempty"`
}

func (p Policy) RegistryMaintenanceStatus(s state.State, session access.Session, at int64, tenant, operation string) (RegistryMaintenanceStatus, error) {
	p, err := p.Current(s)
	if err != nil {
		return RegistryMaintenanceStatus{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return RegistryMaintenanceStatus{}, err
	}
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, "") != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, "") != nil {
		return RegistryMaintenanceStatus{}, access.ErrDenied
	}
	jobs, err := p.RegistryMaintenanceJobs(s)
	if err != nil {
		return RegistryMaintenanceStatus{}, err
	}
	row, ok := jobs.Record(operation)
	if !ok || row.Change.Tenant != tenant {
		return RegistryMaintenanceStatus{}, access.ErrDenied
	}
	return RegistryMaintenanceStatus{Schema: 1, Tenant: tenant, Operation: operation, Action: row.Origin.Change.Action, User: row.Origin.Session.User, State: row.State, Revision: row.Revision, RootRevision: s.Object(RegistryMaintenanceKey).Revision, At: row.At, Change: row.Change, Result: row.Result}, nil
}
