// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/observability"
)

type TaskSelection struct {
	Node, Tenant, App string
	Standalone        string `json:",omitempty"`
}

func (q TaskSelection) Valid() bool {
	for _, name := range []string{q.Node, q.Tenant, q.App, q.Standalone} {
		if name != "" && !lifecycle.ValidID(name) {
			return false
		}
	}
	return q.Standalone == "" || q.App == ""
}

type TaskResource struct {
	Kind     string
	Name     string
	Realm    string `json:",omitempty"`
	Borrowed bool
}

type TaskView struct {
	Kind, Standalone                       string `json:",omitempty"`
	Tenant, App, Deployment, Service, Node string
	TaskID                                 string
	Generation, Revision                   uint64
	Container, ContainerName, Image        string
	ImageID                                string `json:",omitempty"`
	Desired, Observed                      string
	StartedAt                              string                  `json:",omitempty"`
	RestartCount                           *uint64                 `json:",omitempty"`
	ExitCode                               *int64                  `json:",omitempty"`
	LastCheck                              *containerops.TaskCheck `json:",omitempty"`
	EndpointPresent                        *bool                   `json:",omitempty"`
	ObservedAt, ObservationMaxAge          uint64
	Resources                              []TaskResource
}

type TasksPage struct {
	Tasks        []TaskView
	Next         string
	RootRevision uint64
}

// Position refers only to a sorted, already-authorized projection. The digest
// binds the exact roots, selector and signed scope; hidden rows never affect it.
func taskCursorBasis(s state.State, session access.Session, q TaskSelection) [32]byte {
	raw, _ := json.Marshal(struct {
		State, Apps, Catalog, Members, Vault uint64
		User                                 string
		Scopes                               []access.Scope
		Query                                TaskSelection
	}{s.Index(), s.Object(AppsKey).Revision, s.Object(CatalogKey).Revision, s.Object(MembersKey).Revision, s.Object(VaultKey).Revision, session.User, session.Scopes, q})
	return sha256.Sum256(append([]byte("sfc-task-page-1\x00"), raw...))
}

func taskCursor(after string, basis [32]byte) (uint32, error) {
	if after == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(after)
	if err != nil || len(raw) != 37 || raw[0] != 1 || base64.RawURLEncoding.EncodeToString(raw) != after {
		return 0, access.ErrInvalid
	}
	if [32]byte(raw[1:33]) != basis {
		return 0, access.ErrConflict
	}
	return binary.LittleEndian.Uint32(raw[33:]), nil
}

func nextTaskCursor(basis [32]byte, offset uint32) string {
	raw := append([]byte{1}, basis[:]...)
	return base64.RawURLEncoding.EncodeToString(binary.LittleEndian.AppendUint32(raw, offset))
}

// TaskPage projects committed Tasks and their retained claims. It never acquires
// a provider pin, changes a Task, or treats missing/stale evidence as Running.
func (p Policy) TaskPage(s state.State, session access.Session, at int64, q TaskSelection, after string, reports ...[]observability.Report) (TasksPage, error) {
	deny := func(err error) (TasksPage, error) { return TasksPage{}, err }
	if !q.Valid() || at <= 0 {
		return deny(access.ErrInvalid)
	}
	var err error
	p, err = p.Current(s)
	if err != nil {
		return deny(access.ErrDenied)
	}
	c, err := p.Catalog(s)
	if err != nil {
		return deny(err)
	}
	issuer := p.Issuer(session.Issuer)
	if c.VerifySession(session, p.Cluster, issuer, at) != nil {
		return deny(access.ErrDenied)
	}
	hasRead := false
	for _, scope := range session.Scopes {
		hasRead = hasRead || slices.Contains(scope.Actions, access.Read)
	}
	if !hasRead {
		return deny(access.ErrDenied)
	}
	if q.Tenant != "" && c.AuthorizeSession(session, p.Cluster, issuer, at, q.Tenant, access.Read, "") != nil {
		return deny(access.ErrDenied)
	}
	a, err := p.readOnlyApps(s)
	if err != nil {
		return deny(err)
	}
	basis := taskCursorBasis(s, session, q)
	admin := c.SystemAllowed(session.User)
	allowed := map[string]bool{}
	checked := map[string]bool{}
	canRead := func(tenant, node string) bool {
		if admin {
			node = ""
		}
		key := tenant + "/" + node
		if !checked[key] {
			allowed[key] = c.AuthorizeSession(session, p.Cluster, issuer, at, tenant, access.Read, node) == nil
			checked[key] = true
		}
		return allowed[key]
	}
	measurements := map[string]observability.Report{}
	directory, err := p.Members(s)
	if err != nil {
		return deny(err)
	}
	for _, set := range reports {
		for _, report := range set {
			task := report.Task
			if task == nil || report.Cluster != p.Cluster || report.Index > s.Index() || q.Tenant != "" && q.Tenant != task.Tenant || q.Node != "" && q.Node != report.Node || q.App != "" && q.App != task.App || !canRead(task.Tenant, report.Node) {
				continue
			}
			entry, ok := directory.Entry(report.Node)
			if !ok || entry.CurrentPeer().Key != fmt.Sprintf("%x", report.Key) || !directory.MemberKey(report.Key) || !report.Valid() {
				continue
			}
			key := report.Node + "\x00" + task.Key
			if old, ok := measurements[key]; !ok || old.At < report.At {
				measurements[key] = report
			}
		}
	}
	var vault *Vault
	rows := []TaskView{}
	for _, entry := range a.entries {
		scope := entry.Inventory.Scope()
		if q.Standalone != "" && (entry.Standalone == nil || entry.Standalone.Name != q.Standalone) || q.App != "" && entry.Standalone != nil {
			continue
		}
		if q.Tenant != "" && q.Tenant != scope.Tenant || q.App != "" && q.App != scope.App || !canRead(scope.Tenant, "") {
			continue
		}
		claims := entry.Inventory.Claims()
		candidates, err := acceptedTaskCandidates(s, a, scope, claims)
		if err != nil {
			return deny(err)
		}
		for _, candidate := range candidates {
			goal := candidate.goal
			if q.Node != "" && q.Node != goal.Node || !canRead(scope.Tenant, goal.Node) {
				continue
			}
			var service deployment.ComposeService
			if canonical(goal.Config, &service) != nil {
				return deny(ErrCatalog)
			}
			instance, instanceErr := deployment.TaskInstanceForKey(scope.Tenant, scope.App, candidate.ref.Key, service)
			if instanceErr != nil {
				return deny(ErrCatalog)
			}
			name := instance.Service
			row := TaskView{Tenant: scope.Tenant, App: scope.App, Deployment: scope.Deployment, Service: name, Node: goal.Node, TaskID: candidate.ref.Key, Generation: candidate.ref.Generation, Revision: candidate.ref.Revision, Container: candidate.native, Image: service.Image, Desired: "running", Observed: "unknown", ObservationMaxAge: AppObservationMaxAge, Resources: []TaskResource{}}
			current := s.Object(candidate.ref.Key)
			var currentGoal deployment.GoalCommand
			if current.Present && canonical([]byte(current.Value), &currentGoal) != nil {
				return deny(ErrCatalog)
			}
			if entry.Standalone != nil && entry.Standalone.Desired == "stopped" || entry.Down != nil || !current.Present || current.Generation != candidate.ref.Generation || currentGoal.Lifecycle != nil && currentGoal.Lifecycle.Drain {
				row.Desired = "stopped"
			}
			fact := candidate.observation
			if fact != nil {
				row.ObservedAt = fact.At
				if fact.Native != "" {
					row.Container = fact.Native
				}
				if fact.TaskFact != nil && fact.TaskFact.Image != "" {
					row.ImageID = fact.TaskFact.Image
				}
				if fact.StartedAt > 0 {
					row.StartedAt = time.Unix(0, fact.StartedAt).UTC().Format(time.RFC3339Nano)
				}
				if fact.Exit != nil {
					exit := int64(fact.Exit.Code)
					row.ExitCode = &exit
				}
				if fact.Live(uint64(at)) {
					if fact.TaskFact != nil {
						row.ContainerName, row.Observed = fact.TaskFact.Name, fact.TaskFact.State
						copy := fact.TaskFact.Clone()
						if row.Observed != "unknown" {
							row.EndpointPresent = copy.EndpointPresent
						}
						n := fact.TaskFact.RestartCount
						row.RestartCount = &n
						if fact.TaskFact.LastCheck != nil {
							c := *fact.TaskFact.LastCheck
							row.LastCheck = &c
						}
					} else if fact.Gone {
						row.Observed = "missing"
					} else if fact.Exit != nil || fact.Stopped {
						row.Observed = "exited"
					}
					if row.Observed == "missing" {
						present := false
						row.EndpointPresent = &present
					}
				}
			}
			if report, ok := measurements[goal.Node+"\x00"+candidate.ref.Key]; ok {
				measured := report.Task
				if report.Key == goal.Owner && measured.Tenant == scope.Tenant && measured.App == scope.App && measured.Deployment == scope.Deployment && measured.Generation == candidate.ref.Generation && measured.Revision == candidate.ref.Revision && (row.Container == "" || row.Container == measured.Native) && report.At/1000 >= row.ObservedAt {
					row.ObservedAt = report.At / 1000
					row.Container, row.ContainerName, row.ImageID, row.StartedAt = measured.Native, measured.Fact.Name, measured.Fact.Image, measured.StartedAt
					row.Observed, row.RestartCount, row.LastCheck, row.ExitCode, row.EndpointPresent = "unknown", nil, nil, nil, nil
					if report.At <= uint64(at)*1000+999 && uint64(at)*1000+999-report.At <= AppObservationMaxAge*1000 {
						row.Observed = measured.Fact.State
						n := measured.Fact.RestartCount
						row.RestartCount = &n
						copy := measured.Fact.Clone()
						row.LastCheck = copy.LastCheck
						if row.Observed != "unknown" {
							row.EndpointPresent = copy.EndpointPresent
						}
						if row.Observed == "missing" {
							present := false
							row.EndpointPresent = &present
						}
						if measured.ExitCode != nil {
							n := *measured.ExitCode
							row.ExitCode = &n
						}
					}
				}
			}
			// Projection contains only logical public references, never Config,
			// environment, provider paths, credential or fetched Secret values.
			for alias := range service.Networks {
				ref, err := taskNetworkReference(s, goal, alias, claims)
				if err != nil {
					return deny(err)
				}
				row.Resources = append(row.Resources, ref)
			}
			if bound, found := a.Binding(candidate.ref); found {
				for _, source := range bound.Needs().ApprovalSources() {
					if vault == nil {
						v, err := p.Vault(s)
						if err != nil {
							return deny(err)
						}
						vault = &v
					}
					tree, found := vault.Trees[source.Realm]
					if !found {
						return deny(ErrCatalog)
					}
					object, found := tree.Object(source.Object)
					if !found {
						return deny(ErrCatalog)
					}
					kind := "secret"
					if string(object.Kind) == "group" {
						kind = "secret-group"
					}
					row.Resources = append(row.Resources, TaskResource{Kind: kind, Name: source.Object, Realm: source.Realm, Borrowed: true})
				}
				for _, pin := range bound.Pins() {
					row.Resources = append(row.Resources, TaskResource{Kind: "volume", Name: pin.Scope.ID, Borrowed: pin.Scope.TenantManaged()})
				}
			}
			slices.SortFunc(row.Resources, func(a, b TaskResource) int {
				if a.Kind != b.Kind {
					return strings.Compare(a.Kind, b.Kind)
				}
				if a.Realm != b.Realm {
					return strings.Compare(a.Realm, b.Realm)
				}
				return strings.Compare(a.Name, b.Name)
			})
			if entry.Standalone != nil {
				row.Kind = "standalone"
				row.Standalone = entry.Standalone.Name
				row.App = ""
			} else {
				row.Kind = "app"
			}
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b TaskView) int {
		if a.TaskID != b.TaskID {
			return strings.Compare(a.TaskID, b.TaskID)
		}
		if a.Generation < b.Generation {
			return -1
		}
		if a.Generation > b.Generation {
			return 1
		}
		if a.Revision < b.Revision {
			return -1
		}
		if a.Revision > b.Revision {
			return 1
		}
		return 0
	})
	if len(reports) > 0 {
		raw, _ := json.Marshal(rows)
		basis = sha256.Sum256(append(basis[:], raw...))
	}
	offset, err := taskCursor(after, basis)
	if err != nil {
		return deny(err)
	}
	if uint64(offset) > uint64(len(rows)) {
		return deny(access.ErrInvalid)
	}
	end := int(offset)
	used := 0
	for end < len(rows) && end-int(offset) < 16 {
		raw, _ := json.Marshal(rows[end])
		if used+len(raw) > 96<<10 {
			if end == int(offset) {
				return deny(access.ErrInvalid)
			}
			break
		}
		used += len(raw)
		end++
	}
	page := TasksPage{Tasks: rows[int(offset):end], RootRevision: s.Object(AppsKey).Revision}
	if end < len(rows) {
		page.Next = nextTaskCursor(basis, uint32(end))
	}
	return page, nil
}

// A committed Task can precede collection of its native Claim. Its exact
// binding source is enough to list the desired Task, but never a Ready fact.
type taskProjection struct {
	ref         deployment.ObjectRef
	goal        deployment.GoalCommand
	native      string
	observation *deployment.Observation
}

func acceptedTaskCandidates(s state.State, apps Apps, scope deployment.AppScope, claims []deployment.Claim) ([]taskProjection, error) {
	rows := []taskProjection{}
	seen := map[deployment.ObjectRef]bool{}
	add := func(ref deployment.ObjectRef, raw []byte, native string, observation *deployment.Observation) error {
		var goal deployment.GoalCommand
		if canonical(raw, &goal) != nil || goal.Schema != 1 || goal.Cluster != scope.Cluster || goal.Kind != "task" || goal.Tenant != scope.Tenant || goal.App != scope.App || goal.Deployment != scope.Deployment || !lifecycle.ValidID(goal.Node) {
			return ErrCatalog
		}
		if !seen[ref] {
			rows = append(rows, taskProjection{ref: ref, goal: goal, native: native, observation: observation})
			seen[ref] = true
		}
		return nil
	}
	for _, claim := range claims {
		if claim.Removed || claim.Step.Kind != "task" {
			continue
		}
		ref := deployment.ObjectRef{Key: claim.Step.Key, Generation: claim.Result.Generation, Revision: claim.Result.Revision}
		observation := claim.Observation
		if execution, exists := apps.Execution(scope.Tenant, scope.App); exists {
			if stage, found := execution.Stage(claim.Step.Key); found {
				observation = taskClaimObservation(claim, stage)
			}
		}
		if err := add(ref, []byte(claim.Command.Value), claim.Native, observation); err != nil {
			return nil, err
		}
	}
	prefix := "workload/task/" + scope.Tenant + "/" + scope.App + "/"
	for _, source := range apps.sources {
		if !strings.HasPrefix(source.Task.Key, prefix) || seen[source.Task] {
			continue
		}
		object := s.Object(source.Task.Key)
		if !object.Present || object.Generation != source.Task.Generation || object.Revision != source.Task.Revision {
			continue
		}
		if err := add(source.Task, []byte(object.Value), "", nil); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

// A Keep stage preserves the effect's original Claim, while its new signed
// observations belong to the active operation. Select those facts only for
// the same committed object/native; never replace the claim's provenance.
func taskClaimObservation(claim deployment.Claim, stage deployment.StageRecord) *deployment.Observation {
	o := stage.Observation
	if o == nil {
		return claim.Observation
	}
	if stage.Held() && stage.Previous.Result == claim.Result && stage.Previous.Command == claim.Command {
		return o
	}
	if stage.Noop && !claim.Removed && !claim.Retained && stage.Command != nil && stage.Result != nil && *stage.Result == claim.Result && stage.Command.Key == claim.Command.Key && stage.Command.Value == claim.Command.Value && !stage.Command.Delete && !claim.Command.Delete && claim.Native != "" && o.Native == claim.Native && o.Owner == claim.Step.Owner && o.Key == claim.Step.Key && o.Generation == claim.Result.Generation && o.Revision == claim.Result.Revision {
		return o
	}
	return claim.Observation
}

// Resolve public names from the Task's frozen dependency, including a retained
// generation. A later object at the same key must not rename an old reference.
func taskNetworkReference(s state.State, task deployment.GoalCommand, alias string, claims []deployment.Claim) (TaskResource, error) {
	bridge := deployment.ResourceKey("bridge", task.Tenant, task.App, alias+"/"+task.Node)
	network := deployment.ResourceKey("network-ref", task.Tenant, task.App, alias+"/"+task.Node)
	var selected deployment.ObjectRef
	for _, ref := range task.Dependencies {
		if ref.Key != bridge && ref.Key != network {
			continue
		}
		if selected.Key != "" {
			return TaskResource{}, ErrCatalog
		}
		selected = ref
	}
	if selected.Key == "" {
		return TaskResource{}, ErrCatalog
	}
	var config json.RawMessage
	for _, claim := range claims {
		if claim.Step.Key == selected.Key && claim.Result.Generation == selected.Generation && claim.Result.Revision == selected.Revision {
			config = claim.Step.Goal
			break
		}
	}
	if config == nil {
		object := s.Object(selected.Key)
		var goal deployment.GoalCommand
		if !object.Present || object.Generation != selected.Generation || object.Revision != selected.Revision || canonical([]byte(object.Value), &goal) != nil || goal.Tenant != task.Tenant || goal.App != task.App || goal.Node != task.Node || goal.Owner != task.Owner {
			return TaskResource{}, ErrCatalog
		}
		config = goal.Config
	}
	if selected.Key == network {
		var ref deployment.NetworkReference
		if json.Unmarshal(config, &ref) != nil {
			return TaskResource{}, ErrCatalog
		}
		name := ref.ManagedName
		if name == "" {
			name = ref.Network
		}
		return TaskResource{Kind: "network", Name: name, Borrowed: true}, nil
	}
	var ref struct{ Network string }
	if json.Unmarshal(config, &ref) != nil || ref.Network == "" {
		return TaskResource{}, ErrCatalog
	}
	return TaskResource{Kind: "network", Name: ref.Network}, nil
}
