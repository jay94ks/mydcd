// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/imagecache"
	"github.com/jay94ks/seafield/internal/workload"
)

// ImageReference is derived from the original shared owners. It is not native
// liveness evidence, a cached count, a new image lease or a rewritten grant.
type ImageReference struct {
	Unknown                                          bool `json:",omitempty"`
	ID                                               string
	Tenant, App, Deployment, Node, Service, Instance string
	Image, Kind, Task, Operation, Commit             string
	Version                                          uint64 `json:",omitempty"`
}

func imageReferenceID(row ImageReference) string {
	row.ID = ""
	raw, _ := json.Marshal(row)
	digest := sha256.Sum256(append([]byte("sfc-image-reference-1\x00"), raw...))
	return hex.EncodeToString(digest[:])
}

func (row ImageReference) Valid() bool {
	if row.ID != imageReferenceID(row) || row.Tenant != "" && !validID(row.Tenant) || len(row.Task) > 512 || len(row.Instance) > 192 {
		return false
	}
	for _, id := range []string{row.App, row.Deployment, row.Node, row.Service, row.Operation} {
		if id != "" && !validID(id) {
			return false
		}
	}
	if row.Commit != "" && (len(row.Commit) != 40 || !lowerHex(row.Commit)) {
		return false
	}
	if row.Unknown {
		return row.Kind == "app-previous-unknown" && row.Image == "" && row.App != "" && row.Version > 0
	}
	ref, err := imagecache.CanonicalReference(row.Image)
	if err != nil || ref != row.Image {
		return false
	}
	kind := strings.TrimPrefix(row.Kind, "lifecycle-compiler/")
	switch kind {
	case "image-build-cache-prune", "image-build-builder", "image-build-base", "image-build-output", "image-build-result", "task-shared", "legacy-task", "app-claim", "app-execution", "app-held", "app-retiring", "app-previous", "cd-candidate", "cd-running", "cd-last-success", "cd-last-failure", "cd-transition", "lifecycle-build":
		return true
	}
	return false
}

// ImageReferences is shared by public usage reads and actual deletion/cache
// protection. Empty tenant/node means all. Unmapped legacy rows stay private
// with Tenant=""; unknown retained placement protects every node's cache.
func (p Policy) ImageReferences(s state.State, tenant, node string) ([]ImageReference, error) {
	rows := map[string]ImageReference{}
	add := func(row ImageReference) error {
		if tenant != "" && row.Tenant != "" && row.Tenant != tenant || node != "" && row.Node != "" && row.Node != node {
			return nil
		}
		if row.Unknown {
			if row.Image != "" || row.Kind != "app-previous-unknown" {
				return ErrCatalog
			}
			row.ID = imageReferenceID(row)
			rows[row.ID] = row
			return nil
		}
		ref, err := imagecache.CanonicalReference(row.Image)
		if err != nil {
			return err
		}
		row.Image = ref
		row.ID = imageReferenceID(row)
		rows[row.ID] = row
		return nil
	}
	addService := func(base ImageReference, service deployment.ComposeService) error {
		base.Image = service.Image
		if err := add(base); err != nil {
			return err
		}
		if program := service.LifecycleProgram; program != nil {
			compiled := false
			for _, script := range program.Scripts {
				compiled = compiled || script.Compile
			}
			if compiled {
				for _, buildNode := range program.Policy.Build.Nodes {
					ref := base
					ref.Node = buildNode
					ref.Image = program.Policy.Build.Image
					ref.Kind = "lifecycle-compiler/" + base.Kind
					if err := add(ref); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	addStep := func(scope deployment.AppScope, step deployment.Step, kind, operation, commit string, version uint64) error {
		if step.Kind != "task" {
			return nil
		}
		var service deployment.ComposeService
		if json.Unmarshal(step.Goal, &service) != nil {
			return ErrCatalog
		}
		instance, err := deployment.TaskInstanceForKey(scope.Tenant, scope.App, step.Key, service)
		if err != nil {
			return err
		}
		return addService(ImageReference{Tenant: scope.Tenant, App: scope.App, Deployment: scope.Deployment, Node: step.Node, Service: instance.Service, Instance: instance.ResourceID(), Task: step.Key, Kind: kind, Operation: operation, Commit: commit, Version: version}, service)
	}
	for key, object := range s.Objects("workload/task/") {
		if !object.Present {
			continue
		}
		var goal deployment.GoalCommand
		if json.Unmarshal([]byte(object.Value), &goal) == nil && goal.Schema == 1 && goal.Kind == "task" {
			if tenant != "" && goal.Tenant != tenant {
				continue
			}
			scope := deployment.AppScope{Tenant: goal.Tenant, App: goal.App, Deployment: goal.Deployment}
			if err := addStep(scope, deployment.Step{Key: key, Kind: "task", Node: goal.Node, Owner: goal.Owner, Goal: goal.Config}, "task-shared", "", "", 0); err != nil {
				return nil, err
			}
		} else {
			spec, err := workload.DecodeContainer(object.Value)
			if err != nil {
				return nil, err
			}
			row := ImageReference{Node: spec.Node, Task: key, Kind: "legacy-task", Image: spec.Image}
			if err = add(row); err != nil {
				return nil, err
			}
		}
	}
	apps, err := p.Apps(s)
	if err != nil {
		return nil, err
	}
	for _, entry := range apps.entries {
		scope := entry.Inventory.Scope()
		if tenant != "" && scope.Tenant != tenant {
			continue
		}
		for _, claim := range entry.Inventory.Claims() {
			if !claim.Removed {
				if err = addStep(scope, claim.Step, "app-claim", claim.Operation, "", 0); err != nil {
					return nil, err
				}
			}
		}
		if execution, ok := entry.Inventory.Execution(); ok && execution.Status() != "Closed" {
			for _, step := range execution.Steps() {
				if err = addStep(scope, step, "app-execution", execution.ActiveOperation(), "", entry.LastVersion); err != nil {
					return nil, err
				}
				if stage, ok := execution.Stage(step.Key); ok && stage.Held() {
					old := stage.Previous
					if err = addStep(scope, old.Step, "app-held", old.Operation, "", 0); err != nil {
						return nil, err
					}
				}
			}
		}
		if retirement, ok := entry.Inventory.Retirement(); ok {
			for _, target := range retirement.Targets {
				if !target.Closed {
					old := target.Original
					if err = addStep(scope, old.Step, "app-retiring", old.Operation, "", 0); err != nil {
						return nil, err
					}
				}
			}
		}
		if entry.Delivery != nil {
			for _, selected := range entry.Delivery.ImagePlans() {
				for _, step := range selected.Plan.Steps() {
					if err = addStep(scope, step, selected.Kind, selected.Operation, selected.Commit, 0); err != nil {
						return nil, err
					}
				}
			}
		}
		// The one immediately preceding accepted version is a declared rollback
		// reference while this app exists. Ordinary down releases that intent;
		// unjoined old natives are still covered by claims/retirement above.
		if entry.Down == nil && len(entry.Versions) > 1 {
			version := entry.Versions[len(entry.Versions)-2]
			if !version.OriginalRetained {
				if err = add(ImageReference{Tenant: scope.Tenant, App: scope.App, Deployment: scope.Deployment, Kind: "app-previous-unknown", Operation: version.Operation, Version: version.Revision, Unknown: true}); err != nil {
					return nil, err
				}
				continue
			}

			var local *deployment.LocalServicesDocument
			if len(version.LocalBody) > 0 {
				local = &deployment.LocalServicesDocument{Revision: version.LocalRevision, Actor: version.LocalActor, Digest: version.LocalDigest, Body: version.LocalBody}
			}
			input, err := deployment.RestoreAppInput(version.Body, local, scope, version.Overlays)
			if err != nil {
				return nil, err
			}

			for name, service := range input.Services {
				nodes := service.Sfc.Nodes
				if len(nodes) == 0 {
					nodes = []string{service.Sfc.Node}
				}
				for _, placement := range nodes {
					row := ImageReference{Tenant: scope.Tenant, App: scope.App, Deployment: scope.Deployment, Node: placement, Service: name, Image: service.Image, Kind: "app-previous", Operation: version.Operation, Commit: version.Commit, Version: version.Revision}
					if err = addService(row, service); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	checkers, err := p.Lifecycles(s)
	if err != nil {
		return nil, err
	}
	for _, job := range checkers.BuildJobs() {
		if job.Closure != nil || tenant != "" && job.Intent.Tenant != tenant || node != "" && job.Intent.Node != node {
			continue
		}
		policy, ok := checkers.AdmissionPolicy(job.Intent.Tenant, job.Intent.Selection.PolicyRevision)
		if !ok {
			return nil, ErrCatalog
		}
		if err = add(ImageReference{Tenant: job.Intent.Tenant, Node: job.Intent.Node, Task: "compiler/" + job.Intent.Tenant + "/" + job.Intent.ID, Kind: "lifecycle-build", Operation: job.Intent.ID, Image: policy.Build.Image}); err != nil {
			return nil, err
		}
	}
	builds, err := p.ImageBuilds(s)
	if err != nil {
		return nil, err
	}
	for _, job := range builds.Jobs {
		if job.Deleted {
			continue
		}
		spec := job.Run.Spec
		base := ImageReference{Tenant: spec.Tenant, Node: spec.Scope.Root.Node, Operation: spec.ID, Task: "image-build/" + spec.Tenant + "/" + spec.ID}
		if !job.Run.Terminal() {
			row := base
			row.Kind = "image-build-builder"
			row.Image = spec.Policy.BuilderImage
			if err := add(row); err != nil {
				return nil, err
			}
			for _, input := range job.Run.Inputs {
				row := base
				row.Kind = "image-build-base"
				row.Image = input.Image
				if err := add(row); err != nil {
					return nil, err
				}
			}
			for _, tag := range mustJobTags(spec) {
				row := base
				row.Kind = "image-build-output"
				row.Image = tag
				if err := add(row); err != nil {
					return nil, err
				}
			}
		} else if job.Run.Closure.Result.Code == "OK" {
			row := base
			row.Kind = "image-build-result"
			row.Image = job.Run.Closure.Result.Image
			if err := add(row); err != nil {
				return nil, err
			}
		}
	}
	for _, prune := range builds.CachePrunes {
		if !prune.Pending() {
			continue
		}
		change, err := prune.Change()
		if err != nil {
			return nil, err
		}
		source, found := builds.Job(change.Tenant, prune.Source)
		if !found {
			return nil, ErrCatalog
		}
		if err := add(ImageReference{Tenant: change.Tenant, Node: change.Node, Kind: "image-build-cache-prune", Operation: change.ID, Task: "image-build-cache-prune/" + change.Tenant + "/" + change.ID, Image: source.Run.Spec.Policy.BuilderImage}); err != nil {
			return nil, err
		}
	}
	result := make([]ImageReference, 0, len(rows))
	for _, row := range rows {
		result = append(result, row)
	}
	slices.SortFunc(result, func(a, b ImageReference) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return result, nil
}
