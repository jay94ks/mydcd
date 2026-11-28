// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/secrets"
)

// Inputs resolves metadata aliases to the same D2 consumer recipe. generation
// comes from the real committed task; it is never assumed to be one by a plan.
// Source existence/ACL/approvals are checked by Required/Bindings.Reserve using
// current trees, including a namespace change if it has actually committed.
func (b Blueprint) Inputs(service, consumer string, generation uint64, requester [32]byte) (Needs, error) {
	n, err := b.inputMetadata(service, requester)
	if err != nil {
		return Needs{}, err
	}
	n.Consumer, n.Generation = consumer, generation
	if !validNeeds(n) {
		return Needs{}, ErrInputs
	}
	return n, nil
}

func (b Blueprint) inputMetadata(service string, requester [32]byte) (Needs, error) {
	s, logical, inputErr := b.taskInput(service)
	if inputErr != nil || b.d.Schema != 1 {
		return Needs{}, ErrInputs
	}
	var owner [32]byte
	for _, step := range b.d.Steps {
		if step.Kind == "task" && step.Key == ResourceKey("task", b.d.Tenant, b.d.App, service) {
			owner = step.Owner
			break
		}
	}
	n := Needs{Use: secrets.Use{Tenant: b.d.Tenant, User: b.d.Actor, App: b.d.App, Deployment: b.d.Deployment, Service: logical, Node: s.Sfc.Node, NodeKey: owner, RequesterKey: requester}}
	n.ResourceKeys = lifecycle.OwnIdentityTransitions(b.d.Nodes[s.Sfc.Node].ResourceKeys)
	n.RegistrySources = slices.Clone(b.d.RegistrySources[logical])
	if s.Sfc.Instance != nil {
		instance := *s.Sfc.Instance
		n.Instance = &instance
	}
	if b.d.Checkers != nil {
		program, err := b.d.Checkers.Task(logical)
		if err != nil {
			return Needs{}, err
		}
		selection, err := program.Selection()
		if err != nil {
			return Needs{}, err
		}
		n.Lifecycle = selection
	}
	n.Sources = selectorSources(b.d.Input, b.d.Tenant, s)
	for _, mount := range s.Secrets {
		def := b.d.Input.Secrets[mount.Source]
		if len(s.Sfc.Sources) == 0 {
			if def.File == "" && !def.External {
				return Needs{}, inputError("SECRET_SOURCES_REQUIRED", service)
			}
			id := mount.Source
			if def.Name != "" {
				id = def.Name
			}
			source := Source{Realm: b.d.Tenant, Object: id}
			if !slices.Contains(n.Sources, source) {
				n.Sources = append(n.Sources, source)
			}
		}
		uid, _ := strconv.ParseUint(mount.UID, 10, 32)
		gid, _ := strconv.ParseUint(mount.GID, 10, 32)
		mode, _ := strconv.ParseUint(mount.Mode, 8, 32)
		n.Files = append(n.Files, Projection{Key: def.Sfc.Key, Target: mount.Target, UID: uint32(uid), GID: uint32(gid), Mode: uint32(mode)})
	}

	for _, env := range s.Sfc.SecretEnv {
		def := b.d.Input.Secrets[env.Source]
		if len(s.Sfc.Sources) == 0 {
			if def.File == "" && !def.External {
				return Needs{}, inputError("SECRET_SOURCES_REQUIRED", service)
			}
			id := env.Source
			if def.Name != "" {
				id = def.Name
			}
			source := Source{Realm: b.d.Tenant, Object: id}
			if !slices.Contains(n.Sources, source) {
				n.Sources = append(n.Sources, source)
			}
		}
		n.Files = append(n.Files, Projection{Key: def.Sfc.Key, Target: env.Name, Mode: 0400, Kind: "env"})
	}
	for _, mount := range s.Volumes {
		key := b.volumeKey(mount.Source)
		n.Volumes = append(n.Volumes, VolumeNeed{key, !mount.ReadOnly})
		if ref, ok := b.d.FixedVolumes[mount.Source]; ok {
			if n.FixedVolumes == nil {
				n.FixedVolumes = map[string]VolumeReference{}
			}
			n.FixedVolumes[key] = ref
		}
	}
	if !validInputMetadata(n) {
		return Needs{}, ErrInputs
	}
	return n, nil
}

// selectorSources resolves a service's `secrets_from` selectors to Vault
// objects: tenant realm by default, the cluster realm for cluster/NAME, and
// app-local Vault aliases to their object IDs.
func selectorSources(c Compose, tenant string, s ComposeService) []Source {
	var out []Source
	for _, selector := range s.Sfc.Sources {
		realm := tenant
		id := selector.Secret
		if selector.Group != "" {
			id = selector.Group
		}
		if selector.Scope == "cluster" {
			realm = ""
		} else if v := c.Sfc.Vault; v != nil {
			if selector.Secret != "" {
				if o, ok := v.Tree.Secrets[id]; ok {
					id = o.ID
				}
			} else {
				if o, ok := v.Tree.Groups[id]; ok {
					id = o.ID
				}
			}
		}
		out = append(out, Source{Realm: realm, Object: id})
	}
	return out
}

// secretInputSources is every Vault object a service's inputs read: its
// selectors, or without them the names of its mounted and env secrets (the
// same rule as inputMetadata).
func secretInputSources(c Compose, tenant string, s ComposeService) []Source {
	out := selectorSources(c, tenant, s)
	if len(s.Sfc.Sources) != 0 {
		return out
	}
	add := func(name string) {
		def := c.Secrets[name]
		if def.File == "" && !def.External {
			return
		}
		id := name
		if def.Name != "" {
			id = def.Name
		}
		if source := (Source{Realm: tenant, Object: id}); !slices.Contains(out, source) {
			out = append(out, source)
		}
	}
	for _, mount := range s.Secrets {
		add(mount.Source)
	}
	for _, env := range s.Sfc.SecretEnv {
		add(env.Source)
	}
	return out
}

// InputMetadata is an owned permission/selection recipe for planning. It has
// no consumer or generation and is not a reservation, permit, or native fact.
func (b Blueprint) InputMetadata(taskID string, requester [32]byte) (Needs, error) {
	n, err := b.inputMetadata(taskID, requester)
	return ownNeeds(n), err
}

// ApprovalUses shares the exact metadata resolution used by real Inputs. It
// needs no consumer lease or invented task generation before commit.
func (b Blueprint) ApprovalUses(requester [32]byte) (map[string][]secrets.Use, error) {
	uses := map[string][]secrets.Use{}
	for _, step := range b.Steps() {
		if step.Kind != "task" {
			continue
		}
		service, err := ResourceIDFromKey("task", b.d.Tenant, b.d.App, step.Key)
		if err != nil {
			return nil, err
		}
		n, err := b.inputMetadata(service, requester)
		if err != nil {
			return nil, err
		}
		for realm, use := range approvalRealmUses(n) {
			// The password approval covers a logical service on a node, not
			// a fabricated extra identity per ordinal. Every actual Binding
			// still reserves its own consumer/generation and usage capacity.
			if !slices.ContainsFunc(uses[realm], func(previous secrets.Use) bool { return useEqual(previous, use) }) {
				uses[realm] = append(uses[realm], use)
			}
		}
	}
	return uses, nil
}

func (e Execution) Blueprint() Blueprint {
	raw, _ := json.Marshal(e.d.Plan)
	b, _ := DecodeBlueprint(raw)
	return b
}

// DecodeBlueprint restores bounded canonical metadata only. Runtime policy,
// availability and per-resource CAS still require current revalidation. It
// never converts a stored plan into a health or command-commit receipt.
func DecodeBlueprint(raw []byte) (Blueprint, error) {
	if len(raw) > 4<<20 {
		return Blueprint{}, ErrInputs
	}
	var d blueprintRecord
	if json.Unmarshal(raw, &d) != nil || d.Schema != 1 || d.Cluster == ([32]byte{}) || !identifier(d.Actor) || !identifier(d.Tenant) || !identifier(d.App) || !identifier(d.Deployment) || d.Input.Name != d.App || d.Input.Sfc.Tenant != d.Tenant || d.Input.Sfc.Deployment != d.Deployment || d.Input.validate() != nil || len(d.Steps) == 0 && !d.Input.allowEmpty() || len(d.Steps) > 1024 {
		return Blueprint{}, ErrInputs
	}
	if d.Input.Standalone != (d.InputKind == "standalone") {
		return Blueprint{}, ErrInputs
	}
	if d.InputKind != "" && d.InputKind != "app" && d.InputKind != "standalone" || (d.InputKind == "app" || d.InputKind == "standalone") && d.Input.validateApp(d.InputKind == "standalone") != nil {
		return Blueprint{}, ErrInputs
	}
	if d.DefaultNode != "" && (!identifier(d.DefaultNode) || d.InputKind != "app" || d.Input.Sfc.Delivery == nil || !d.Input.Sfc.Delivery.Enabled) {
		return Blueprint{}, ErrInputs
	}
	if !validCheckerPlan(d) || !validPlanTaskMetadata(d) || !validBlueprintDocument(Blueprint{d}) {
		return Blueprint{}, ErrInputs
	}
	steps := map[string]Step{}
	for _, s := range d.Steps {
		prefix := ResourceKey(s.Kind, d.Tenant, d.App, "root")
		if prefix == "" || len(s.Key) < len(prefix)-4 || s.Completion != Committed && s.Completion != Applied && s.Completion != Healthy && s.Completion != Completed && s.Completion != Released {
			return Blueprint{}, ErrInputs
		}
		id := s.Key[len(prefix)-4:]
		if ResourceKey(s.Kind, d.Tenant, d.App, id) != s.Key || !json.Valid(s.Goal) || s.Retain != (s.Kind == "volume" || s.Kind == "namespace") {
			return Blueprint{}, ErrInputs
		}
		if s.Node != "" {
			n, ok := d.Nodes[s.Node]
			if !ok || !n.resourceIdentity(d.Cluster, s.Node, s.Owner) || (s.Kind == "task" || s.Kind == "inputs") && n.Key != s.Owner || n.Generation == 0 || n.Revision == 0 {
				return Blueprint{}, ErrInputs
			}
		} else if s.Owner != ([32]byte{}) || s.Kind != "namespace" && s.Kind != "delivery" && s.Kind != "route" {
			return Blueprint{}, ErrInputs
		}
		if s.Base.Key != s.Key || s.Base.Generation > s.Base.Revision || s.BasePresent && (s.Base.Revision == 0 || s.Base.Generation == 0) {
			return Blueprint{}, ErrInputs
		}
		if _, exists := steps[s.Key]; exists {
			return Blueprint{}, ErrInputs
		}
		steps[s.Key] = s
	}
	ordered, e := orderSteps(steps)
	if e != nil {
		return Blueprint{}, e
	}
	if e = validateLifetimes(ordered); e != nil {
		return Blueprint{}, e
	}
	if !validDNSBindings(ordered) {
		return Blueprint{}, ErrInputs
	}
	a, _ := json.Marshal(ordered)
	actual, _ := json.Marshal(d.Steps)
	if !bytes.Equal(a, actual) {
		return Blueprint{}, ErrInputs
	}
	b := Blueprint{d}
	// All representation/graph/frozen metadata checks ran above. Encoding
	// here is solely the canonical byte comparison, not another validation.
	canonical, _ := json.Marshal(d)
	if !bytes.Equal(raw, canonical) {
		return Blueprint{}, ErrInputs
	}
	return b, nil
}

// ValidateCurrent is mandatory before accepting an untrusted/stored plan for a
// new operation. Decode checks representation, not authorization or the graph's
// agreement with a caller-supplied declaration. Accepted operations subsequently
// resume their frozen commands rather than recompiling a different artifact.
func (b Blueprint) ValidateCurrent(policy access.Catalog, ctx PlanningContext) error {
	if ctx.Actor != b.d.Actor || ctx.Cluster != b.d.Cluster || ctx.Tenant != "" && ctx.Tenant != b.d.Tenant || ctx.Project != "" && ctx.Project != b.d.App || ctx.Deployment != "" && ctx.Deployment != b.d.Deployment {
		return inputError("PLAN_SCOPE_CONFLICT", "plan")
	}
	if b.d.Checkers != nil {
		if b.d.Checkers.ValidateCatalog(ctx.Checkers) != nil {
			return ErrInputs
		}
		// Only immutable original inline staging facts are reused. Freeze still
		// checks current policy, provider membership and exact named versions.
		ctx.CheckerSources = b.inlineCheckerSources()
	}
	current, e := compile(b.d.Input, policy, ctx, nil, b.d.InputKind)
	if e != nil {
		return e
	}
	current.d.Document = b.OriginalDocument()
	if !validBlueprintDocument(current) || current.Digest() != b.Digest() {
		return inputError("PLAN_CONFLICT", "plan")
	}
	return nil
}
