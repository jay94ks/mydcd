// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"gopkg.in/yaml.v3"
)

// DeliveryOverride is a committed field ownership record, not native Applied.
// Anchors refer to the exact owned base at intent admission. Actual Desired
// changes use the SAME Execution/A1 result publication as ordinary deployment.
type DeliveryOverride struct {
	Path            []string
	Value           json.RawMessage
	Revision        uint64
	Actor           string
	CatalogRevision uint64
	Anchors         []DeliveryOverrideAnchor
}
type DeliveryOverrideAnchor struct {
	Object ObjectRef
	Node   string
	Owner  [32]byte
}
type overrideTarget struct {
	Key, Kind, Node string
}

func ownDeliveryOverrides(v []DeliveryOverride) []DeliveryOverride {
	if len(v) == 0 {
		return nil
	}
	raw, _ := json.Marshal(v)
	var out []DeliveryOverride
	_ = json.Unmarshal(raw, &out)
	return out
}
func (d Delivery) Overrides() []DeliveryOverride { return ownDeliveryOverrides(d.d.Overrides) }
func overrideName(path []string) string          { return strings.Join(path, "/") }
func overlapOverride(a, b []string) bool {
	n := min(len(a), len(b))
	return slices.Equal(a[:n], b[:n])
}

// AllowedAppOverride is the exact new-input whitelist, shared by the CLI and
// the reducer. Network/provider/placement/Secret/Volume policy is not an app
// field override.
func AllowedAppOverride(path []string) bool {
	if len(path) < 3 || len(path) > 4 || path[0] != "services" || !identifier(path[1]) {
		return false
	}
	if len(path) == 3 {
		return slices.Contains([]string{"image", "command", "entrypoint", "user", "stop_signal", "stop_grace_period", "cpus", "mem_limit", "dns", "dns_search", "logging"}, path[2])
	}
	if path[2] == "environment" {
		return validKey(path[3])
	}
	return path[2] == "healthcheck" && slices.Contains([]string{"test", "interval", "timeout", "retries", "start_period", "start_interval", "disable"}, path[3])
}

func overrideValue(raw []byte) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > 65536 || !json.Valid(raw) {
		return nil, ErrInputs
	}
	var tree yaml.Node
	if yaml.Unmarshal(raw, &tree) != nil {
		return nil, ErrInputs
	}
	budget := 4096
	var check func(*yaml.Node, int) bool
	check = func(n *yaml.Node, depth int) bool {
		budget--
		if budget < 0 || depth > 16 || n.Kind == yaml.AliasNode {
			return false
		}
		if n.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				key := n.Content[i]
				if key.Tag != "!!str" || seen[key.Value] {
					return false
				}
				seen[key.Value] = true
			}
		}
		for _, child := range n.Content {
			if !check(child, depth+1) {
				return false
			}
		}
		return true
	}
	if !check(&tree, 0) {
		return nil, ErrInputs
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if dec.Decode(&value) != nil {
		return nil, ErrInputs
	}
	return json.Marshal(value)
}
func yamlSet(root *yaml.Node, path []string, value *yaml.Node) error {
	current := root
	for i, key := range path {
		if current.Kind != yaml.MappingNode {
			return ErrInputs
		}
		index := -1
		for j := 0; j < len(current.Content); j += 2 {
			if current.Content[j].Value == key {
				index = j + 1
				break
			}
		}
		if i == len(path)-1 {
			if index >= 0 {
				current.Content[index] = value
			} else {
				current.Content = append(current.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
			}
			return nil
		}
		if index < 0 {
			child := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			current.Content = append(current.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, child)
			current = child
		} else {
			current = current.Content[index]
		}
	}
	return ErrInputs
}
func applyDeliveryOverrides(input Compose, overrides []DeliveryOverride) (Compose, error) {
	if len(overrides) == 0 {
		return input, nil
	}
	if !validOverrideSet(overrides, ^uint64(0)) {
		return Compose{}, ErrInputs
	}
	fields := make([]AppFieldOverlay, 0, len(overrides))
	for _, o := range overrides {
		fields = append(fields, AppFieldOverlay{Path: o.Path, Value: o.Value, Revision: o.Revision, Actor: o.Actor})
	}
	return applyAppFieldOverlays(input, fields)
}

// These are already accepted declaration values, not authority/grant anchors.
// The full mutation path validates DeliveryOverride before reaching this core.
func applyAppFieldOverlays(input Compose, overrides []AppFieldOverlay) (Compose, error) {
	if len(overrides) == 0 {
		return input, nil
	}
	if len(overrides) > 128 {
		return Compose{}, ErrInputs
	}
	for i, o := range overrides {
		value, err := overrideValue(o.Value)
		if err != nil || !bytes.Equal(value, o.Value) || !AllowedAppOverride(o.Path) || o.Revision == 0 || !identifier(o.Actor) {
			return Compose{}, ErrInputs
		}
		if i > 0 && overrideName(overrides[i-1].Path) >= overrideName(o.Path) {
			return Compose{}, ErrInputs
		}
		for _, prior := range overrides[:i] {
			if overlapOverride(prior.Path, o.Path) {
				return Compose{}, ErrInputs
			}
		}
	}

	raw, err := yaml.Marshal(input)
	if err != nil {
		return Compose{}, err
	}
	var tree yaml.Node
	if yaml.Unmarshal(raw, &tree) != nil || len(tree.Content) != 1 {
		return Compose{}, ErrInputs
	}
	// yaml omitempty would erase explicit [] on these native inputs. Their
	// presence controls whether the planner may supply the managed resolver.
	for name, service := range input.Services {
		for _, field := range []struct {
			name   string
			values []string
		}{{"dns", service.DNS}, {"dns_search", service.DNSSearch}} {
			if field.values != nil && len(field.values) == 0 {
				if yamlSet(tree.Content[0], []string{"services", name, field.name}, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}) != nil {
					return Compose{}, ErrInputs
				}
			}
		}
	}
	for _, o := range overrides {
		if _, ok := input.Services[o.Path[1]]; !ok {
			return Compose{}, ErrInputs
		}
		var value yaml.Node
		if yaml.Unmarshal(o.Value, &value) != nil || len(value.Content) != 1 {
			return Compose{}, ErrInputs
		}
		if yamlSet(tree.Content[0], o.Path, value.Content[0]) != nil {
			return Compose{}, ErrInputs
		}
	}
	raw, err = yaml.Marshal(&tree)
	if err != nil {
		return Compose{}, err
	}
	// Same bounded Compose parser, including validation and library model.
	return ParseCompose(raw)
}
func overrideTargets(input Compose, path []string, tenant, app string) ([]overrideTarget, error) {
	if !AllowedAppOverride(path) {
		return nil, ErrInputs
	}
	service, ok := input.Services[path[1]]
	if !ok {
		return nil, ErrInputs
	}
	instances, err := servicePlacements(path[1], service, "")
	if err != nil {
		return nil, err
	}
	out := []overrideTarget{}
	for _, instance := range instances {
		out = append(out, overrideTarget{ResourceKey("task", tenant, app, instance.ResourceID()), "task", instance.Node})
	}
	slices.SortFunc(out, func(a, b overrideTarget) int { return strings.Compare(a.Key, b.Key) })
	return out, nil
}
func validOverrideSet(items []DeliveryOverride, floor uint64) bool {
	if len(items) > 128 {
		return false
	}
	for i, o := range items {
		value, err := overrideValue(o.Value)
		if err != nil || !bytes.Equal(value, o.Value) || !AllowedAppOverride(o.Path) || o.Revision == 0 || o.Revision > floor || !identifier(o.Actor) || o.CatalogRevision == 0 || len(o.Anchors) == 0 || len(o.Anchors) > 128 {
			return false
		}
		if i > 0 && overrideName(items[i-1].Path) >= overrideName(o.Path) {
			return false
		}
		for j := 0; j < i; j++ {
			if overlapOverride(items[j].Path, o.Path) {
				return false
			}
		}
		for j, a := range o.Anchors {
			if a.Object.Key == "" || a.Object.Generation == 0 || a.Object.Revision < a.Object.Generation || !identifier(a.Node) || a.Owner == ([32]byte{}) || j > 0 && o.Anchors[j-1].Object.Key >= a.Object.Key {
				return false
			}
		}
	}
	return true
}
func checkOverrideOwners(b Blueprint, overrides []DeliveryOverride) error {
	steps := map[string]Step{}
	for _, s := range b.Steps() {
		steps[s.Key] = s
	}
	for _, o := range overrides {
		targets, err := overrideTargets(b.d.Input, o.Path, b.d.Tenant, b.d.App)
		if err != nil || len(targets) != len(o.Anchors) {
			return ErrInputs
		}
		for i, t := range targets {
			anchor := o.Anchors[i]
			step, ok := steps[t.Key]
			if !ok || anchor.Object.Key != t.Key || anchor.Owner != step.Owner || anchor.Node != step.Node {
				return inputError("OVERRIDE_OWNER_CHANGED", t.Key)
			}
		}
	}
	return nil
}

// Inventory is the current logical generation authority. Original intent
// anchors are never used to adopt an untracked external mutation/generation.
func (d Delivery) checkOverrideInventory(b Blueprint, overrides []DeliveryOverride, ctx PlanningContext) error {
	a := Inventory{d.d.Inventory}
	steps := map[string]Step{}
	for _, s := range b.Steps() {
		steps[s.Key] = s
	}
	for _, o := range overrides {
		for _, anchor := range o.Anchors {
			step := steps[anchor.Object.Key]
			at := a.claim(step.Key)
			if at < 0 {
				return inputError("UNTRACKED_APP_MUTATION", step.Key)
			}
			claim := a.d.Claims[at]
			if claim.Step.Owner != step.Owner || claim.Step.Node != step.Node {
				return inputError("OVERRIDE_OWNER_CHANGED", step.Key)
			}
			current := ctx.Current[step.Key]
			if step.BasePresent {
				if claim.Removed || current.Revision != claim.Result.Revision || current.Generation != claim.Result.Generation || current.Value != claim.Command.Value {
					return inputError("UNTRACKED_APP_MUTATION", step.Key)
				}
			} else if !claim.Removed || claim.Removal == nil || claim.Removal.Delete == nil || claim.Removal.Delete.Result == nil || current.Present || current.Revision != claim.Removal.Delete.Result.Revision || current.Generation != claim.Removal.Delete.Result.Generation {
				return inputError("UNTRACKED_APP_MUTATION", step.Key)
			}
		}
	}
	return nil
}
func (d Delivery) overridePermission(c access.Catalog, actor string, o DeliveryOverride, cleanup bool) bool {
	if cleanup {
		if c.AuthorizeCleanup(actor, d.d.Inventory.Tenant, access.ManageCD) != nil {
			return false
		}
	} else if c.Authorize(actor, d.d.Inventory.Tenant, access.ManageCD, "") != nil {
		return false
	}
	action := access.Deploy
	for _, anchor := range o.Anchors {
		if cleanup {
			if c.AuthorizeCleanup(actor, d.d.Inventory.Tenant, action) != nil {
				return false
			}
		} else if c.Authorize(actor, d.d.Inventory.Tenant, action, anchor.Node) != nil {
			return false
		}
	}
	return true
}
func (d Delivery) overrideIdle() bool {
	if d.d.Inventory.Retirement != nil || d.d.Transition != nil {
		return false
	}
	if e, ok := d.Inventory().Execution(); ok {
		return e.Status() == "Succeeded" || e.Status() == "Closed"
	}
	return true // Put still requires current accepted inventory claims below.
}

// PutOverride registers an intent against current owned bases. Actual runtime
// commands/results remain the ordinary app Execution, never a second writer.
func (d Delivery) PutOverride(expected, previous uint64, c access.Catalog, ctx PlanningContext, actor string, path []string, value json.RawMessage, refs []ObjectRef) (Delivery, error) {
	if expected != d.Revision() || !d.scope(c, ctx) || !d.overrideIdle() || d.d.Candidate == nil || d.d.OverrideRevision == ^uint64(0) || !AllowedAppOverride(path) || (Blueprint{d.d.Candidate.Plan}).CheckAppInput() != nil {
		return d, ErrInputs
	}
	canonical, err := overrideValue(value)
	if err != nil {
		return d, err
	}
	targets, err := overrideTargets(d.d.Candidate.Plan.Input, path, d.d.Inventory.Tenant, d.d.Inventory.App)
	if err != nil || len(targets) != len(refs) {
		return d, ErrInputs
	}
	o := DeliveryOverride{Path: slices.Clone(path), Value: canonical, Revision: d.d.OverrideRevision + 1, Actor: actor, CatalogRevision: c.Revision()}
	a := d.Inventory()
	for i, target := range targets {
		current := ctx.Current[target.Key]
		index := a.claim(target.Key)
		var g GoalCommand
		if refs[i] != (ObjectRef{target.Key, current.Revision, current.Generation}) || !current.Present || index < 0 || a.d.Claims[index].Removed || a.d.Claims[index].Step.Owner != ctx.Nodes[target.Node].Key || current.Generation != a.d.Claims[index].Result.Generation || current.Revision != a.d.Claims[index].Result.Revision || current.Value != a.d.Claims[index].Command.Value || json.Unmarshal([]byte(current.Value), &g) != nil || g.Lifecycle != nil || g.Cluster != d.d.Inventory.Cluster || g.Tenant != d.d.Inventory.Tenant || g.App != d.d.Inventory.App || g.Deployment != d.d.Inventory.Deployment || g.Kind != target.Kind || g.Node != target.Node || g.Owner != a.d.Claims[index].Step.Owner {
			return d, ErrInputs
		}
		o.Anchors = append(o.Anchors, DeliveryOverrideAnchor{refs[i], g.Node, g.Owner})
	}
	if !d.overridePermission(c, actor, o, false) {
		return d, access.ErrDenied
	}
	index := slices.IndexFunc(d.d.Overrides, func(old DeliveryOverride) bool { return slices.Equal(old.Path, path) })
	if index < 0 && previous != 0 || index >= 0 && d.d.Overrides[index].Revision != previous {
		return d, ErrInputs
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	if index < 0 {
		n.d.Overrides = append(n.d.Overrides, o)
	} else {
		n.d.Overrides[index] = o
	}
	n.d.OverrideRevision++
	slices.SortFunc(n.d.Overrides, func(a, b DeliveryOverride) int { return strings.Compare(overrideName(a.Path), overrideName(b.Path)) })
	if !validOverrideSet(n.d.Overrides, n.d.OverrideRevision) {
		return d, ErrInputs
	}
	candidate, err := n.compile(c, ctx, n.d.Candidate.Artifact)
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Candidate = &candidate
	n.d.Approval = nil
	return n, nil
}

// ReleaseOverride is explicit current-authority ownership release and approval
// of the rebuilt exact candidate. No timer silently returns fields to Git.
func (d Delivery) ReleaseOverride(expected, revision uint64, c access.Catalog, ctx PlanningContext, actor string, path []string) (Delivery, error) {
	if expected != d.Revision() || !d.baseScope(c, ctx) || !d.overrideIdle() || d.d.Candidate == nil || d.d.OverrideRevision == ^uint64(0) {
		return d, ErrInputs
	}
	index := slices.IndexFunc(d.d.Overrides, func(o DeliveryOverride) bool { return slices.Equal(o.Path, path) })
	metadataOnly := d.d.Paused && d.d.Inventory.Active == nil
	if index < 0 || d.d.Overrides[index].Revision != revision || !d.overridePermission(c, actor, d.d.Overrides[index], metadataOnly) {
		return d, ErrInputs
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.d.Overrides = slices.Delete(n.d.Overrides, index, index+1)
	if len(n.d.Overrides) == 0 {
		n.d.Overrides = nil
	}
	n.d.OverrideRevision++
	if metadataOnly {
		// Stopped resources need no further mutation. Sequential field release
		// may leave the old candidate stale; Replan is mandatory before Start.
		n.d.Approval = nil
		n.floors(c, ctx)
		return n, nil
	}
	candidate, err := n.compile(c, ctx, n.d.Candidate.Artifact)
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Candidate = &candidate
	n.d.Approval = &deliveryApproval{Candidate: candidate.ID, Actor: actor, CatalogRevision: c.Revision()}
	return n, nil
}
