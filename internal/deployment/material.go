// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"fmt"
	"io"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type Fetched struct {
	Realm string
	Value secrets.Fetched
}
type File struct {
	Projection Projection
	Data       []byte
	Source     string
}

// Stage is private, complete in-memory material. It is not a synced filesystem
// receipt, permission to Start, or a durable Ready record. The node adapter must
// publish one immutable consumer generation after sync and a current final gate.
type Stage struct {
	binding [32]byte
	files   []File
}

func (s Stage) Binding() [32]byte { return s.binding }

// Destroy releases owned staging bytes after publication/use. Copies explicitly
// extracted by a caller retain their own lifetime and must be cleared by it.
func (s *Stage) Destroy() {
	for i := range s.files {
		clear(s.files[i].Data)
	}
	s.files = nil
	s.binding = [32]byte{}
}
func (s Stage) Files() []File {
	out := slices.Clone(s.files)
	for i := range out {
		out[i].Data = bytes.Clone(out[i].Data)
	}
	return out
}
func (Stage) MarshalJSON() ([]byte, error)   { return nil, secrets.ErrPrivateMaterial }
func (File) MarshalJSON() ([]byte, error)    { return nil, secrets.ErrPrivateMaterial }
func (Fetched) MarshalJSON() ([]byte, error) { return nil, secrets.ErrPrivateMaterial }
func (Stage) Format(s fmt.State, _ rune)     { _, _ = io.WriteString(s, "[redacted app input stage]") }
func (File) Format(s fmt.State, _ rune)      { _, _ = io.WriteString(s, "[redacted app input file]") }
func (Fetched) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted app input material]") }

func qualified(realm, id string) string { return realm + "/" + id }

// Materialize checks ALL current grants/pins, exact provider revisions and keys
// before returning ANY file. Repeated/global/tenant source order is preserved;
// approval deduplication never sorts the override sequence. It uses the existing
// Secret.Merge algorithm rather than implementing a second key precedence rule.
func (b Binding) Materialize(inventory Bindings, c access.Catalog, trees map[string]secrets.Tree, a secrets.Approvals, v map[string]volumes.State, now int64, values []Fetched, maxBytes int) (Stage, error) {
	if maxBytes <= 0 || len(values) > 4096 {
		return Stage{}, ErrInputs
	}
	if e := b.Check(inventory, c, trees, a, v, now); e != nil {
		return Stage{}, e
	}
	plans := map[string]secrets.UsePlan{}
	for _, g := range b.d.Grants {
		plan, err := a.ReadSet(c, trees[g.Realm], g, now)
		if err != nil {
			return Stage{}, err
		}
		plans[g.Realm] = plan
	}
	return materializeInputs(b.d.Needs, plans, values, maxBytes, b.Digest())
}

// CheckPreparedInputs uses the same private merge/file builder as actual bound
// consumption without manufacturing a Task generation, grant or native stage.
// The caller must verify the exact current authorized public plans separately.
func (b Blueprint) CheckPreparedInputs(service string, requester [32]byte, plans map[string]secrets.UsePlan, values []Fetched, maxBytes int) error {
	n, err := b.inputMetadata(service, requester)
	if err != nil {
		return err
	}
	uses := approvalRealmUses(n)
	if len(uses) != len(plans) {
		return ErrInputs
	}
	for realm, use := range uses {
		plan, ok := plans[realm]
		if !ok || !useEqual(use, plan.Use) {
			return ErrInputs
		}
	}
	stage, err := materializeInputs(n, plans, values, maxBytes, [32]byte{})
	defer stage.Destroy()
	return err
}

func materializeInputs(n Needs, plans map[string]secrets.UsePlan, values []Fetched, maxBytes int, binding [32]byte) (Stage, error) {
	if maxBytes <= 0 || len(values) > 4096 {
		return Stage{}, ErrInputs
	}
	positions := map[string][]int{}
	for i, s := range n.ApprovalSources() {
		positions[s.Realm] = append(positions[s.Realm], i)
	}
	var combined secrets.UsePlan
	for realm, plan := range plans {
		for _, leaf := range plan.Leaves {
			if leaf.SourcePosition < 0 || leaf.SourcePosition >= len(positions[realm]) {
				return Stage{}, ErrInputs
			}
			leaf.Secret = qualified(realm, leaf.Secret)
			leaf.SourcePosition = positions[realm][leaf.SourcePosition]
			combined.Leaves = append(combined.Leaves, leaf)
		}
	}
	slices.SortStableFunc(combined.Leaves, func(a, b secrets.Leaf) int { return a.SourcePosition - b.SourcePosition })
	for i := range combined.Leaves {
		combined.Leaves[i].ExpansionPosition = i
	}
	fetched := make([]secrets.Fetched, 0, len(values))
	for _, value := range values {
		x := value.Value
		x.Secret = qualified(value.Realm, x.Secret)
		fetched = append(fetched, x)
	}
	// Prepared targets may include auxiliary values; normal bound projections
	// contain only projection grants. Validate the supplied readset in either
	// case, then exclude auxiliary leaves from app precedence and projection.
	if len(n.RegistrySources) > 0 {
		if err := secrets.ValidateFetched(combined, fetched, maxBytes); err != nil {
			return Stage{}, err
		}
		var projected []secrets.Leaf
		needed := map[string]bool{}
		for _, leaf := range combined.Leaves {
			if leaf.SourcePosition < len(n.Sources) {
				leaf.ExpansionPosition = len(projected)
				projected = append(projected, leaf)
				needed[leaf.Secret] = true
			}
		}
		combined.Leaves = projected
		selected := make([]secrets.Fetched, 0, len(needed))
		for _, value := range fetched {
			if needed[value.Secret] {
				selected = append(selected, value)
			}
		}
		fetched = selected
	}
	keys, err := secrets.Merge(combined, fetched, maxBytes)
	if err != nil {
		return Stage{}, err
	}
	stage := Stage{binding: binding}
	good := false
	defer func() {
		for _, value := range keys.Values {
			clear(value)
		}
		if !good {
			stage.Destroy()
		}
	}()
	total := 0
	for _, projection := range n.Files {
		data, ok := keys.Values[projection.Key]
		if !ok || len(data) > maxBytes-total {
			return Stage{}, ErrInputs
		}
		total += len(data)
		stage.files = append(stage.files, File{Projection: projection, Data: bytes.Clone(data), Source: keys.Provenance[projection.Key].Secret})
	}
	good = true
	return stage, nil
}
