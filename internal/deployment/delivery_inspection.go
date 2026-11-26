// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"

	"gopkg.in/yaml.v3"
)

// PublicFieldValue distinguishes a missing declaration from an explicit null.
// Values come only from accepted Compose metadata, never native inspect or a
// Secret backend. Internal frozen lifecycle/provider fields have yaml:"-".
type PublicFieldValue struct {
	Present bool
	Value   json.RawMessage `json:",omitempty"`
}

type DeliveryFieldValues struct {
	SourceCommit, CurrentCommit    string
	Source, RunningSource, Current PublicFieldValue
	Overridden                     bool
	CurrentOrigin                  string // candidate-intent, accepted-execution, override-intent
}

type ServiceFieldChange struct {
	Service, Action string // added, removed, changed
	Path            []string
	Before, After   PublicFieldValue
}

func publicComposeTree(c Compose) (map[string]any, error) {
	raw, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	var tree map[string]any
	if yaml.Unmarshal(raw, &tree) != nil {
		return nil, ErrInputs
	}
	return tree, nil
}

func publicArtifactTree(a deliveryArtifact) (map[string]any, error) {
	model, err := artifactCompose(a)
	if err != nil {
		return nil, err
	}
	var tree map[string]any
	if yaml.Unmarshal(a.Body, &tree) != nil {
		return nil, ErrInputs
	}
	services, ok := tree["services"].(map[string]any)
	if !ok {
		return nil, ErrInputs
	}
	for name, value := range services {
		service, ok := value.(map[string]any)
		if !ok {
			return nil, ErrInputs
		}
		// Compose's KEY=value list has the same field identity as a mapping.
		// Keep explicit mapping null/false values in the original source tree.
		if _, list := service["environment"].([]any); list {
			env := map[string]any{}
			for key, value := range model.Services[name].Environment {
				env[key] = value
			}
			service["environment"] = env
		}
	}
	return tree, nil
}

func publicField(tree map[string]any, path []string) PublicFieldValue {
	var value any = tree
	for _, part := range path {
		mapping, ok := value.(map[string]any)
		if !ok {
			return PublicFieldValue{}
		}
		value, ok = mapping[part]
		if !ok {
			return PublicFieldValue{}
		}
	}
	raw, _ := json.Marshal(value)
	return PublicFieldValue{Present: true, Value: raw}
}

// FieldValues uses the current candidate's original source and current intent.
// An override is an accepted intended value, not proof of native application;
// the ordinary field refs/operation/health describe that separate boundary.
func (d Delivery) FieldValues(path []string) (DeliveryFieldValues, error) {
	if !AllowedAppOverride(path) || d.d.Candidate == nil {
		return DeliveryFieldValues{}, ErrInputs
	}
	tree, err := publicArtifactTree(d.d.Candidate.Artifact)
	if err != nil {
		return DeliveryFieldValues{}, err
	}
	out := DeliveryFieldValues{SourceCommit: d.d.Candidate.Artifact.Commit, Source: publicField(tree, path), CurrentOrigin: "candidate-intent"}
	current := d.d.Candidate.Plan.Input
	// Prefer the applied plan unless this exact field has an explicit override.
	// A pending Git candidate must not be shown as the already deployed value.
	if d.d.Running != nil {
		current, out.CurrentCommit = d.d.Running.Candidate.Plan.Input, d.d.Running.Candidate.Artifact.Commit
		out.CurrentOrigin = "accepted-execution"
		runningTree, err := publicArtifactTree(d.d.Running.Candidate.Artifact)
		if err != nil {
			return DeliveryFieldValues{}, err
		}
		out.RunningSource = publicField(runningTree, path)
	}
	for _, override := range d.d.Overrides {
		if slices.Equal(override.Path, path) {
			out.Current = PublicFieldValue{Present: true, Value: bytes.Clone(override.Value)}
			out.Overridden, out.CurrentOrigin = true, "override-intent"
			return out, nil
		}
	}
	tree, err = publicComposeTree(current)
	if err != nil {
		return DeliveryFieldValues{}, err
	}
	out.Current = publicField(tree, path)
	return out, nil
}

// ServiceChanges compares effective service declarations, not resource CAS or
// health bookkeeping. The same array supplies both diff and changeCount.
// Added/removed services use a structural row; their full declaration remains
// available through the original source API rather than duplicating every key.
func (d Delivery) ServiceChanges() ([]ServiceFieldChange, error) {
	if d.d.Candidate == nil {
		return nil, ErrInputs
	}
	before := Compose{Services: map[string]ComposeService{}}
	if d.d.Running != nil {
		before = d.d.Running.Candidate.Plan.Input
	}
	return serviceChanges(before, d.d.Candidate.Plan.Input)
}

func serviceChanges(before, after Compose) ([]ServiceFieldChange, error) {
	a, err := publicComposeTree(before)
	if err != nil {
		return nil, err
	}
	b, err := publicComposeTree(after)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for name := range before.Services {
		names[name] = true
	}
	for name := range after.Services {
		names[name] = true
	}
	out := []ServiceFieldChange{}
	var compare func(string, []string)
	compare = func(service string, path []string) {
		left, right := publicField(a, path), publicField(b, path)
		if left.Present == right.Present && bytes.Equal(left.Value, right.Value) {
			return
		}
		var lm, rm map[string]json.RawMessage
		// Arrays/scalars (including explicit null) are atomic field values.
		if left.Present && right.Present && len(left.Value) > 0 && left.Value[0] == '{' && len(right.Value) > 0 && right.Value[0] == '{' && json.Unmarshal(left.Value, &lm) == nil && json.Unmarshal(right.Value, &rm) == nil {
			keys := map[string]bool{}
			for k := range lm {
				keys[k] = true
			}
			for k := range rm {
				keys[k] = true
			}
			for _, k := range mapKeys(keys) {
				compare(service, append(slices.Clone(path), k))
			}
			return
		}
		out = append(out, ServiceFieldChange{Service: service, Action: "changed", Path: slices.Clone(path), Before: left, After: right})
	}
	for _, name := range mapKeys(names) {
		_, had := before.Services[name]
		_, has := after.Services[name]
		path := []string{"services", name}
		if !had || !has {
			action := "added"
			if !has {
				action = "removed"
			}
			out = append(out, ServiceFieldChange{Service: name, Action: action, Path: path})
			continue
		}
		compare(name, path)
	}
	return out, nil
}
