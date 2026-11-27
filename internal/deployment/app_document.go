// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
)

// AppDocument binds original user bytes to the same effective plan. Overrides
// are explicit CD field overlays, never fetched Secret values or permissions.
type AppDocument struct {
	StandaloneScope string                 `json:",omitempty"`
	StandaloneMode  string                 `json:",omitempty"`
	StandaloneName  string                 `json:",omitempty"`
	LocalServices   *LocalServicesDocument `json:",omitempty"`
	Body            []byte
	DefaultNode     string             `json:",omitempty"`
	Overrides       []DeliveryOverride `json:",omitempty"`
}

// AppFieldOverlay retains public accepted values. It is deliberately distinct
// from DeliveryOverride's current permission/owner anchors; reads grant no edit.
type AppFieldOverlay struct {
	Path     []string
	Value    json.RawMessage
	Revision uint64
	Actor    string
}

func RestoreAppInput(raw []byte, local *LocalServicesDocument, scope AppScope, overlays []AppFieldOverlay) (Compose, error) {
	input, err := ParseApp(raw)
	if err != nil {
		return Compose{}, err
	}
	input, err = mergeLocalServices(input, local, scope)
	if err != nil {
		return Compose{}, err
	}
	return applyAppFieldOverlays(input, overlays)
}

// EffectiveInput restores the accepted declaration and its own overlays only.
// It performs no current-policy admission, default-node guessing or I/O; both
// compilation and retained-version image protection use this same operation.
func (d AppDocument) EffectiveInput(scope AppScope) (Compose, error) {
	parse := ParseApp
	if d.StandaloneName != "" {
		parse = ParseStandalone
	}
	input, err := parse(d.Body)
	if err != nil {
		return Compose{}, err
	}
	if d.StandaloneName != "" {
		if scope.App != d.StandaloneScope || !identifier(d.StandaloneScope) || (d.StandaloneMode != "entrypoint" && d.StandaloneMode != "shell") || d.LocalServices != nil || len(d.Overrides) != 0 || validateStandaloneInput(input, d.StandaloneName) != nil {
			return Compose{}, ErrInputs
		}
		applyStandaloneMode(&input, d.StandaloneMode)
		input.Name = scope.App
	}
	input, err = mergeLocalServices(input, d.LocalServices, scope)
	if err != nil {
		return Compose{}, err
	}
	return applyDeliveryOverrides(input, d.Overrides)
}

// CompileAppDocument retains the exact input, including comments and whitespace.
// The existing compiler still owns normalization, authorization and all goals.
func CompileAppDocument(raw []byte, policy access.Catalog, ctx PlanningContext) (Blueprint, error) {
	return compileAppDocument(raw, nil, policy, ctx, nil)
}

func compileAppDocument(raw []byte, overrides []DeliveryOverride, policy access.Catalog, ctx PlanningContext, move *VolumeMovePlacement, local ...*LocalServicesDocument) (Blueprint, error) {
	if len(local) > 1 {
		return Blueprint{}, ErrInputs
	}
	var additions *LocalServicesDocument
	if len(local) == 1 {
		additions = local[0]
	}
	input, err := (AppDocument{Body: raw, Overrides: overrides, LocalServices: additions}).EffectiveInput(AppScope{Tenant: ctx.Tenant, App: ctx.Project, Deployment: ctx.Deployment})
	if err != nil {
		return Blueprint{}, err
	}
	var b Blueprint
	if move == nil {
		b, err = CompileApp(input, policy, ctx)
	} else {
		b, err = CompileAppVolumeMove(input, policy, ctx, *move)
	}
	if err != nil {
		return Blueprint{}, err
	}
	b.d.Document = &AppDocument{Body: bytes.Clone(raw), DefaultNode: ctx.DefaultNode, Overrides: ownDeliveryOverrides(overrides), LocalServices: ownLocalServices(additions)}
	if _, err := b.Encode(); err != nil {
		return Blueprint{}, err
	}
	return b, nil
}

// OriginalDocument owns every returned byte. Nil means original bytes were
// never retained, not permission to reconstruct a different YAML as original.
func (b Blueprint) OriginalDocument() *AppDocument {
	if b.d.Document == nil {
		return nil
	}
	d := *b.d.Document
	d.Body, d.Overrides = bytes.Clone(d.Body), ownDeliveryOverrides(d.Overrides)
	d.LocalServices = ownLocalServices(d.LocalServices)
	return &d
}

// Only the committed Delivery core may attach historical field-owner/local overlays.
// An ordinary user upload must supply its own original app declaration.
func (b Blueprint) HasDocumentOverrides() bool {
	return b.d.Document != nil && (len(b.d.Document.Overrides) != 0 || b.d.Document.LocalServices != nil)
}

func validBlueprintDocument(b Blueprint) bool {
	d := b.d.Document
	if d == nil {
		return true // immutable schema1 artifacts accepted before retention
	}
	if (b.d.InputKind != "app" || d.StandaloneName != "") && (b.d.InputKind != "standalone" || d.StandaloneName == "") || len(d.Body) == 0 || len(d.Body) > ArtifactMaxBytes || d.DefaultNode != "" && !identifier(d.DefaultNode) || !validOverrideSet(d.Overrides, ^uint64(0)) || checkOverrideOwners(b, d.Overrides) != nil {
		return false
	}
	input, err := d.EffectiveInput(b.Scope())
	return err == nil && matchesBlueprintInput(input, b, &d.DefaultNode)
}

// This is the existing pure Delivery checkpoint model comparison. It validates
// only the compiler's frozen default resolutions; current authority and goal
// correctness remain with ValidateCurrent and the ordinary compiler.
func matchesBlueprintInput(input Compose, b Blueprint, defaultNode *string) bool {
	// Compile fills explicit CLI scope into an otherwise valid source.
	if input.Name == "" {
		input.Name = b.d.App
	}
	if input.Sfc.Tenant == "" {
		input.Sfc.Tenant = b.d.Tenant
	}
	if input.Sfc.Deployment == "" {
		input.Sfc.Deployment = b.d.Deployment
	}
	// Compile resolves omitted placement/resource defaults from the captured
	// node admission. Check these permitted resolutions without replaying any
	// current catalog, external fetch or side effect during snapshot restore.
	for name, source := range input.Services {
		bound, ok := b.d.Input.Services[name]
		if !ok {
			return false
		}
		if len(source.Sfc.Nodes) > 0 {
			// Per-instance defaults/addresses live in the frozen Task goals.
			// The original logical service remains the same declaration.
			input.Services[name] = source
			continue
		}
		if source.Sfc.Node == "" {
			source.Sfc.Node = bound.Sfc.Node
			if defaultNode != nil {
				source.Sfc.Node = *defaultNode
			}
		}
		node, ok := b.d.Nodes[bound.Sfc.Node]
		if !ok {
			return false
		}
		cpu, err := nanoCPU(source.CPUs)
		if err != nil {
			return false
		}
		if cpu == 0 {
			cpu = node.DefaultCPU
		}
		actualCPU, err := nanoCPU(bound.CPUs)
		if err != nil || cpu != actualCPU {
			return false
		}
		memory, err := byteSize(source.Memory)
		if err != nil {
			return false
		}
		if memory == 0 {
			memory = node.DefaultMemory
		}
		actualMemory, err := byteSize(bound.Memory)
		if err != nil || memory != actualMemory {
			return false
		}
		source.CPUs, source.Memory = bound.CPUs, bound.Memory
		source = resolveServiceDNS(source, input.Networks)
		input.Services[name] = source
	}
	for name, source := range input.Volumes {
		if source.Sfc.Node == "" {
			source.Sfc.Node = b.d.Input.Volumes[name].Sfc.Node
		}
		input.Volumes[name] = source
	}
	return bytes.Equal(goal(input), goal(b.d.Input))
}

func CompileAppDocumentVolumeMove(raw []byte, policy access.Catalog, ctx PlanningContext, move VolumeMovePlacement) (Blueprint, error) {
	return compileAppDocument(raw, nil, policy, ctx, &move)
}

// PlanMovedDocument is PlanMoved with an exact original user document. It uses
// the same policy/override/move compiler and retains no native authorization.
func (d Delivery) PlanMovedDocument(raw []byte, policy access.Catalog, ctx PlanningContext, move VolumeMovePlacement) (Blueprint, error) {
	input, err := ParseApp(raw)
	if err != nil || !d.scope(policy, ctx) || d.d.Paused || !d.overrideIdle() || !d.movePolicy(input) {
		return Blueprint{}, ErrInputs
	}
	return compileAppDocument(raw, d.d.Overrides, policy, ctx, &move, d.d.LocalServices)
}
