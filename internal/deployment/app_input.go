// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"github.com/jay94ks/seafield/internal/logstore"
	"reflect"

	"github.com/jay94ks/seafield/internal/access"
	"gopkg.in/yaml.v3"
)

func appFields(root *yaml.Node) error {
	if x := nodeField(root, "x-sfc"); x != nil {
		// The model keeps these for cluster settings; app.yaml has no such
		// keys (yaml-formats.md Y9).
		for _, field := range []string{"nodes", "vault", "routing", "registries"} {
			if nodeField(x, field) != nil {
				return inputError("INVALID_FIELD", "x-sfc."+field)
			}
		}
	}
	if networks := nodeField(root, "networks"); networks != nil && networks.Kind == yaml.MappingNode {
		for i := 0; i < len(networks.Content); i += 2 {
			alias, n := networks.Content[i].Value, networks.Content[i+1]
			for _, field := range []string{"driver", "x-sfc"} {
				if nodeField(n, field) != nil {
					return inputError("INVALID_FIELD", "networks."+alias+"."+field)
				}
			}
			if external := nodeField(n, "external"); external != nil && (external.Tag != "!!bool" || external.Value != "true") {
				return inputError("MANAGED_NETWORK_REFERENCE_REQUIRED", "networks."+alias)
			}
		}
	}
	return nil
}

// ValidateApp applies to a new in-memory input or untrusted new artifact. It
// grants no resource authority and does not reinterpret old accepted records.
func (c Compose) ValidateApp() error { return c.validateApp(false) }
func (c Compose) validateApp(standalone bool) error {
	if c.Standalone != standalone {
		return inputError("WORKLOAD_OWNER_KIND", "services")
	}
	if err := c.validate(); err != nil {
		return err
	}
	if len(c.Sfc.Nodes) != 0 || c.Sfc.Vault != nil || c.Sfc.Routing != nil || len(c.Sfc.Registries) != 0 {
		return inputError("INVALID_FIELD", "x-sfc")
	}
	for alias, n := range c.Networks {
		if !n.External || n.Driver != "" || !reflect.DeepEqual(n.Sfc, NetworkExtension{}) {
			return inputError("MANAGED_NETWORK_REFERENCE_REQUIRED", "networks."+alias)
		}
	}
	for name, s := range c.Services {
		if len(s.FixedVolumes) != 0 || s.LifecycleSources != nil || s.LifecycleProgram != nil || s.Sfc.Instance != nil {
			return inputError("RESERVED_TASK_METADATA", name)
		}
		if s.Sfc.Logs != nil {
			if _, _, err := logstore.ParseKeep(s.Sfc.Logs.Keep); err != nil {
				return inputError("INVALID_FIELD", "services."+name+".x-sfc.logs.keep")
			}
		}
	}
	if c.Sfc.Logs != nil {
		if _, _, err := logstore.ParseKeep(c.Sfc.Logs.Keep); err != nil {
			return inputError("INVALID_FIELD", "x-sfc.logs.keep")
		}
	}
	return nil
}

// LogKeep is the x-sfc.logs.keep that applies to service: the service's,
// else the app's, else "".
func (c Compose) LogKeep(service string) string {
	if s, ok := c.Services[service]; ok && s.Sfc.Logs != nil && s.Sfc.Logs.Keep != "" {
		return s.Sfc.Logs.Keep
	}
	if c.Sfc.Logs != nil {
		return c.Sfc.Logs.Keep
	}
	return ""
}

// CompileApp produces the app input contract using the existing compiler,
// graph, current CAS checks and Inventory/Execution. InputKind separates it
// from frozen old plans without changing schema1 or their encoded bytes.
func CompileApp(c Compose, policy access.Catalog, ctx PlanningContext) (Blueprint, error) {
	return compile(c, policy, ctx, nil, "app")
}

func (b Blueprint) CheckAppInput() error {
	if b.d.InputKind != "app" {
		return inputError("APP_INPUT_CONTRACT_REQUIRED", "plan")
	}
	return b.d.Input.ValidateApp()
}
