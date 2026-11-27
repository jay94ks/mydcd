// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"reflect"

	"github.com/jay94ks/seafield/internal/access"
	"gopkg.in/yaml.v3"
)

func appFields(root *yaml.Node) error {
	if x := nodeField(root, "x-sfc"); x != nil {
		for _, field := range []string{"nodes", "vault", "routing", "registries"} {
			if nodeField(x, field) != nil {
				return inputError("CLUSTER_SETTING_IN_APP", "x-sfc."+field)
			}
		}
	}
	if networks := nodeField(root, "networks"); networks != nil && networks.Kind == yaml.MappingNode {
		for i := 0; i < len(networks.Content); i += 2 {
			alias, n := networks.Content[i].Value, networks.Content[i+1]
			for _, field := range []string{"driver", "x-sfc"} {
				if nodeField(n, field) != nil {
					return inputError("CLUSTER_SETTING_IN_APP", "networks."+alias+"."+field)
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
		return inputError("CLUSTER_SETTING_IN_APP", "x-sfc")
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
	}
	return nil
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
