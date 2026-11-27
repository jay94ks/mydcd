// SPDX-License-Identifier: Apache-2.0

package enginefake

import (
	"github.com/jay94ks/seafield/internal/config"

	"gopkg.in/yaml.v3"
)

// Modules is a node's module configuration with network and workload on
// this engine (and ingress off).
func (e *Engine) Modules() map[string]config.Module {
	return map[string]config.Module{
		"network":  module("enabled: true\n"),
		"workload": module("enabled: true\n"),
		"ingress":  {},
	}
}

// Node is a node configuration with Modules on this engine.
func (e *Engine) Node() config.Node {
	return config.Node{Version: 1, Modules: e.Modules(), EngineAPI: e.Endpoint(), AnonymousImages: e.Source}
}

func module(body string) config.Module {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		panic(err)
	}
	return config.Module{Enabled: true, Body: *doc.Content[0]}
}
