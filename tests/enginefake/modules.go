// SPDX-License-Identifier: Apache-2.0

package enginefake

import (
	"github.com/jay94ks/mydcd/internal/config"

	"gopkg.in/yaml.v3"
)

// Modules is a node's module configuration with network and workload on
// this engine (and ingress off).
func (e *Engine) Modules() map[string]config.Module {
	return map[string]config.Module{
		"network":  module("enabled: true\ndocker_socket: " + e.Endpoint() + "\n"),
		"workload": module("enabled: true\n"),
		"ingress":  {},
	}
}

func module(body string) config.Module {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		panic(err)
	}
	return config.Module{Enabled: true, Body: *doc.Content[0]}
}
