// SPDX-License-Identifier: Apache-2.0

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/config"
)

// node.yaml no longer names the engine API (config.Node.EngineAPI): native
// tests that give each node its own engine keep that engine's endpoint
// beside the node's file, in NODE.yaml.engine, and set it on every load.

// writeTestEngine records the engine API endpoint the node at configPath uses.
func writeTestEngine(t *testing.T, configPath, endpoint string) {
	t.Helper()
	if err := os.WriteFile(configPath+".engine", []byte(endpoint), 0600); err != nil {
		t.Fatal(err)
	}
}

// testEngineAPI is the engine a native test uses when a node has none of its
// own: SFC_TEST_ENGINE_API, else the host's Docker Engine.
func testEngineAPI() string {
	if v := os.Getenv("SFC_TEST_ENGINE_API"); v != "" {
		return v
	}
	return "unix:///var/run/docker.sock"
}

func testEngineAPIFor(configPath string) string {
	if raw, err := os.ReadFile(configPath + ".engine"); err == nil {
		return strings.TrimSpace(string(raw))
	}
	return testEngineAPI()
}

// loadTestNode is config.LoadNode with the node's test engine set.
func loadTestNode(configPath string) (config.Node, error) {
	c, err := config.LoadNode(configPath)
	if err == nil {
		c.EngineAPI = testEngineAPIFor(configPath)
	}
	return c, err
}

// sfcdEngineFlags are the sfcd options for the node at configPath: its test
// engine, and an engine socket of its own beside its file.
func sfcdEngineFlags(configPath string) []string {
	base := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	return []string{"--engine-api", testEngineAPIFor(configPath), "--engine-socket", filepath.Join(filepath.Dir(configPath), base+"-sfcd-engine.sock")}
}
