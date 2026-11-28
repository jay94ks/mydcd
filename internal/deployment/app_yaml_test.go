// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func secretsBlockDocument(secrets string) string {
	return strings.Replace(appInputDocument(), "x-sfc: {node: node-a}", "x-sfc: {node: node-a, "+secrets+"}", 1) + "secrets:\n  db:\n    x-sfc: {key: DB_PASSWORD}\n"
}

func TestAppSecretsBlockKeepsFlatModel(t *testing.T) {
	c, err := ParseApp([]byte(secretsBlockDocument("secrets: {from: [defaults, group/common, cluster/tls], env: [{source: db, name: DB_PASSWORD}]}")))
	if err != nil {
		t.Fatal(err)
	}
	x := c.Services["web"].Sfc
	if len(x.Sources) != 3 || x.Sources[1].Group != "common" || x.Sources[2].Scope != "cluster" || len(x.SecretEnv) != 1 || x.SecretEnv[0].Name != "DB_PASSWORD" || x.Socket != nil {
		t.Fatal("secrets block", x)
	}
	// The yaml form round-trips through the same block (CD and overrides
	// marshal the model and read it back).
	raw, err := yaml.Marshal(c.Services["web"].Sfc)
	if err != nil || !strings.Contains(string(raw), "secrets:") || strings.Contains(string(raw), "secrets_from") {
		t.Fatal("marshal", string(raw), err)
	}
	var back ServiceExtension
	if err := yaml.Unmarshal(raw, &back); err != nil || len(back.Sources) != 3 || len(back.SecretEnv) != 1 || back.Node != "node-a" {
		t.Fatal("round trip", back, err)
	}
	for _, bad := range []string{
		"secrets_from: [defaults]",
		"secret_env: [{source: db, name: DB_PASSWORD}]",
		"secrets: {from: [defaults], unknown: 1}",
		"secrets: {from: [../x]}",
		"secrets: {socket: [api-token]}",
	} {
		if _, err := ParseApp([]byte(secretsBlockDocument(bad))); err == nil || !strings.Contains(err.Error(), "INVALID_FIELD") {
			t.Fatal("accepted", bad, err)
		}
	}
}
