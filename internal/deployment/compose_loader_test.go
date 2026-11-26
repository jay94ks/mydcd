// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"strings"
	"testing"
)

func TestComposeLibraryDoesNotResolveFilesEnvironmentOrUnsupportedFeatures(t *testing.T) {
	if _, err := standardCompose([]byte(strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64)))); err != nil {
		t.Fatal("upstream fixture boundary", err)
	}
	t.Setenv("DB_HOST", "ambient-value")
	for _, mutate := range []func(string) string{
		func(s string) string { return "include: [/unapproved.yaml]\n" + s },
		func(s string) string {
			return strings.Replace(s, "    command: [php, app.php]", "    extends: {file: /unapproved.yaml, service: source}", 1)
		},
		func(s string) string {
			return strings.Replace(s, "    command: [php, app.php]", "    env_file: /unapproved.env", 1)
		},
		func(s string) string {
			return strings.Replace(s, "    environment: {DB_HOST: db, DB_PASSWORD_FILE: /run/secrets/db-password}", "    environment: [DB_HOST]", 1)
		},
		func(s string) string {
			return strings.Replace(s, "    command: [php, app.php]", "    command: php app.php", 1)
		},
		func(s string) string {
			return strings.Replace(s, "    command: [php, app.php]", "    build: /unapproved", 1)
		},
	} {
		if _, err := ParseCompose([]byte(mutate(strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64))))); err == nil {
			t.Fatal("unsupported input reached standard loader")
		}
	}
	c := smallCompose(t)
	if c.Secrets["db-password"].External || c.Secrets["db-password"].MyDC.Source != "service-final-keyset" {
		t.Fatal("standard projection changed MyDC secret ownership")
	}
	explicit := strings.Replace(composeFixture, "  db-password:\n", "  db-password:\n    external: false\n", 1)
	withFalse, err := ParseCompose([]byte(strings.ReplaceAll(explicit, "DIGEST", strings.Repeat("a", 64))))
	if err != nil || withFalse.Secrets["db-password"].External {
		t.Fatal("explicit false changed managed secret ownership", err)
	}
	if c.Services["web"].Environment["DB_HOST"] != "db" {
		t.Fatal("host environment inherited")
	}
	precision := strings.Replace(composeFixture, "cpus: 0.5", "cpus: 0.123456789", 1)
	c, err = ParseCompose([]byte(strings.ReplaceAll(precision, "DIGEST", strings.Repeat("a", 64))))
	if err != nil || c.Services["web"].CPUs != "0.123456789" {
		t.Fatal("float32 rounded reviewed CPU budget", err)
	}
}
