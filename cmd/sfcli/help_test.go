// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpDiscoversCommandsWithoutConfigurationOrSideEffects(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, test := range []struct {
		name string
		args []string
		want []string
	}{
		{"root", []string{"--help"}, []string{
			"node", "cluster", "events", "enroll-admin", "login", "whoami", "logout", "tenant",
			"cluster", "wallet", "manage", "app", "secret", "volume", "lifecycle", "registry", "cd",
			"context", "identity", "version",
			"global options before COMMAND", "--user", "--tenant",
		}},
		{"wallet", []string{"wallet", "--help"}, []string{"wallet init", "wallet passwd", "No private key/password output"}},
		{"login", []string{"login", "--help"}, []string{"--method private-key", "--method password", "--method token", "--key NAME | --key-file PRIVATE.pem", "multiple saved accounts --user is required"}},
		{"enroll-admin", []string{"enroll-admin", "--help"}, []string{"enroll-admin --user-id ID --user USER (--key NAME | --key-file PRIVATE.pem) --request-id ID"}},
		{"whoami", []string{"whoami", "--help"}, []string{"whoami", "Requires auth: user"}},
		{"logout", []string{"logout", "--help"}, []string{"logout [--resume-original]", "unchanged intent"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			args := append([]string{"--config", filepath.Join(home, "absent.yaml")}, test.args...)
			var out, diagnostic bytes.Buffer
			if code := run(args, &out, &diagnostic); code != 0 {
				t.Fatalf("help required configuration/authentication: code=%d, %s", code, &diagnostic)
			}
			help := out.String() + diagnostic.String()
			for _, want := range test.want {
				if !strings.Contains(help, want) {
					t.Errorf("missing guidance %q in %s", want, help)
				}
			}
			entries, err := os.ReadDir(home)
			if err != nil || len(entries) != 0 {
				t.Fatalf("help changed local state: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestImageCommandHelp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for args, want := range map[string][]string{
		"registry --help":         {"create", "external", "prune", "login"},
		"image --help":            {"resolve", "pull-content", "usages"},
		"build --help":            {"context", "draft", "run", "cache", "policy"},
		"build context --help":    {"upload", "versions", "cat"},
		"build draft --help":      {"put", "freeze"},
		"build policy set --help": {"builder:", "concurrency"},
	} {
		var out, diagnostic bytes.Buffer
		if code := run(strings.Fields(args), &out, &diagnostic); code != 0 {
			t.Fatalf("%s: code %d %s", args, code, &diagnostic)
		}
		help := out.String() + diagnostic.String()
		for _, w := range want {
			if !strings.Contains(help, w) {
				t.Errorf("%s: missing %q in %s", args, w, help)
			}
		}
	}
}

func TestLegacyCommandsAcceptGlobalYes(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if code := run([]string{"-y", "manage", "--help"}, &out, &diagnostic); code != 0 {
		t.Fatal("legacy manage rejected -y", code, diagnostic.String())
	}
}
