// SPDX-License-Identifier: Apache-2.0

package engineconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jay94ks/seafield/internal/config"
)

// The defaults are the node package's sample daemon.json.
func TestRenderDefaultsMatchThePackagedSample(t *testing.T) {
	got, err := Render(config.Engine{})
	if err != nil {
		t.Fatal(err)
	}
	sample, err := os.ReadFile("../../seafield/packaging/daemon.json")
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if json.Unmarshal(got, &a) != nil || json.Unmarshal(sample, &b) != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("rendered defaults differ from seafield/packaging/daemon.json:\n%s", got)
	}
}

func TestRenderTakesTheServersEngineSection(t *testing.T) {
	off := false
	got, err := Render(config.Engine{Build: &off, Logs: config.EngineLogs{NotifyQuiet: "50ms", NotifyMaxWait: "1m", MaxSize: "1g"}})
	if err != nil {
		t.Fatal(err)
	}
	var d daemon
	if err = json.Unmarshal(got, &d); err != nil {
		t.Fatal(err)
	}
	if d.Features["buildkit"] || d.LogOpts != (logOpts{CacheDisabled: "true", NotifyQuiet: "50ms", NotifyMaxWait: "1m0s", MaxSize: "1048576k"}) {
		t.Fatal(string(got))
	}
	for _, bad := range []config.EngineLogs{{NotifyQuiet: "5ms"}, {NotifyQuiet: "11s"}, {NotifyQuiet: "2s", NotifyMaxWait: "1s"}, {NotifyMaxWait: "61s"}, {MaxSize: "255k"}, {MaxSize: "5g"}, {MaxSize: "64MB"}, {NotifyQuiet: "soon"}} {
		if _, err := Render(config.Engine{Logs: bad}); err == nil {
			t.Error("accepted", bad)
		}
	}
}

// Write replaces the file only when it changes.
func TestWriteReportsAChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.json")
	if changed, err := Write(path, config.Engine{}); err != nil || !changed {
		t.Fatal(changed, err)
	}
	if changed, err := Write(path, config.Engine{}); err != nil || changed {
		t.Fatal("rewrote the same file", changed, err)
	}
	off := false
	if changed, err := Write(path, config.Engine{Build: &off}); err != nil || !changed {
		t.Fatal(changed, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatal(info, err)
	}
	if _, err := Write("daemon.json", config.Engine{}); err == nil {
		t.Fatal("relative path")
	}
}
