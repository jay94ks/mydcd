// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestRestoredWriterPreservesOriginalExecutableAndStorageLayout(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	job, f, _ := artifactFixture(t)
	target := job.Binding.Source.Spec
	target.Scope.ID, target.Materialization = "restored", "r-one"
	original, err := workload.DecodeContainer(f.source.Writer.Task.Spec)
	if err != nil {
		t.Fatal(err)
	}
	next := original
	raw, _ := json.Marshal(original)
	_ = json.Unmarshal(raw, &next)
	next.Volumes[0].Scope = target.Scope
	next.Volumes[0].NativeKey = volumes.NativeKey(target)
	next.Volumes[0].Consumer.Generation++
	next.BridgeGeneration++
	if !restoredWriterCompatible(f.source, job.Binding, target, next) {
		t.Fatal("same pinned writer with new target/task identities refused")
	}
	for _, name := range []string{"image", "command", "env", "user", "directory", "signal", "tmpfs", "destination", "scope", "multiple", "inputs", "recipe", "exit", "mode"} {
		t.Run(name, func(t *testing.T) {
			var changed workload.ContainerSpec
			b, _ := json.Marshal(next)
			_ = json.Unmarshal(b, &changed)
			source, backup, spec := f.source, job.Binding, target
			switch name {
			case "image":
				changed.Process.ImageID = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
			case "command":
				changed.Process.Command = []string{"/another-db"}
			case "env":
				changed.Process.Env = []string{"FORMAT=other"}
			case "user":
				changed.Process.User = "500:500"
			case "directory":
				changed.Process.WorkingDir = "/different"
			case "signal":
				changed.Process.StopSignal = "SIGKILL"
			case "tmpfs":
				changed.Tmpfs = []workload.Tmpfs{{Target: "/config"}}
			case "destination":
				changed.Volumes[0].Target = "/other"
			case "scope":
				changed.Volumes[0].Scope.Tenant = "other"
			case "multiple":
				changed.Volumes = append(changed.Volumes, changed.Volumes[0])
			case "inputs":
				changed.Inputs = &workload.InputRef{Key: "workload/inputs/tenant/app/db"}
			case "recipe":
				backup.Compatibility[0]++
			case "exit":
				source.Exit.Code = 137
			case "mode":
				spec.Mode = 0750
			}
			if restoredWriterCompatible(source, backup, spec, changed) {
				t.Fatal("incompatible writer accepted", name)
			}
		})
	}
}
