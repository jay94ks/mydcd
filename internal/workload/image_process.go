// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// ResolveImageProcess is the SDK boundary. ImageInspect returns OCI image
// metadata rather than a ContainerCreate Config; map only portable supported
// fields, then call the same previously verified resolution core.
func ResolveImageProcess(image client.ImageInspectResult, overrides ProcessOverrides) (Process, error) {
	c := image.Config
	if c == nil || image.Os != "" && image.Os != "linux" {
		return Process{}, ErrProcess
	}
	return ResolveProcess(image.ID, &container.Config{User: c.User, Cmd: c.Cmd, Entrypoint: c.Entrypoint, Env: c.Env, WorkingDir: c.WorkingDir, StopSignal: c.StopSignal, Healthcheck: c.Healthcheck, Volumes: c.Volumes, ArgsEscaped: c.ArgsEscaped}, overrides)
}
