// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"log"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// checkerCompilerImage is the compiler image (repo@sha256:…) for task's
// compile=true scripts in this deploy: the policy's own digest, or the
// deploy's one resolution of its tag (devel/design/image-tags.md). When the
// deploy could not reach the registry, or was told the tag is gone, it is
// this server's last copy of the tag; with none the Task cannot compile.
func (r *Runtime) checkerCompilerImage(ctx context.Context, v cluster.View, task deployment.ObjectRef, program checker.TaskProgram) (string, error) {
	tag := program.CompilerTag()
	if tag == "" {
		image, err := access.PinImage(program.Policy.Build.Image)
		if err != nil {
			return "", checker.ErrPreparation
		}
		return image.Reference, nil
	}
	goal, err := schema.Decode[deployment.GoalCommand]([]byte(v.State.Object(task.Key).Value))
	if err != nil {
		return "", checker.ErrPreparation
	}
	apps, err := r.controlPolicy.Apps(v.State)
	if err != nil {
		return "", err
	}
	e, ok := apps.Execution(goal.Tenant, goal.App)
	if !ok {
		return "", checker.ErrPreparation
	}
	resolved, ok := e.Image(tag)
	switch {
	case !ok:
		return "", checker.ErrPreparation
	case resolved.Digest != "":
		return resolved.Digest, nil
	case !deployment.LocalCopyAllowed(resolved.Code):
		return "", fmt.Errorf("lifecycle compiler image %s: %s: %w", tag, resolved.Code, checker.ErrPreparation)
	}
	local, ok := r.imageTags.Get(goal.Tenant, tag)
	if !ok {
		local, err = r.localBuilderCopy(ctx, tag)
	}
	if local == "" || err != nil || !e.TagAllows(tag, local) {
		return "", fmt.Errorf("lifecycle compiler image %s: %s and this server has no copy: %w", tag, resolved.Code, checker.ErrPreparation)
	}
	log.Printf("lifecycle compiler image %s: %s, using this server's copy %s", tag, resolved.Code, local)
	return local, nil
}
