// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/imagecache"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/tests/enginefixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// The parent fixture owns its original live Task, CLI and remote leader. This
// adds one prebuilt, uniquely labeled image and one never-started container.
// The imported image is the only deletion selection. Existing fixture cleanup
// checks exact labels/IDs even on failure; no ambient image prune is performed.
func verifyImageCacheUserNative(t *testing.T, ctx context.Context, r *Runtime, root string, c userauth.Client, peer sfcp.Peer, session access.Session) {
	t.Helper()
	original, err := c.ObserveContainer(ctx, peer, session, "tenant", containerops.Query{Schema: 1, Selection: containerops.Selection{App: "app", Service: "web"}, Kind: "inspect", MaxBytes: containerops.MaxOutput})
	if err != nil || original.Container == nil || original.Container.Detail == nil {
		t.Fatal("original Task image detail", err)
	}
	originalID := original.Container.Detail.ImageID
	protected, err := c.PlanImageCache(ctx, peer, session, imagecache.Query{Node: peer.ID, Images: []string{originalID}})
	if err != nil || len(protected.Images) != 1 || protected.DeleteReady() || protected.Images[0].Containers == 0 || protected.Images[0].References == 0 {
		t.Fatal("actual live Task image not protected", err)
	}
	hash := sha256.Sum256([]byte(root))
	tag := "rq4-cache-" + hex.EncodeToString(hash[:8])
	f := enginefixture.OpenPrepared(t, ctx, r.docker.Owner+"/cache-fixture", tag, nil, os.Getenv("SFC_DOCKER_TEST_BACKEND"))
	name := "sfc-" + tag
	created, err := f.Client.API.ContainerCreate(ctx, client.ContainerCreateOptions{Name: name, Config: &container.Config{Image: f.Image, Cmd: []string{"/backend"}, Labels: map[string]string{"org.sfc.owner": f.Client.Owner, "org.sfc.kind": "container"}}, HostConfig: &container.HostConfig{NetworkMode: "none"}})
	if err != nil {
		t.Fatal("owned stopped cache consumer", err)
	}
	stopped, err := c.PlanImageCache(ctx, peer, session, imagecache.Query{Node: peer.ID, Images: []string{f.Image}})
	if err != nil || len(stopped.Images) == 0 || stopped.DeleteReady() || stopped.Images[0].Containers == 0 {
		t.Fatal("stopped non-Task container was not protected", err)
	}
	if _, err = f.Client.API.ContainerRemove(ctx, created.ID, client.ContainerRemoveOptions{}); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		out, diag, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
		if err != nil {
			t.Fatal("actual cache CLI", args, err, string(diag))
		}
		return out
	}
	var plan imagecache.Plan
	if json.Unmarshal(run("node", "cache", "plan", peer.ID, "--images", f.Image), &plan) != nil || !plan.DeleteReady() || plan.Images[0].ID != f.Image {
		t.Fatal("unused owned image plan invalid")
	}
	args := []string{"node", "cache", "delete", peer.ID, "--images", f.Image, "--operation", "rq4-native-cache", "--request-id", "rq4-native-cache-request"}
	run(args...)
	var done *control.ImageCacheStatus
	for {
		status, e := c.ImageCacheStatus(ctx, peer, session, "rq4-native-cache")
		if e == nil && (status.State == "done" || status.State == "failed") {
			done = &status
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("original cache job did not settle", e, ctx.Err())
		case <-time.After(40 * time.Millisecond):
		}
	}
	if done.State != "done" || len(done.Parts) != 1 || (done.Parts[0].State != "removed" && done.Parts[0].State != "already-absent") {
		t.Fatal("original cache result", done)
	}
	if _, err = f.Client.API.ImageInspect(ctx, f.Image); !cerrdefs.IsNotFound(err) {
		t.Fatal("reported cache removal still exists", err)
	}
	if _, err = r.docker.API.ImageInspect(ctx, originalID); err != nil {
		t.Fatal("live Task image removed", err)
	}
	run(args...) // already absent: a new native plan would now fail
	run("node", "cache", "status", "rq4-native-cache")
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := r.controlPolicy.ImageCacheJobs(v.State)
	if err != nil || len(jobs.Records) != 1 {
		t.Fatal("cache replay created another operation", err)
	}
	t.Log("scope: actual remote control/User/CLI/owner Docker plan and explicit image removal, original live Task and stopped native references, real shared fence/result and same request replay; only the labeled temporary image selected")
}
