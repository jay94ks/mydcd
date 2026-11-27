// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/tests/enginefixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestRealBoundaryContainerObservationTTYLogs(t *testing.T) {
	tag, backend, manifest := os.Getenv("SFC_DOCKER_TEST_OWNER"), os.Getenv("SFC_DOCKER_TEST_BACKEND"), os.Getenv("SFC_NATIVE_MANIFEST")
	if tag == "" || backend == "" || manifest == "" {
		t.Skip("requires owned Docker rollback baseline and prebuilt backend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner := engine.Owner(sha256.Sum256([]byte(tag+"-tty-cluster")), sha256.Sum256([]byte(tag+"-tty-node")))
	raw, _ := json.Marshal(map[string]string{"Owner": owner, "Tag": tag + "-tty"})
	if err := os.WriteFile(manifest+".tty", raw, 0600); err != nil {
		t.Fatal(err)
	}
	f := enginefixture.OpenPrepared(t, ctx, owner, tag+"-tty", nil, backend)
	labels := map[string]string{"org.sfc.owner": owner, "org.sfc.kind": "container"}
	created, err := f.Client.API.ContainerCreate(ctx, client.ContainerCreateOptions{Config: &container.Config{Image: f.Image, Cmd: []string{"/backend"}, User: "10001:10001", Env: []string{"SFC_OBSERVATION_FIXTURE=1"}, Tty: true, Labels: labels}, HostConfig: &container.HostConfig{NetworkMode: "none", ReadonlyRootfs: true, Resources: container.Resources{Memory: 32 << 20, NanoCPUs: 100000000}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if _, err := f.Client.API.ContainerRemove(cleanup, created.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
			t.Error(err)
		}
	}()
	if _, err = f.Client.API.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	for {
		logs, err := f.Client.API.ContainerLogs(ctx, created.ID, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "200"})
		if err != nil {
			t.Fatal(err)
		}
		out, diagnostic, truncated, err := readObservationLogs(logs, true, 16384)
		if err != nil || len(diagnostic) != 0 || truncated {
			t.Fatal("raw TTY decoding", err)
		}
		if strings.Contains(string(out), "sfc-observation-stdout") && strings.Contains(string(out), "sfc-observation-stderr") {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("TTY startup output", ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}
