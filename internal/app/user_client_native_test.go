// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/tests/enginefixture"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestRQ2NonvoterContainerUsesPinnedVoter(t *testing.T) {
	if !filepath.IsAbs(os.Getenv("SFC_TEST_RQ2_AUTHCLIENT")) {
		t.Skip("requires explicitly prepared static authclient and local Docker")
	}
	testRealManagedJoin(t, false, "user-client")
}

func verifyNonvoterContainerClient(t *testing.T, ctx context.Context, runtime *Runtime, cluster [32]byte, voter, nonvoter sfcp.Peer, socket string, private ed25519.PrivateKey) {
	t.Helper()
	if err := runtime.Mesh.ListenUnix(socket); err != nil {
		t.Fatal(err)
	}
	local := nonvoter
	local.Endpoint = "unix:///sfcdp.sock"
	owner := "rq2-authclient-" + runtime.Identity.Actor()[:12]
	f := enginefixture.OpenPrepared(t, ctx, owner, owner, nil, os.Getenv("SFC_TEST_RQ2_AUTHCLIENT"))
	id, err := f.Client.IdentityDigest("container", "user-client", 1, sha256.Sum256([]byte("rq2-user-client")))
	if err != nil {
		t.Fatal(err)
	}
	created, err := f.Client.API.ContainerCreate(ctx, client.ContainerCreateOptions{Name: id.Name, Config: &container.Config{Image: f.Image, Cmd: []string{"/backend"}, Labels: id.Labels, OpenStdin: true, StdinOnce: true, AttachStdin: true, AttachStdout: true, AttachStderr: true}, HostConfig: &container.HostConfig{NetworkMode: "host", ReadonlyRootfs: true, Binds: []string{socket + ":/sfcdp.sock:ro"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := f.Client.API.ContainerRemove(clean, created.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true}); err != nil {
			t.Error("authclient exact-container rollback", err)
		}
	})
	attached, err := f.Client.API.ContainerAttach(ctx, created.ID, client.ContainerAttachOptions{Stream: true, Stdin: true, Stdout: true, Stderr: true})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	stop := context.AfterFunc(ctx, func() { attached.Close() })
	defer stop()
	if _, err = f.Client.API.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(struct {
		Cluster      [32]byte
		Local, Voter sfcp.Peer
		Username     string
		PrivateKey   []byte
	}{cluster, local, voter, "admin", private})
	if err != nil {
		t.Fatal(err)
	}
	_, err = attached.Conn.Write(input)
	clear(input)
	if err != nil {
		t.Fatal(err)
	}
	if err = attached.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	if _, err = stdcopy.StdCopy(&out, &diagnostic, io.LimitReader(attached.Reader, 24<<10)); err != nil {
		t.Fatal(err)
	}
	wait := f.Client.API.ContainerWait(ctx, created.ID, client.ContainerWaitOptions{Condition: container.WaitConditionNotRunning})
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case result := <-wait.Result:
		if result.StatusCode != 0 {
			t.Fatal("authclient exited", result.StatusCode)
		}
	case err := <-wait.Error:
		t.Fatal(err)
	}
	var result struct {
		User, LocalCode, Voter string
		Issuer                 [32]byte
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || result.User != "admin" || result.LocalCode != "relayed" || result.Issuer != [32]byte(voter.Key) || result.Voter != voter.ID {
		t.Fatal("non-voter container/voter authentication contract")
	}
	t.Log("actual non-voter socket shared into Docker container relays login to the voter; exact pinned voter issues user session over SFCP")
}
