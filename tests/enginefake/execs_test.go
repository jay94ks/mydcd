// SPDX-License-Identifier: Apache-2.0

package enginefake

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/pkg/sfcp/enginemux"
	"github.com/jay94ks/seafield/pkg/sfcp/wire"
)

// killOver sends purpose 38 op kill over a real engine session, as sfcd does.
func killOver(t *testing.T, s *enginemux.Session, execID string) map[string]any {
	t.Helper()
	st, err := s.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	raw, _ := json.Marshal(map[string]any{"Schema": 1, "Op": "kill", "OpID": "k-" + execID, "ExecID": execID})
	if err := engineCodec.WriteFrame(st, wire.Frame{Purpose: sfcp.EngineExec, Kind: 1, Request: st.ID(), Fields: []wire.Field{{Tag: 1, Required: true, Value: raw}}}); err != nil {
		t.Fatal(err)
	}
	f, err := engineCodec.ReadFrame(st, 8+64<<10)
	if err != nil || f.Kind != 2 || len(f.Fields) != 1 {
		t.Fatal("kill answer", f, err)
	}
	var a map[string]any
	if err := json.Unmarshal(f.Fields[0].Value, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

// Execs as sfed supervises them: attached output, exec_die attributes, and
// the purpose 38 kill of the whole tree.
func TestExecSupervision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	e := start(t)
	sock := filepath.Join(e.Root(), "sfcd-engine.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	e.ConnectSFCD(sock)
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	s := enginemux.Server(conn)
	defer s.Close()

	c, err := engine.Open(ctx, e.Endpoint(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer c.API.Close()
	api := c.API
	e.AddImage(dockerspec.DockerOCIImage{}, "registry.test/x:1")
	created, err := api.ContainerCreate(ctx, client.ContainerCreateOptions{Config: &container.Config{Image: "registry.test/x:1"}, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	e.OnExec(func(_ string, argv []string) ExecPlan {
		switch argv[0] {
		case "hold":
			return ExecPlan{Hold: true, Stdout: []byte("started\n")}
		case "leftover":
			return ExecPlan{Leftover: true, Stdout: []byte("ok\n"), ExitCode: 0}
		case "plain":
			return ExecPlan{Unsupervised: true, Hold: true}
		}
		return ExecPlan{Stdout: []byte("out\n"), Stderr: []byte("err!\n"), ExitCode: 3}
	})
	evs := api.Events(ctx, client.EventsListOptions{Filters: client.Filters{}.Add("event", "exec_die")})
	die := func() events.Message {
		t.Helper()
		select {
		case m := <-evs.Messages:
			return m
		case err := <-evs.Err:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal("no exec_die")
		}
		return events.Message{}
	}
	run := func(argv ...string) (string, string, string) {
		t.Helper()
		x, err := api.ExecCreate(ctx, created.ID, client.ExecCreateOptions{Cmd: argv, AttachStdout: true, AttachStderr: true})
		if err != nil {
			t.Fatal(err)
		}
		at, err := api.ExecAttach(ctx, x.ID, client.ExecAttachOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer at.Close()
		var out, errOut bytes.Buffer
		if argv[0] == "hold" || argv[0] == "plain" {
			return x.ID, "", ""
		}
		if _, err := stdcopy.StdCopy(&out, &errOut, at.Reader); err != nil {
			t.Fatal(err)
		}
		return x.ID, out.String(), errOut.String()
	}

	// An exec that ends with its whole tree.
	id, out, errOut := run("check")
	m := die()
	a := m.Actor.Attributes
	if out != "out\n" || errOut != "err!\n" || a["execID"] != id || a["exitCode"] != "3" || a["seafield.tree"] != "ended" || a["seafield.stdout_bytes"] != "4" || a["seafield.stderr_bytes"] != "5" || a["seafield.killed"] != "" {
		t.Fatal("plain exec", out, errOut, a)
	}
	ins, err := api.ExecInspect(ctx, id, client.ExecInspectOptions{})
	if err != nil || ins.Running || ins.ExitCode != 3 {
		t.Fatal("inspect", ins, err)
	}
	if r := killOver(t, s, id); r["Result"] != "applied" || r["Tree"] != "ended" {
		t.Fatal("kill of an ended exec", r)
	}

	// Part of the tree outlives the first process; the kill ends it.
	id, _, _ = run("leftover")
	if a := die().Actor.Attributes; a["seafield.tree"] != "running" {
		t.Fatal("leftover", a)
	}
	if running, _ := e.ExecTree(id); !running {
		t.Fatal("leftover tree not running")
	}
	if r := killOver(t, s, id); r["Result"] != "applied" || r["Tree"] != "ended" {
		t.Fatal("kill leftover", r)
	}
	if running, _ := e.ExecTree(id); running {
		t.Fatal("leftover tree still running")
	}

	// A running exec killed: 137, killed=1, tree ended.
	id, _, _ = run("hold")
	if r := killOver(t, s, id); r["Result"] != "applied" || r["Tree"] != "ended" {
		t.Fatal("kill running", r)
	}
	if a := die().Actor.Attributes; a["exitCode"] != "137" || a["seafield.killed"] != "1" || a["seafield.tree"] != "ended" || a["seafield.stdout_bytes"] != "8" {
		t.Fatal("killed exec", a)
	}

	// Without a sub-cgroup: not-ready while it runs, no seafield.tree.
	id, _, _ = run("plain")
	if r := killOver(t, s, id); r["Result"] != "not-applied" || r["Reason"] != "not-ready" {
		t.Fatal("unsupervised kill", r)
	}
	if err := e.EndExec(id, 0); err != nil {
		t.Fatal(err)
	}
	if a := die().Actor.Attributes; a["seafield.tree"] != "" || a["exitCode"] != "0" {
		t.Fatal("unsupervised die", a)
	}
	if r := killOver(t, s, id); r["Result"] != "applied" {
		t.Fatal("unsupervised kill after end", r)
	}

	if r := killOver(t, s, "nope"); r["Result"] != "not-applied" || r["Reason"] != "not-found" {
		t.Fatal("unknown exec", r)
	}

	// The container ending ends its held execs.
	run("hold")
	if err := e.Exit(created.ID, 0); err != nil {
		t.Fatal(err)
	}
	if a := die().Actor.Attributes; a["exitCode"] != "137" || a["seafield.killed"] != "" {
		t.Fatal("exec on container exit", a)
	}
}

// Many execs at once: create, start (detached and attached), inspect.
func TestExecConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	e := start(t)
	c, err := engine.Open(ctx, e.Endpoint(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer c.API.Close()
	api := c.API
	e.AddImage(dockerspec.DockerOCIImage{}, "registry.test/x:1")
	created, err := api.ContainerCreate(ctx, client.ContainerCreateOptions{Config: &container.Config{Image: "registry.test/x:1"}, Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.ContainerStart(ctx, created.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	e.OnExec(func(string, []string) ExecPlan { return ExecPlan{Stdout: []byte("ok\n")} })
	errs := make(chan error, 8)
	for g := 0; g < 8; g++ {
		go func(g int) {
			for i := 0; i < 20; i++ {
				x, err := api.ExecCreate(ctx, created.ID, client.ExecCreateOptions{Cmd: []string{"true"}, AttachStdout: true})
				if err != nil {
					errs <- err
					return
				}
				if g%2 == 0 {
					_, err = api.ExecStart(ctx, x.ID, client.ExecStartOptions{Detach: true})
				} else {
					var at client.ExecAttachResult
					if at, err = api.ExecAttach(ctx, x.ID, client.ExecAttachOptions{}); err == nil {
						var out bytes.Buffer
						_, err = stdcopy.StdCopy(&out, &out, at.Reader)
						at.Close()
						if err == nil && out.String() != "ok\n" {
							err = fmt.Errorf("output %q", out.String())
						}
					}
				}
				if err != nil {
					errs <- err
					return
				}
				ins, err := api.ExecInspect(ctx, x.ID, client.ExecInspectOptions{})
				if err != nil || ins.Running {
					errs <- fmt.Errorf("inspect %v %v", ins, err)
					return
				}
			}
			errs <- nil
		}(g)
	}
	for g := 0; g < 8; g++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
