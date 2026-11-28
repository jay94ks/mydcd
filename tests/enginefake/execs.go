// SPDX-License-Identifier: Apache-2.0

package enginefake

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/moby/moby/api/types/container"
)

// Execs as sfed runs them (seafield/docs/additions.md "exec 프로세스 묶음
// 감독", patch 0020): each exec has its own sub-cgroup, exec_die reports
// seafield.stdout_bytes, seafield.stderr_bytes, seafield.tree and
// seafield.killed, and purpose 38 op "kill" kills the whole tree. The real
// engine is the reference; change this when sfed changes.

// ExecPlan is how the fake runs one exec. The zero plan exits 0 at once
// with no output.
type ExecPlan struct {
	Stdout, Stderr []byte
	ExitCode       int
	// Hold keeps the first process running until EndExec, a purpose 38
	// kill, or the container ending.
	Hold bool
	// Leftover leaves part of the tree running after the first process
	// ends (exec_die seafield.tree=running) until a kill or the container
	// ending.
	Leftover bool
	// Unsupervised runs the exec without a sub-cgroup, as sfed does when
	// sfe-runc is missing: exec_die has no seafield.tree and a kill while
	// it runs answers not-ready.
	Unsupervised bool
}

type execProcess struct {
	ID, Container string
	Config        container.ExecCreateRequest
	Plan          ExecPlan
	Started       bool
	Running       bool
	ExitCode      int
	// leftover is true while part of the tree runs after the first process.
	leftover bool
	killed   bool
	done     chan struct{}
	end      func(code int)
}

// OnExec sets how later execs run. fn gets the container ID and argv.
func (e *Engine) OnExec(fn func(container string, argv []string) ExecPlan) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.execPlan = fn
}

// EndExec ends a held exec's first process with code.
func (e *Engine) EndExec(id string, code int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	x := e.execs[id]
	if x == nil || !x.Running || x.end == nil {
		return fmt.Errorf("no running exec %s", id)
	}
	x.end(code)
	return nil
}

// ExecTree reports whether any process of the exec still runs.
func (e *Engine) ExecTree(id string) (running bool, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	x := e.execs[id]
	if x == nil {
		return false, false
	}
	return x.Running || x.leftover, true
}

func execRoutes() {
	handle("POST", "/containers/*/exec", (*Engine).execCreate)
	handle("GET", "/exec/*/json", (*Engine).execInspect)
	handle("POST", "/exec/*/start", (*Engine).execStart)
	handle("POST", "/exec/*/resize", func(_ *Engine, w http.ResponseWriter, _ *http.Request, _ []string) { w.WriteHeader(http.StatusCreated) })
}

func (e *Engine) execCreate(w http.ResponseWriter, r *http.Request, a []string) {
	var req container.ExecCreateRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	e.withContainer(w, a[0], func(c *ctr) {
		if !c.State.Running {
			writeError(w, http.StatusConflict, "container "+c.ID+" is not running")
			return
		}
		x := &execProcess{ID: newID(), Container: c.ID, Config: req}
		e.execs[x.ID] = x
		attrs := c.attributes()
		attrs["execID"] = x.ID
		e.emit("container", "exec_create: "+strings.Join(req.Cmd, " "), c.ID, attrs)
		writeJSON(w, http.StatusCreated, map[string]string{"Id": x.ID})
	})
}

func (e *Engine) execInspect(w http.ResponseWriter, _ *http.Request, a []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	x := e.execs[a[0]]
	if x == nil {
		writeError(w, http.StatusNotFound, "No such exec instance: "+a[0])
		return
	}
	var exit *int
	if x.Started && !x.Running {
		code := x.ExitCode
		exit = &code
	}
	pid := 0
	if x.Running {
		pid = 4242
	}
	writeJSON(w, http.StatusOK, map[string]any{"ID": x.ID, "ContainerID": x.Container, "Running": x.Running, "ExitCode": exit, "ProcessConfig": map[string]any{"entrypoint": firstOf(nil, x.Config.Cmd), "arguments": restOf(nil, x.Config.Cmd), "tty": x.Config.Tty, "user": x.Config.User}, "OpenStdin": x.Config.AttachStdin, "OpenStdout": x.Config.AttachStdout, "OpenStderr": x.Config.AttachStderr, "Pid": pid})
}

// execStart runs an exec by its plan. A detached start answers at once; an
// attached one takes the connection over (as the engine's upgrade) and
// streams the output, closing it when the first process ends.
func (e *Engine) execStart(w http.ResponseWriter, r *http.Request, a []string) {
	var req container.ExecStartRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	e.mu.Lock()
	x := e.execs[a[0]]
	if x == nil {
		e.mu.Unlock()
		writeError(w, http.StatusNotFound, "No such exec instance: "+a[0])
		return
	}
	if x.Started {
		e.mu.Unlock()
		writeError(w, http.StatusConflict, "exec command "+x.ID+" is already running")
		return
	}
	c := e.containers[x.Container]
	if c == nil || !c.State.Running {
		e.mu.Unlock()
		writeError(w, http.StatusConflict, "container "+x.Container+" is not running")
		return
	}
	if e.execPlan != nil {
		x.Plan = e.execPlan(x.Container, append([]string(nil), x.Config.Cmd...))
	}
	x.Started, x.Running, x.done = true, true, make(chan struct{})
	attrs := c.attributes()
	attrs["execID"] = x.ID
	e.emit("container", "exec_start: "+strings.Join(x.Config.Cmd, " "), c.ID, attrs)
	attached := !req.Detach
	x.end = func(code int) { e.execDie(x, code, attached) }
	done := x.done
	if !x.Plan.Hold {
		// The first process ends at once (under e.mu); an attached stream
		// still writes the output, then sees done closed.
		x.end(x.Plan.ExitCode)
	}
	plan, tty := x.Plan, x.Config.Tty || req.Tty
	out, errOut := x.Config.AttachStdout, x.Config.AttachStderr
	if !attached {
		e.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		e.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "no hijack")
		return
	}
	conn, buf, err := hj.Hijack()
	e.mu.Unlock()
	if err != nil {
		return
	}
	go streamExec(conn, buf, done, plan, tty, out, errOut)
}

// streamExec writes an attached exec's output and closes the connection
// when the first process has ended.
func streamExec(conn net.Conn, buf *bufio.ReadWriter, done <-chan struct{}, plan ExecPlan, tty, out, errOut bool) {
	defer conn.Close()
	ctype := "application/vnd.docker.multiplexed-stream"
	if tty {
		ctype = "application/vnd.docker.raw-stream"
	}
	fmt.Fprintf(buf, "HTTP/1.1 101 UPGRADED\r\nContent-Type: %s\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n", ctype)
	frame := func(stream byte, p []byte) {
		if len(p) == 0 {
			return
		}
		if tty {
			_, _ = buf.Write(p)
			return
		}
		var h [8]byte
		h[0] = stream
		binary.BigEndian.PutUint32(h[4:], uint32(len(p)))
		_, _ = buf.Write(h[:])
		_, _ = buf.Write(p)
	}
	if out {
		frame(1, plan.Stdout)
	}
	if errOut {
		frame(2, plan.Stderr)
	}
	_ = buf.Flush()
	<-done
}

// execDie ends x's first process with code and emits exec_die as sfed
// does. The caller holds e.mu.
func (e *Engine) execDie(x *execProcess, code int, attached bool) {
	if !x.Running {
		return
	}
	x.Running, x.ExitCode, x.end = false, code, nil
	x.leftover = x.Plan.Leftover && !x.killed && !x.Plan.Unsupervised
	attrs := map[string]string{"execID": x.ID, "exitCode": strconv.Itoa(code)}
	if c := e.containers[x.Container]; c != nil {
		for k, v := range c.attributes() {
			attrs[k] = v
		}
	}
	var outN, errN int
	if attached && x.Config.AttachStdout {
		outN = len(x.Plan.Stdout)
	}
	if attached && x.Config.AttachStderr {
		errN = len(x.Plan.Stderr)
	}
	attrs["seafield.stdout_bytes"] = strconv.Itoa(outN)
	attrs["seafield.stderr_bytes"] = strconv.Itoa(errN)
	if !x.Plan.Unsupervised {
		attrs["seafield.tree"] = "ended"
		if x.leftover {
			attrs["seafield.tree"] = "running"
		}
	}
	if x.killed {
		attrs["seafield.killed"] = "1"
	}
	close(x.done)
	e.emit("container", "exec_die", x.Container, attrs)
}

// endExecs ends every exec of c, as the container's cgroup going away does.
// The caller holds e.mu.
func (e *Engine) endExecs(c *ctr) {
	for _, x := range e.execs {
		if x.Container != c.ID {
			continue
		}
		x.leftover = false
		if x.Running {
			x.Plan.Leftover = false
			e.execDie(x, 137, x.end != nil)
		}
	}
}

// killExec answers purpose 38 op "kill" as execsup.Serve does.
func (e *Engine) killExec(id string) (result, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	x := e.execs[id]
	if x == nil {
		return "not-applied", "not-found"
	}
	if x.Plan.Unsupervised {
		if x.Running {
			return "not-applied", "not-ready"
		}
		return "applied", ""
	}
	if x.Running || x.leftover {
		x.killed = true
	}
	x.leftover = false
	if x.Running {
		x.Plan.Leftover = false
		e.execDie(x, 137, true)
	}
	return "applied", ""
}
