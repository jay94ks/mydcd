// SPDX-License-Identifier: Apache-2.0

package enginefake

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	apinetwork "github.com/moby/moby/api/types/network"
)

type ctr struct {
	ID, Name   string
	Created    time.Time
	Config     *container.Config
	HostConfig *container.HostConfig
	State      container.State
	Networks   map[string]*apinetwork.EndpointSettings // by network name
	Logs       []LogLine
	// logSeq numbers queued lines; logAcked is what sfcd acked (purpose 34).
	logSeq, logAcked uint64
	Restarts         int
	// waiters are closed when the container stops running.
	waiters []chan struct{}
	// sandbox is the running container's namespace (Host).
	sandbox *sandbox
}

// LogLine is one line of a container's output.
type LogLine struct {
	Time   time.Time
	Stderr bool
	Text   string
	seq    uint64
}

func containerRoutes() {
	handle("GET", "/containers/json", (*Engine).containerList)
	handle("POST", "/containers/create", (*Engine).containerCreate)
	handle("GET", "/containers/*/json", (*Engine).containerInspect)
	handle("POST", "/containers/*/start", (*Engine).containerStart)
	handle("POST", "/containers/*/stop", (*Engine).containerStop)
	handle("POST", "/containers/*/kill", (*Engine).containerStop)
	handle("POST", "/containers/*/restart", (*Engine).containerRestart)
	handle("POST", "/containers/*/wait", (*Engine).containerWait)
	handle("POST", "/containers/*/rename", (*Engine).containerRename)
	handle("POST", "/containers/*/update", (*Engine).containerUpdate)
	handle("POST", "/containers/*/pause", func(e *Engine, w http.ResponseWriter, r *http.Request, a []string) { e.containerPause(w, r, a, true) })
	handle("POST", "/containers/*/unpause", func(e *Engine, w http.ResponseWriter, r *http.Request, a []string) { e.containerPause(w, r, a, false) })
	handle("GET", "/containers/*/logs", (*Engine).containerLogs)
	handle("GET", "/containers/*/stats", (*Engine).containerStats)
	handle("GET", "/containers/*/top", (*Engine).containerTop)
	handle("DELETE", "/containers/*", (*Engine).containerRemove)
}

// lookupContainer finds a container by ID, unique ID prefix or name. The
// caller holds e.mu.
func (e *Engine) lookupContainer(ref string) *ctr {
	if c, ok := e.containers[ref]; ok {
		return c
	}
	name := "/" + strings.TrimPrefix(ref, "/")
	var found *ctr
	for _, c := range e.containers {
		if c.Name == name {
			return c
		}
		if len(ref) >= 12 && strings.HasPrefix(c.ID, ref) {
			if found != nil {
				return nil
			}
			found = c
		}
	}
	return found
}

func (e *Engine) withContainer(w http.ResponseWriter, ref string, fn func(*ctr)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.lookupContainer(ref)
	if c == nil {
		writeError(w, http.StatusNotFound, "No such container: "+ref)
		return
	}
	fn(c)
}

func (e *Engine) containerCreate(w http.ResponseWriter, r *http.Request, _ []string) {
	var req container.CreateRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Config == nil {
		req.Config = &container.Config{}
	}
	if req.HostConfig == nil {
		req.HostConfig = &container.HostConfig{}
	}
	name := r.URL.Query().Get("name")
	e.mu.Lock()
	defer e.mu.Unlock()
	if name != "" && e.lookupContainer(name) != nil && e.lookupContainer(name).Name == "/"+name {
		writeError(w, http.StatusConflict, fmt.Sprintf("Conflict. The container name %q is already in use", "/"+name))
		return
	}
	img := e.lookupImage(req.Config.Image)
	if img == nil {
		writeError(w, http.StatusNotFound, "No such image: "+req.Config.Image)
		return
	}
	mergeImageConfig(req.Config, img)
	for _, m := range req.HostConfig.Mounts {
		if m.Type == mount.TypeVolume && m.Source != "" && e.volumes[m.Source] == nil {
			if _, err := e.createVolume(m.Source, "local", nil, nil); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
	}
	id := newID()
	if name == "" {
		name = id[:12]
	}
	c := &ctr{ID: id, Name: "/" + name, Created: time.Now().UTC(), Config: req.Config, HostConfig: req.HostConfig, State: container.State{Status: container.StateCreated}, Networks: map[string]*apinetwork.EndpointSettings{}}
	mode := string(req.HostConfig.NetworkMode)
	if req.NetworkingConfig != nil {
		for n, s := range req.NetworkingConfig.EndpointsConfig {
			if err := e.attach(c, n, s); err != nil {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
		}
	}
	if len(c.Networks) == 0 && mode != "none" && mode != "host" && !strings.HasPrefix(mode, "container:") {
		if mode == "" || mode == "default" {
			mode = "bridge"
		}
		if err := e.attach(c, mode, nil); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
	}
	e.containers[id] = c
	e.emit("container", "create", id, c.attributes())
	writeJSON(w, http.StatusCreated, map[string]any{"Id": id, "Warnings": []string{}})
}

func (c *ctr) attributes() map[string]string {
	a := map[string]string{"name": strings.TrimPrefix(c.Name, "/"), "image": c.Config.Image}
	for k, v := range c.Config.Labels {
		a[k] = v
	}
	return a
}

// attach connects c to network ref with an address from its first subnet.
// The caller holds e.mu.
func (e *Engine) attach(c *ctr, ref string, s *apinetwork.EndpointSettings) error {
	n := e.lookupNetwork(ref)
	if n == nil {
		return fmt.Errorf("network %s not found", ref)
	}
	if _, ok := c.Networks[n.Name]; ok {
		return nil
	}
	es := &apinetwork.EndpointSettings{}
	if s != nil {
		cp := *s
		es = &cp
	}
	es.NetworkID, es.EndpointID = n.ID, newID()
	if es.IPAMConfig != nil && es.IPAMConfig.IPv4Address.IsValid() {
		es.IPAddress = es.IPAMConfig.IPv4Address
	} else if ip, bits, gw, ok := n.allocate(); ok {
		es.IPAddress, es.IPPrefixLen, es.Gateway = ip, bits, gw
	}
	if p, ok := n.prefix(); ok {
		es.IPPrefixLen = p.Bits()
		if gw, ok := n.gateway(); ok {
			es.Gateway = gw
		}
	}
	c.Networks[n.Name] = es
	n.Endpoints[c.ID] = endpoint{Name: strings.TrimPrefix(c.Name, "/"), EndpointID: es.EndpointID, IP: es.IPAddress, Bits: es.IPPrefixLen}
	return nil
}

func (e *Engine) detach(c *ctr, n *netw) {
	delete(c.Networks, n.Name)
	delete(n.Endpoints, c.ID)
}

func (e *Engine) inspectOf(c *ctr) container.InspectResponse {
	st := c.State
	out := container.InspectResponse{ID: c.ID, Created: stamp(c.Created), Path: firstOf(c.Config.Entrypoint, c.Config.Cmd), Args: restOf(c.Config.Entrypoint, c.Config.Cmd), State: &st, Image: e.imageID(c.Config.Image), Name: c.Name, RestartCount: c.Restarts, Driver: "overlay2", Platform: "linux", HostConfig: c.HostConfig, Config: c.Config, LogPath: "/enginefake/" + c.ID + ".log"}
	out.Mounts = e.mountsOf(c)
	out.NetworkSettings = &container.NetworkSettings{SandboxID: c.ID, Networks: c.Networks}
	if pid, key := c.sandboxOf(); key != "" {
		st.Pid, out.NetworkSettings.SandboxKey = pid, key
	}
	return out
}

func firstOf(entry, cmd []string) string {
	all := append(append([]string{}, entry...), cmd...)
	if len(all) == 0 {
		return ""
	}
	return all[0]
}

func restOf(entry, cmd []string) []string {
	all := append(append([]string{}, entry...), cmd...)
	if len(all) < 2 {
		return []string{}
	}
	return all[1:]
}

// mountsOf reports mounts as the daemon does: volumes resolve to their
// mountpoint. The caller holds e.mu.
func (e *Engine) mountsOf(c *ctr) []container.MountPoint {
	var out []container.MountPoint
	for _, m := range c.HostConfig.Mounts {
		mp := container.MountPoint{Type: m.Type, Source: m.Source, Destination: m.Target, RW: !m.ReadOnly}
		if m.Type == mount.TypeVolume {
			mp.Name, mp.Driver = m.Source, "local"
			if v := e.volumes[m.Source]; v != nil {
				mp.Source = v.Mountpoint
			}
		}
		out = append(out, mp)
	}
	for _, b := range c.HostConfig.Binds {
		parts := strings.Split(b, ":")
		if len(parts) < 2 {
			continue
		}
		mp := container.MountPoint{Type: mount.TypeBind, Source: parts[0], Destination: parts[1], RW: len(parts) < 3 || !strings.Contains(parts[2], "ro")}
		if !strings.HasPrefix(parts[0], "/") {
			mp.Type, mp.Name, mp.Driver = mount.TypeVolume, parts[0], "local"
			if v := e.volumes[parts[0]]; v != nil {
				mp.Source = v.Mountpoint
			}
		}
		out = append(out, mp)
	}
	return out
}

func (e *Engine) containerInspect(w http.ResponseWriter, _ *http.Request, a []string) {
	e.withContainer(w, a[0], func(c *ctr) { writeJSON(w, http.StatusOK, e.inspectOf(c)) })
}

func (e *Engine) containerList(w http.ResponseWriter, r *http.Request, _ []string) {
	f, err := parseFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	all := r.URL.Query().Get("all") == "1" || r.URL.Query().Get("all") == "true"
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []container.Summary{}
	for _, c := range e.containers {
		if !all && !c.State.Running {
			continue
		}
		if !f.labels(c.Config.Labels) ||
			!f.oneOf("id", func(v string) bool { return strings.HasPrefix(c.ID, v) }) ||
			!f.oneOf("name", func(v string) bool { return strings.Contains(c.Name, strings.TrimPrefix(v, "/")) }) ||
			!f.oneOf("status", func(v string) bool { return v == string(c.State.Status) }) {
			continue
		}
		s := container.Summary{ID: c.ID, Names: []string{c.Name}, Image: c.Config.Image, ImageID: e.imageID(c.Config.Image), Command: strings.Join(append(append([]string{}, c.Config.Entrypoint...), c.Config.Cmd...), " "), Created: c.Created.Unix(), Labels: c.Config.Labels, State: c.State.Status, Status: string(c.State.Status), Mounts: e.mountsOf(c), NetworkSettings: &container.NetworkSettingsSummary{Networks: c.Networks}}
		s.HostConfig.NetworkMode = string(c.HostConfig.NetworkMode)
		out = append(out, s)
	}
	writeJSON(w, http.StatusOK, out)
}

func (e *Engine) containerStart(w http.ResponseWriter, _ *http.Request, a []string) {
	e.withContainer(w, a[0], func(c *ctr) {
		if c.State.Running {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if err := e.run(c); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// run marks c running (in host mode, in its own namespace). The caller holds
// e.mu.
func (e *Engine) run(c *ctr) error {
	pid := 1000 + len(e.containers)
	if e.host {
		if err := e.startSandbox(c); err != nil {
			return fmt.Errorf("container namespace: %w", err)
		}
		pid = c.sandbox.pid()
	}
	c.State = container.State{Status: container.StateRunning, Running: true, Pid: pid, StartedAt: stamp(time.Now()), FinishedAt: "0001-01-01T00:00:00Z"}
	if c.Config.Healthcheck != nil && len(c.Config.Healthcheck.Test) > 0 && c.Config.Healthcheck.Test[0] != "NONE" {
		c.State.Health = &container.Health{Status: container.Healthy}
	}
	e.emit("container", "start", c.ID, c.attributes())
	return nil
}

// exit marks c exited with code. The caller holds e.mu.
func (e *Engine) exit(c *ctr, code int, oom bool) {
	if !c.State.Running && c.State.Status != container.StatePaused {
		return
	}
	e.endExecs(c)
	e.stopSandbox(c)
	c.State.Status, c.State.Running, c.State.Paused, c.State.Pid = container.StateExited, false, false, 0
	c.State.ExitCode, c.State.OOMKilled, c.State.FinishedAt = code, oom, stamp(time.Now())
	c.State.Health = nil
	attrs := c.attributes()
	attrs["exitCode"] = strconv.Itoa(code)
	e.emit("container", "die", c.ID, attrs)
	for _, ch := range c.waiters {
		close(ch)
	}
	c.waiters = nil
}

func (e *Engine) containerStop(w http.ResponseWriter, r *http.Request, a []string) {
	e.withContainer(w, a[0], func(c *ctr) {
		if !c.State.Running {
			if strings.HasSuffix(r.URL.Path, "/kill") {
				writeError(w, http.StatusConflict, "Container "+c.ID+" is not running")
				return
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		// A stop signal ends the process cleanly; kill is SIGKILL (137).
		code := 0
		if strings.HasSuffix(r.URL.Path, "/kill") {
			code = 137
		}
		e.exit(c, code, false)
		e.emit("container", "stop", c.ID, c.attributes())
		w.WriteHeader(http.StatusNoContent)
	})
}

func (e *Engine) containerRestart(w http.ResponseWriter, _ *http.Request, a []string) {
	e.withContainer(w, a[0], func(c *ctr) {
		e.exit(c, 0, false)
		c.Restarts++
		if err := e.run(c); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (e *Engine) containerWait(w http.ResponseWriter, r *http.Request, a []string) {
	e.mu.Lock()
	c := e.lookupContainer(a[0])
	if c == nil {
		e.mu.Unlock()
		writeError(w, http.StatusNotFound, "No such container: "+a[0])
		return
	}
	condition := r.URL.Query().Get("condition")
	var ch chan struct{}
	if c.State.Running || c.State.Paused || condition == "next-exit" || condition == "removed" {
		ch = make(chan struct{})
		c.waiters = append(c.waiters, ch)
	}
	e.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	if ch != nil {
		select {
		case <-ch:
		case <-r.Context().Done():
			return
		}
	}
	e.mu.Lock()
	code := c.State.ExitCode
	e.mu.Unlock()
	_, _ = fmt.Fprintf(w, `{"StatusCode":%d}`+"\n", code)
}

func (e *Engine) containerRename(w http.ResponseWriter, r *http.Request, a []string) {
	e.withContainer(w, a[0], func(c *ctr) {
		name := "/" + strings.TrimPrefix(r.URL.Query().Get("name"), "/")
		if other := e.lookupContainer(name); other != nil && other != c && other.Name == name {
			writeError(w, http.StatusConflict, "name in use")
			return
		}
		c.Name = name
		e.emit("container", "rename", c.ID, c.attributes())
		w.WriteHeader(http.StatusNoContent)
	})
}

func (e *Engine) containerUpdate(w http.ResponseWriter, r *http.Request, a []string) {
	var req container.UpdateConfig
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	e.withContainer(w, a[0], func(c *ctr) {
		h := c.HostConfig
		if req.NanoCPUs != 0 {
			h.NanoCPUs = req.NanoCPUs
		}
		if req.Memory != 0 {
			h.Memory = req.Memory
		}
		if req.MemorySwap != 0 {
			h.MemorySwap = req.MemorySwap
		}
		if req.PidsLimit != nil {
			h.PidsLimit = req.PidsLimit
		}
		if req.RestartPolicy.Name != "" {
			h.RestartPolicy = req.RestartPolicy
		}
		e.emit("container", "update", c.ID, c.attributes())
		writeJSON(w, http.StatusOK, map[string]any{"Warnings": []string{}})
	})
}

func (e *Engine) containerPause(w http.ResponseWriter, _ *http.Request, a []string, pause bool) {
	e.withContainer(w, a[0], func(c *ctr) {
		switch {
		case pause && c.State.Running:
			c.State.Paused, c.State.Status = true, container.StatePaused
			e.emit("container", "pause", c.ID, c.attributes())
		case !pause && c.State.Paused:
			c.State.Paused, c.State.Status = false, container.StateRunning
			e.emit("container", "unpause", c.ID, c.attributes())
		default:
			writeError(w, http.StatusConflict, "Container "+c.ID+" is not in the right state")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (e *Engine) containerRemove(w http.ResponseWriter, r *http.Request, a []string) {
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"
	removeVolumes := r.URL.Query().Get("v") == "1" || r.URL.Query().Get("v") == "true"
	e.withContainer(w, a[0], func(c *ctr) {
		if c.State.Running && !force {
			writeError(w, http.StatusConflict, "You cannot remove a running container "+c.ID+". Stop the container before attempting removal or force remove")
			return
		}
		e.exit(c, 137, false)
		for _, n := range e.networks {
			delete(n.Endpoints, c.ID)
		}
		delete(e.containers, c.ID)
		if removeVolumes {
			for _, m := range c.HostConfig.Mounts {
				if v := e.volumes[m.Source]; m.Type == mount.TypeVolume && v != nil && v.Anonymous && e.volumeRefs(v.Name) == 0 {
					e.removeVolume(v)
				}
			}
		}
		e.emit("container", "destroy", c.ID, c.attributes())
		w.WriteHeader(http.StatusNoContent)
	})
}

func (e *Engine) containerLogs(w http.ResponseWriter, r *http.Request, a []string) {
	q := r.URL.Query()
	stdout, stderr := q.Get("stdout") == "1" || q.Get("stdout") == "true", q.Get("stderr") == "1" || q.Get("stderr") == "true"
	timestamps := q.Get("timestamps") == "1" || q.Get("timestamps") == "true"
	var lines []LogLine
	tty := false
	found := false
	e.mu.Lock()
	if c := e.lookupContainer(a[0]); c != nil {
		found, tty = true, c.Config.Tty
		lines = append(lines, c.Logs...)
	}
	e.mu.Unlock()
	if !found {
		writeError(w, http.StatusNotFound, "No such container: "+a[0])
		return
	}
	if tail := q.Get("tail"); tail != "" && tail != "all" {
		if n, err := strconv.Atoi(tail); err == nil && n >= 0 && n < len(lines) {
			lines = lines[len(lines)-n:]
		}
	}
	if since := q.Get("since"); since != "" {
		if t, err := parseUnix(since); err == nil {
			lines = filterLines(lines, func(l LogLine) bool { return !l.Time.Before(t) })
		}
	}
	if until := q.Get("until"); until != "" {
		if t, err := parseUnix(until); err == nil {
			lines = filterLines(lines, func(l LogLine) bool { return l.Time.Before(t) })
		}
	}
	if tty {
		w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
	} else {
		w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
	}
	w.WriteHeader(http.StatusOK)
	for _, l := range lines {
		if l.Stderr && !stderr || !l.Stderr && !stdout {
			continue
		}
		text := l.Text
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		if timestamps {
			text = l.Time.UTC().Format(time.RFC3339Nano) + " " + text
		}
		if tty {
			_, _ = w.Write([]byte(text))
			continue
		}
		var h [8]byte
		h[0] = 1
		if l.Stderr {
			h[0] = 2
		}
		binary.BigEndian.PutUint32(h[4:], uint32(len(text)))
		_, _ = w.Write(append(h[:], text...))
	}
}

func filterLines(in []LogLine, keep func(LogLine) bool) []LogLine {
	var out []LogLine
	for _, l := range in {
		if keep(l) {
			out = append(out, l)
		}
	}
	return out
}

func parseUnix(s string) (time.Time, error) {
	sec, frac, _ := strings.Cut(s, ".")
	n, err := strconv.ParseInt(sec, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	var nsec int64
	if frac != "" {
		frac = (frac + "000000000")[:9]
		if nsec, err = strconv.ParseInt(frac, 10, 64); err != nil {
			return time.Time{}, err
		}
	}
	return time.Unix(n, nsec), nil
}

// Test controls.

// Containers lists container IDs whose labels include every given label.
func (e *Engine) Containers(labels map[string]string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for id, c := range e.containers {
		ok := true
		for k, v := range labels {
			if c.Config.Labels[k] != v {
				ok = false
			}
		}
		if ok {
			out = append(out, id)
		}
	}
	return out
}

// Running lists the IDs of the running containers.
func (e *Engine) Running() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for id, c := range e.containers {
		if c.State.Running {
			out = append(out, id)
		}
	}
	return out
}

// Env returns a container's environment as created (image defaults merged).
func (e *Engine) Env(ref string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c := e.lookupContainer(ref); c != nil && c.Config != nil {
		return slices.Clone(c.Config.Env)
	}
	return nil
}

// Exit ends a running container's process with code (as if it crashed or
// finished).
func (e *Engine) Exit(ref string, code int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.lookupContainer(ref)
	if c == nil {
		return fmt.Errorf("no container %s", ref)
	}
	e.exit(c, code, false)
	return nil
}

// Log appends an output line to a container.
func (e *Engine) Log(ref string, stderr bool, text string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.lookupContainer(ref)
	if c == nil {
		return fmt.Errorf("no container %s", ref)
	}
	c.logSeq++
	c.Logs = append(c.Logs, LogLine{Time: time.Now().UTC(), Stderr: stderr, Text: text, seq: c.logSeq})
	// As the seafield-queue log driver: a data-free "lines stored" event.
	e.emit("container", "seafield.logs", c.ID, c.attributes())
	return nil
}

// SetHealth sets a running container's health status (healthy, unhealthy,
// starting).
func (e *Engine) SetHealth(ref string, status container.HealthStatus) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.lookupContainer(ref)
	if c == nil || !c.State.Running {
		return fmt.Errorf("no running container %s", ref)
	}
	c.State.Health = &container.Health{Status: status}
	e.emit("container", "health_status: "+string(status), c.ID, c.attributes())
	return nil
}

// mergeImageConfig fills a create request from the image as the daemon
// does: an Entrypoint of [""] clears the image's, an unset one inherits it
// (and then an unset Cmd inherits the image's Cmd), image environment
// variables the request does not set are appended, and an empty user,
// working directory, stop signal or health check comes from the image.
func mergeImageConfig(c *container.Config, img *img) {
	ic := img.Config.Config
	switch {
	case len(c.Entrypoint) == 1 && c.Entrypoint[0] == "":
		c.Entrypoint = nil
	case len(c.Entrypoint) == 0:
		c.Entrypoint = ic.Entrypoint
		if len(c.Cmd) == 0 {
			c.Cmd = ic.Cmd
		}
	}
	if len(c.Cmd) == 1 && c.Cmd[0] == "" {
		c.Cmd = nil
	}
	for _, kv := range ic.Env {
		k, _, _ := strings.Cut(kv, "=")
		set := false
		for _, own := range c.Env {
			if ok, _, _ := strings.Cut(own, "="); ok == k {
				set = true
			}
		}
		if !set {
			c.Env = append(c.Env, kv)
		}
	}
	if c.User == "" {
		c.User = ic.User
	}
	if c.WorkingDir == "" {
		c.WorkingDir = ic.WorkingDir
	}
	if c.StopSignal == "" {
		c.StopSignal = ic.StopSignal
	}
	if c.Healthcheck == nil && ic.Healthcheck != nil {
		h := *ic.Healthcheck
		c.Healthcheck = &h
	}
	for k, v := range ic.Labels {
		if c.Labels == nil {
			c.Labels = map[string]string{}
		}
		if _, ok := c.Labels[k]; !ok {
			c.Labels[k] = v
		}
	}
}

// containerStats answers one sample (stream=false) with a previous sample a
// second earlier: 10% of one CPU, 32 MiB of memory against the limit.
func (e *Engine) containerStats(w http.ResponseWriter, r *http.Request, a []string) {
	if q := r.URL.Query().Get("stream"); q != "0" && q != "false" {
		e.notImplemented(w, "GET /containers/*/stats (stream)")
		return
	}
	e.withContainer(w, a[0], func(c *ctr) {
		now := time.Now().UTC()
		out := map[string]any{"id": c.ID, "name": c.Name, "read": now.Format(time.RFC3339Nano), "preread": "0001-01-01T00:00:00Z", "num_procs": 0}
		if c.State.Running {
			const second = uint64(time.Second)
			up := uint64(now.Sub(c.Created)) + second
			limit := uint64(c.HostConfig.Memory)
			if limit == 0 {
				limit = uint64(e.MemTotal)
			}
			out["preread"] = now.Add(-time.Second).Format(time.RFC3339Nano)
			out["cpu_stats"] = map[string]any{"cpu_usage": map[string]any{"total_usage": up / 10}, "system_cpu_usage": up * uint64(e.NCPU), "online_cpus": e.NCPU}
			out["precpu_stats"] = map[string]any{"cpu_usage": map[string]any{"total_usage": (up - second) / 10}, "system_cpu_usage": (up - second) * uint64(e.NCPU), "online_cpus": e.NCPU}
			out["memory_stats"] = map[string]any{"usage": uint64(32 << 20), "limit": limit, "stats": map[string]uint64{"inactive_file": 4 << 20}}
			out["pids_stats"] = map[string]any{"current": 1}
		}
		writeJSON(w, http.StatusOK, out)
	})
}

// containerTop lists the one process a running container stands for.
func (e *Engine) containerTop(w http.ResponseWriter, _ *http.Request, a []string) {
	e.withContainer(w, a[0], func(c *ctr) {
		if !c.State.Running {
			writeError(w, http.StatusConflict, "Container "+c.ID+" is not running")
			return
		}
		cmd := strings.Join(append(append([]string{}, c.Config.Entrypoint...), c.Config.Cmd...), " ")
		writeJSON(w, http.StatusOK, map[string]any{"Titles": []string{"UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"}, "Processes": [][]string{{c.Config.User, strconv.Itoa(c.State.Pid), "1", "0", "00:00", "?", "00:00:00", cmd}}})
	})
}
