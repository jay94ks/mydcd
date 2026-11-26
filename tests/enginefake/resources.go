// SPDX-License-Identifier: Apache-2.0

package enginefake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	apinetwork "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
)

// Networks.

type netw struct {
	ID, Name, Driver string
	Created          time.Time
	Internal         bool
	EnableIPv6       bool
	IPAM             apinetwork.IPAM
	Options, Labels  map[string]string
	Endpoints        map[string]endpoint // by container ID
	// HostLink is the kernel bridge made for this network (Host).
	HostLink string
}

type endpoint struct {
	Name, EndpointID string
	IP               netip.Addr
	Bits             int
}

func (n *netw) prefix() (netip.Prefix, bool) {
	for _, c := range n.IPAM.Config {
		if c.Subnet.IsValid() && c.Subnet.Addr().Is4() {
			return c.Subnet.Masked(), true
		}
	}
	return netip.Prefix{}, false
}

func (n *netw) gateway() (netip.Addr, bool) {
	for _, c := range n.IPAM.Config {
		if c.Gateway.IsValid() {
			return c.Gateway, true
		}
	}
	p, ok := n.prefix()
	if !ok {
		return netip.Addr{}, false
	}
	return p.Addr().Next(), true
}

// allocate picks the lowest free address after the gateway.
func (n *netw) allocate() (netip.Addr, int, netip.Addr, bool) {
	p, ok := n.prefix()
	if !ok {
		return netip.Addr{}, 0, netip.Addr{}, false
	}
	gw, _ := n.gateway()
	used := map[netip.Addr]bool{gw: true}
	for _, ep := range n.Endpoints {
		used[ep.IP] = true
	}
	for _, c := range n.IPAM.Config {
		for _, a := range c.AuxAddress {
			used[a] = true
		}
	}
	for a := p.Addr().Next(); p.Contains(a); a = a.Next() {
		if !used[a] && a.Next().IsValid() && p.Contains(a.Next()) {
			return a, p.Bits(), gw, true
		}
	}
	return netip.Addr{}, 0, netip.Addr{}, false
}

func (n *netw) inspect() apinetwork.Inspect {
	out := apinetwork.Inspect{Containers: map[string]apinetwork.EndpointResource{}}
	out.Name, out.ID, out.Created, out.Scope, out.Driver = n.Name, n.ID, n.Created, "local", n.Driver
	out.EnableIPv4, out.EnableIPv6, out.IPAM, out.Internal = true, n.EnableIPv6, n.IPAM, n.Internal
	out.Options, out.Labels = n.Options, n.Labels
	if out.IPAM.Driver == "" {
		out.IPAM.Driver = "default"
	}
	for id, ep := range n.Endpoints {
		r := apinetwork.EndpointResource{Name: ep.Name, EndpointID: ep.EndpointID}
		if ep.IP.IsValid() {
			r.IPv4Address = netip.PrefixFrom(ep.IP, ep.Bits)
		}
		out.Containers[id] = r
	}
	return out
}

func networkRoutes() {
	handle("GET", "/networks", (*Engine).networkList)
	handle("POST", "/networks/create", (*Engine).networkCreate)
	handle("POST", "/networks/*/connect", (*Engine).networkConnect)
	handle("POST", "/networks/*/disconnect", (*Engine).networkDisconnect)
	handle("GET", "/networks/*", (*Engine).networkInspect)
	handle("DELETE", "/networks/*", (*Engine).networkRemove)
}

// Networks lists the names of the networks the engine holds, sorted.
func (e *Engine) Networks() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, n := range e.networks {
		out = append(out, n.Name)
	}
	slices.Sort(out)
	return out
}

// lookupNetwork finds a network by ID, unique ID prefix or name. The caller
// holds e.mu.
func (e *Engine) lookupNetwork(ref string) *netw {
	if n, ok := e.networks[ref]; ok {
		return n
	}
	var found *netw
	for _, n := range e.networks {
		if n.Name == ref {
			return n
		}
		if strings.HasPrefix(n.ID, ref) {
			found = n
		}
	}
	return found
}

func (e *Engine) networkList(w http.ResponseWriter, r *http.Request, _ []string) {
	f, err := parseFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []apinetwork.Inspect{}
	for _, n := range e.networks {
		if !f.labels(n.Labels) || !f.oneOf("name", func(v string) bool { return strings.Contains(n.Name, v) }) || !f.oneOf("id", func(v string) bool { return strings.HasPrefix(n.ID, v) }) || !f.oneOf("driver", func(v string) bool { return v == n.Driver }) {
			continue
		}
		out = append(out, n.inspect())
	}
	writeJSON(w, http.StatusOK, out)
}

func (e *Engine) networkCreate(w http.ResponseWriter, r *http.Request, _ []string) {
	var req apinetwork.CreateRequest
	if err := readJSON(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, fmt.Sprint("network create: ", err))
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, n := range e.networks {
		if n.Name == req.Name {
			writeError(w, http.StatusConflict, "network with name "+req.Name+" already exists")
			return
		}
	}
	n := &netw{ID: newID(), Name: req.Name, Driver: req.Driver, Created: time.Now().UTC(), Internal: req.Internal, Options: req.Options, Labels: req.Labels, Endpoints: map[string]endpoint{}}
	if n.Driver == "" {
		n.Driver = "bridge"
	}
	if req.EnableIPv6 != nil {
		n.EnableIPv6 = *req.EnableIPv6
	}
	if req.IPAM != nil {
		n.IPAM = *req.IPAM
	}
	if n.Options == nil {
		n.Options = map[string]string{}
	}
	if n.Labels == nil {
		n.Labels = map[string]string{}
	}
	if p, ok := n.prefix(); ok {
		for _, other := range e.networks {
			if q, ok := other.prefix(); ok && q.Overlaps(p) {
				writeError(w, http.StatusForbidden, "Pool overlaps with other one on this address space")
				return
			}
		}
	}
	if e.host && n.Driver == "bridge" {
		if err := e.createBridgeLink(n); err != nil {
			writeError(w, http.StatusInternalServerError, "bridge link: "+err.Error())
			return
		}
	}
	e.networks[n.ID] = n
	e.emit("network", "create", n.ID, map[string]string{"name": n.Name, "type": n.Driver})
	writeJSON(w, http.StatusCreated, map[string]any{"Id": n.ID, "Warning": ""})
}

func (e *Engine) networkInspect(w http.ResponseWriter, _ *http.Request, a []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := e.lookupNetwork(a[0])
	if n == nil {
		writeError(w, http.StatusNotFound, "network "+a[0]+" not found")
		return
	}
	writeJSON(w, http.StatusOK, n.inspect())
}

func (e *Engine) networkRemove(w http.ResponseWriter, _ *http.Request, a []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := e.lookupNetwork(a[0])
	if n == nil {
		writeError(w, http.StatusNotFound, "network "+a[0]+" not found")
		return
	}
	if len(n.Endpoints) > 0 {
		writeError(w, http.StatusForbidden, "error while removing network: network "+n.Name+" has active endpoints")
		return
	}
	e.deleteBridgeLink(n)
	delete(e.networks, n.ID)
	e.emit("network", "destroy", n.ID, map[string]string{"name": n.Name, "type": n.Driver})
	w.WriteHeader(http.StatusNoContent)
}

func (e *Engine) networkConnect(w http.ResponseWriter, r *http.Request, a []string) {
	var req apinetwork.ConnectRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	n, c := e.lookupNetwork(a[0]), e.lookupContainer(req.Container)
	if n == nil || c == nil {
		writeError(w, http.StatusNotFound, "no such network or container")
		return
	}
	if err := e.attach(c, n.Name, req.EndpointConfig); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := e.connectSandbox(c, n, c.Networks[n.Name]); err != nil {
		writeError(w, http.StatusInternalServerError, "container link: "+err.Error())
		return
	}
	e.emit("network", "connect", n.ID, map[string]string{"container": c.ID, "name": n.Name, "type": n.Driver})
	w.WriteHeader(http.StatusOK)
}

func (e *Engine) networkDisconnect(w http.ResponseWriter, r *http.Request, a []string) {
	var req apinetwork.DisconnectRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	n, c := e.lookupNetwork(a[0]), e.lookupContainer(req.Container)
	if n == nil || c == nil {
		writeError(w, http.StatusNotFound, "no such network or container")
		return
	}
	e.detach(c, n)
	e.emit("network", "disconnect", n.ID, map[string]string{"container": c.ID, "name": n.Name, "type": n.Driver})
	w.WriteHeader(http.StatusOK)
}

// Volumes.

// validVolumeName is Docker's local volume name rule. It also keeps a name
// from leaving the engine's volumes directory.
var validVolumeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`)

type vol struct {
	Name, Driver, Mountpoint string
	Created                  time.Time
	Labels, Options          map[string]string
	Anonymous                bool
}

func (v *vol) view() volume.Volume {
	return volume.Volume{Name: v.Name, Driver: v.Driver, Mountpoint: v.Mountpoint, CreatedAt: stamp(v.Created), Labels: v.Labels, Options: v.Options, Scope: "local"}
}

// Mountpoints lists the data directories of the volumes whose labels
// include labels, by volume name.
func (e *Engine) Mountpoints(labels map[string]string) map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]string{}
	for _, v := range e.volumes {
		match := true
		for k, want := range labels {
			match = match && v.Labels[k] == want
		}
		if match {
			out[v.Name] = v.Mountpoint
		}
	}
	return out
}

func volumeRoutes() {
	handle("GET", "/volumes", (*Engine).volumeList)
	handle("POST", "/volumes/create", (*Engine).volumeCreate)
	handle("GET", "/volumes/*", (*Engine).volumeInspect)
	handle("DELETE", "/volumes/*", (*Engine).volumeRemove)
}

// createVolume makes a volume with a real data directory. The caller holds
// e.mu.
func (e *Engine) createVolume(name, driver string, labels, options map[string]string) (*vol, error) {
	anonymous := name == ""
	if anonymous {
		name = newID()
	}
	if !validVolumeName.MatchString(name) {
		return nil, fmt.Errorf("create %s: %q includes invalid characters for a local volume name, only \"[a-zA-Z0-9][a-zA-Z0-9_.-]\" are allowed", name, name)
	}
	if v := e.volumes[name]; v != nil {
		return v, nil
	}
	if driver == "" {
		driver = "local"
	}
	if labels == nil {
		labels = map[string]string{}
	}
	if options == nil {
		options = map[string]string{}
	}
	dir := filepath.Join(e.root, "volumes", name, "_data")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	v := &vol{Name: name, Driver: driver, Mountpoint: dir, Created: time.Now().UTC(), Labels: labels, Options: options, Anonymous: anonymous}
	e.volumes[name] = v
	e.emit("volume", "create", name, map[string]string{"driver": driver})
	return v, nil
}

// removeVolume deletes a volume and its data. The caller holds e.mu.
func (e *Engine) removeVolume(v *vol) {
	_ = os.RemoveAll(filepath.Dir(v.Mountpoint))
	delete(e.volumes, v.Name)
	e.emit("volume", "destroy", v.Name, map[string]string{"driver": v.Driver})
}

// volumeRefs counts containers that mount name. The caller holds e.mu.
func (e *Engine) volumeRefs(name string) int {
	n := 0
	for _, c := range e.containers {
		for _, m := range e.mountsOf(c) {
			if m.Type == mount.TypeVolume && m.Name == name {
				n++
			}
		}
	}
	return n
}

func (e *Engine) volumeList(w http.ResponseWriter, r *http.Request, _ []string) {
	f, err := parseFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := volume.ListResponse{Volumes: []volume.Volume{}, Warnings: []string{}}
	for _, v := range e.volumes {
		if !f.labels(v.Labels) || !f.oneOf("name", func(s string) bool { return strings.Contains(v.Name, s) }) || !f.oneOf("dangling", func(s string) bool { return (s == "true" || s == "1") == (e.volumeRefs(v.Name) == 0) }) {
			continue
		}
		out.Volumes = append(out.Volumes, v.view())
	}
	writeJSON(w, http.StatusOK, out)
}

func (e *Engine) volumeCreate(w http.ResponseWriter, r *http.Request, _ []string) {
	var req volume.CreateRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if v := e.volumes[req.Name]; v != nil && req.Name != "" {
		writeJSON(w, http.StatusCreated, v.view())
		return
	}
	v, err := e.createVolume(req.Name, req.Driver, req.Labels, req.DriverOpts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, v.view())
}

func (e *Engine) volumeInspect(w http.ResponseWriter, _ *http.Request, a []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v := e.volumes[a[0]]
	if v == nil {
		writeError(w, http.StatusNotFound, "get "+a[0]+": no such volume")
		return
	}
	writeJSON(w, http.StatusOK, v.view())
}

func (e *Engine) volumeRemove(w http.ResponseWriter, r *http.Request, a []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v := e.volumes[a[0]]
	if v == nil {
		writeError(w, http.StatusNotFound, "get "+a[0]+": no such volume")
		return
	}
	if e.volumeRefs(v.Name) > 0 {
		writeError(w, http.StatusConflict, "remove "+v.Name+": volume is in use")
		return
	}
	e.removeVolume(v)
	w.WriteHeader(http.StatusNoContent)
}

// Images.

type img struct {
	ID          string
	RepoTags    []string
	RepoDigests []string
	Created     time.Time
	Config      dockerspec.DockerOCIImage
	Size        int64
	Layers      []string
}

func imageRoutes() {
	handle("GET", "/images/json", (*Engine).imageList)
	handle("GET", "/images/**", (*Engine).imageGet)
	handle("POST", "/images/**", (*Engine).imagePost)
	handle("DELETE", "/images/**", (*Engine).imageRemove)
}

// normalRef adds the implied :latest tag to a reference without a tag or
// digest.
func normalRef(ref string) string {
	if strings.Contains(ref, "@") {
		return ref
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref
	}
	return ref + ":latest"
}

// lookupImage finds an image by ID, short ID, tag or digest reference. The
// caller holds e.mu.
func (e *Engine) lookupImage(ref string) *img {
	if ref == "" {
		return nil
	}
	if i, ok := e.images[ref]; ok {
		return i
	}
	if i, ok := e.images["sha256:"+ref]; ok {
		return i
	}
	n := normalRef(ref)
	for _, i := range e.images {
		for _, t := range i.RepoTags {
			if t == n {
				return i
			}
		}
		for _, d := range i.RepoDigests {
			if d == ref {
				return i
			}
			// repo:tag@sha256:… matches its repo@sha256:… digest.
			if name, digest, ok := strings.Cut(ref, "@"); ok {
				if repo, _, _ := strings.Cut(d, "@"); d == stripTag(name)+"@"+digest && repo != "" {
					return i
				}
			}
		}
		if len(ref) >= 12 && strings.HasPrefix(strings.TrimPrefix(i.ID, "sha256:"), ref) {
			return i
		}
	}
	return nil
}

func stripTag(name string) string {
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		return name[:i]
	}
	return name
}

func (e *Engine) imageID(ref string) string {
	if i := e.lookupImage(ref); i != nil {
		return i.ID
	}
	return ""
}

func (i *img) inspect() map[string]any {
	cfg := i.Config
	return map[string]any{"Id": i.ID, "RepoTags": orEmpty(i.RepoTags), "RepoDigests": orEmpty(i.RepoDigests), "Created": stamp(i.Created), "Config": cfg.Config, "Architecture": "amd64", "Os": "linux", "Size": i.Size, "RootFS": map[string]any{"Type": "layers", "Layers": orEmpty(i.Layers)}, "Metadata": map[string]any{}}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (e *Engine) imageList(w http.ResponseWriter, r *http.Request, _ []string) {
	f, err := parseFilters(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := []map[string]any{}
	for _, i := range e.images {
		if !f.labels(i.Config.Config.Labels) || !f.oneOf("reference", func(v string) bool { return e.lookupImage(v) == i }) {
			continue
		}
		used := 0
		for _, c := range e.containers {
			if e.imageID(c.Config.Image) == i.ID {
				used++
			}
		}
		out = append(out, map[string]any{"Id": i.ID, "RepoTags": orEmpty(i.RepoTags), "RepoDigests": orEmpty(i.RepoDigests), "Created": i.Created.Unix(), "Size": i.Size, "Labels": i.Config.Config.Labels, "Containers": used, "ParentId": "", "SharedSize": -1})
	}
	writeJSON(w, http.StatusOK, out)
}

func (e *Engine) imageGet(w http.ResponseWriter, _ *http.Request, a []string) {
	name, ok := strings.CutSuffix(a[0], "/json")
	if !ok {
		e.notImplemented(w, "GET /images/"+a[0])
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	i := e.lookupImage(name)
	if i == nil {
		writeError(w, http.StatusNotFound, "No such image: "+name)
		return
	}
	writeJSON(w, http.StatusOK, i.inspect())
}

func (e *Engine) imagePost(w http.ResponseWriter, r *http.Request, a []string) {
	if a[0] == "create" {
		e.imagePull(w, r)
		return
	}
	if name, ok := strings.CutSuffix(a[0], "/tag"); ok {
		repo, tag := r.URL.Query().Get("repo"), r.URL.Query().Get("tag")
		if tag == "" {
			tag = "latest"
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		i := e.lookupImage(name)
		if i == nil {
			writeError(w, http.StatusNotFound, "No such image: "+name)
			return
		}
		e.tag(i, repo+":"+tag)
		w.WriteHeader(http.StatusCreated)
		return
	}
	e.notImplemented(w, "POST /images/"+a[0])
}

// tag moves ref to i. The caller holds e.mu.
func (e *Engine) tag(i *img, ref string) {
	for _, other := range e.images {
		other.RepoTags = without(other.RepoTags, ref)
	}
	i.RepoTags = append(i.RepoTags, ref)
	e.emit("image", "tag", i.ID, map[string]string{"name": ref})
}

func without(s []string, v string) []string {
	var out []string
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func (e *Engine) imageRemove(w http.ResponseWriter, r *http.Request, a []string) {
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"
	e.mu.Lock()
	defer e.mu.Unlock()
	i := e.lookupImage(a[0])
	if i == nil {
		writeError(w, http.StatusNotFound, "No such image: "+a[0])
		return
	}
	n := normalRef(a[0])
	var out []map[string]string
	if !strings.HasPrefix(a[0], "sha256:") && len(i.RepoTags)+len(i.RepoDigests) > 1 && (contains(i.RepoTags, n) || contains(i.RepoDigests, a[0])) {
		i.RepoTags, i.RepoDigests = without(i.RepoTags, n), without(i.RepoDigests, a[0])
		e.emit("image", "untag", i.ID, map[string]string{"name": a[0]})
		writeJSON(w, http.StatusOK, []map[string]string{{"Untagged": a[0]}})
		return
	}
	for _, c := range e.containers {
		if e.imageID(c.Config.Image) == i.ID && !force {
			writeError(w, http.StatusConflict, "conflict: unable to delete "+a[0]+" (must be forced) - image is being used by container "+c.ID[:12])
			return
		}
	}
	for _, t := range append(append([]string{}, i.RepoTags...), i.RepoDigests...) {
		out = append(out, map[string]string{"Untagged": t})
	}
	out = append(out, map[string]string{"Deleted": i.ID})
	delete(e.images, i.ID)
	e.emit("image", "delete", i.ID, map[string]string{"name": a[0]})
	writeJSON(w, http.StatusOK, out)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (e *Engine) notImplemented(w http.ResponseWriter, call string) {
	e.mu.Lock()
	e.unknown = append(e.unknown, call)
	e.mu.Unlock()
	writeError(w, http.StatusNotImplemented, "enginefake: "+call+" is not implemented")
}

// AddImage puts an image under refs (tags "repo:tag" or digests
// "repo@sha256:…") with cfg as its config. The image ID is the digest of
// the config, as Docker's.
func (e *Engine) AddImage(cfg dockerspec.DockerOCIImage, refs ...string) string {
	if cfg.OS == "" {
		cfg.OS, cfg.Architecture = "linux", "amd64"
	}
	b, _ := json.Marshal(cfg)
	id := digestOf(b)
	e.mu.Lock()
	defer e.mu.Unlock()
	i := e.images[id]
	if i == nil {
		i = &img{ID: id, Created: time.Now().UTC(), Config: cfg, Size: int64(len(b)), Layers: []string{digestOf(append([]byte("layer\x00"), b...))}}
		e.images[id] = i
	}
	for _, r := range refs {
		if strings.Contains(r, "@") {
			if !contains(i.RepoDigests, r) {
				i.RepoDigests = append(i.RepoDigests, r)
			}
			continue
		}
		e.tag(i, normalRef(r))
	}
	return id
}

// imagePull serves POST /images/create?fromImage=…&tag=… from the images a
// test published with Publish (the fake reaches no registry).
func (e *Engine) imagePull(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, tag := q.Get("fromImage"), q.Get("tag")
	if from == "" || q.Get("fromSrc") != "" {
		e.notImplemented(w, "POST /images/create (import)")
		return
	}
	ref := from
	switch {
	case strings.HasPrefix(tag, "sha256:"):
		ref = from + "@" + tag
	case tag != "":
		ref = from + ":" + tag
	}
	ref = normalRef(ref)
	e.mu.Lock()
	remote, ok := e.remote[ref]
	if !ok && strings.HasPrefix(ref, "docker.io/") {
		remote, ok = e.remote[strings.TrimPrefix(ref, "docker.io/")]
	}
	if ok {
		e.pulls = append(e.pulls, ref)
	}
	e.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "manifest for "+ref+" not found: manifest unknown")
		return
	}
	id := e.AddImage(remote, ref)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	_ = enc.Encode(map[string]string{"status": "Pulling from " + stripTag(strings.Split(ref, "@")[0])})
	_ = enc.Encode(map[string]string{"status": "Digest: " + digestPart(ref)})
	_ = enc.Encode(map[string]string{"status": "Status: Downloaded newer image for " + ref, "id": id})
}

func digestPart(ref string) string {
	_, d, _ := strings.Cut(ref, "@")
	return d
}

// Publish makes ref ("repo@sha256:…" or "repo:tag") pullable with cfg, as if
// a registry held it.
func (e *Engine) Publish(cfg dockerspec.DockerOCIImage, ref string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.remote[normalRef(ref)] = cfg
}

// Pulls lists the references pulled, in order.
func (e *Engine) Pulls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.pulls...)
}

// Execs.

type execProcess struct {
	ID, Container string
	Config        container.ExecCreateRequest
	Running       bool
	ExitCode      int
	// Output is what a start returns (a test sets it with ExecOutput).
	Output []byte
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
	writeJSON(w, http.StatusOK, map[string]any{"ID": x.ID, "ContainerID": x.Container, "Running": x.Running, "ExitCode": x.ExitCode, "ProcessConfig": map[string]any{"entrypoint": firstOf(nil, x.Config.Cmd), "arguments": restOf(nil, x.Config.Cmd), "tty": x.Config.Tty, "user": x.Config.User}, "OpenStdin": x.Config.AttachStdin, "OpenStdout": x.Config.AttachStdout, "OpenStderr": x.Config.AttachStderr, "Pid": 0})
}

// execStart runs a detached exec to completion at once (exit code 0). An
// attached start needs the upgrade protocol, which the fake does not serve.
func (e *Engine) execStart(w http.ResponseWriter, r *http.Request, a []string) {
	var req container.ExecStartRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !req.Detach {
		e.notImplemented(w, "POST /exec/*/start (attached)")
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	x := e.execs[a[0]]
	if x == nil {
		writeError(w, http.StatusNotFound, "No such exec instance: "+a[0])
		return
	}
	x.Running = false
	w.WriteHeader(http.StatusOK)
}
