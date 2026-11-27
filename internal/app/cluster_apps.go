// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/clusterapp"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// CheckClusterApps refuses to start with an enabled cluster app whose image is not
// installed on this node, or whose bundle has no release manifest signed by a
// trusted key, or does not hold the image that manifest names.
func CheckClusterApps(c config.Node) error {
	for _, name := range c.ClusterApps.Enabled() {
		if _, err := openClusterAppImage(name); err != nil {
			return fmt.Errorf("cluster app %s: %w", name, err)
		}
	}
	if web := c.ClusterApps.Web; web != nil && web.Enabled && web.SealKeyFile != "" {
		if _, err := readSealKey(web.SealKeyFile); err != nil {
			return fmt.Errorf("cluster app web: seal key file: %w", err)
		}
	}
	return nil
}

// openClusterAppImage verifies and opens an installed cluster app image
// against this node's release keys (devel/design/cluster-apps.md 3.3).
func openClusterAppImage(name string) (clusterapp.Bundle, error) {
	image, _ := clusterapp.Lookup(name)
	trust, err := clusterapp.LoadTrust(clusterapp.KeyDir)
	if err != nil {
		return clusterapp.Bundle{}, err
	}
	return clusterapp.Open(clusterapp.ImageDir, image, trust)
}

// loadedClusterAppImage is a cluster app image pulled into the Engine: the
// manifest digest its release manifest named and the Engine's image ID.
type loadedClusterAppImage struct{ digest, id string }

// pullClusterAppImage has the Engine pull app's verified bundle by digest
// (devel/design/cluster-apps.md 3.3). The pull ticket lets purpose 37 answer
// the Engine's manifest and blob requests from the bundle, and only while
// this pull runs. It returns the Engine's image ID. Seafield keeps images
// in the containerd image store, where the ID is the manifest digest the
// release manifest names; an engine on the old image store reports the
// bundle's config digest instead. Either one is the verified bundle.
func (r *Runtime) pullClusterAppImage(ctx context.Context, app string, bundle clusterapp.Bundle) (string, error) {
	config, err := bundle.Image.ConfigName()
	if err != nil {
		return "", err
	}
	img, err := r.docker.PullClusterApp(ctx, bundle.PullRef(app), bundle.Open)
	if err != nil {
		return "", err
	}
	if !clusterAppImageID(img.ID, bundle.Release.Digest, config.String()) {
		return "", clusterapp.ErrImage
	}
	return img.ID, nil
}

// clusterAppImageID: id is the image the engine reports for a pull of the
// bundle's manifest digest (containerd image store) or of its config.
func clusterAppImageID(id, manifest, config string) bool {
	return id != "" && (id == manifest || id == config)
}

// Paths inside the sfc-web container (devel/design/cluster-apps.md 3). Its
// run directory is clusterapp.ContainerRunDir.
const (
	webContainerDataDir = "/var/lib/sfc-web"
	webContainerSealKey = "/run/secrets/seal-key"
)

func clusterAppDir(stateDir, app string) string { return filepath.Join(stateDir, "cluster-apps", app) }

// openClusterApps opens the cluster app owner whenever the network module runs, so
// a cluster app that node.yaml no longer enables is still removed.
func (r *Runtime) openClusterApps(c config.Node) error {
	if r.historicalOwner || r.network == nil || r.docker == nil {
		return nil
	}
	dir := filepath.Join(c.Node.StateDir, "cluster-apps")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	owner, err := clusterapp.OpenOwner(filepath.Join(dir, "journal.db"), r.docker, r.network)
	if err != nil {
		return err
	}
	r.clusterApps, r.clusterAppStateDir, r.clusterAppImages = owner, c.Node.StateDir, map[string]loadedClusterAppImage{}
	r.clusterAppNAT = network.SetClusterApps
	return nil
}

// reconcileClusterApps keeps each cluster app container as node.yaml says. A
// cluster app waits until this server's sfc-system Bridge is there and the
// cluster records this server as the one that runs it (claimClusterApps);
// one another server runs gets no container. While the Bridge drains, the
// container is removed so the Bridge can go.
func (r *Runtime) reconcileClusterApps(ctx context.Context, v cluster.View) error {
	target, err := r.reconcileWeb(ctx, v)
	// The web's cluster-wide address reaches its container only here, on
	// the server that runs it; any other server keeps no forward.
	var forwards []network.ClusterAppForward
	if cluster, ok := network.ClusterAppAddress(clusterapp.Web); ok && target.IsValid() {
		forwards = append(forwards, network.ClusterAppForward{Cluster: cluster, Pool: target.Addr(), In: r.systemTunnelDevice(v)})
	}
	if r.clusterAppNAT != nil {
		if nerr := r.clusterAppNAT(forwards); nerr != nil {
			r.clusterAppProblems.set(clusterapp.Web, "failed", "address-unavailable")
			err = errors.Join(err, fmt.Errorf("cluster app address: %w", errClusterAppAddress))
		}
	}
	listen := ""
	if web := r.installation.config.ClusterApps.Web; web != nil && web.Enabled && target.IsValid() {
		listen = clusterAppListen(r.installation.config.Node.Listen, web.Port)
	}
	if perr := r.webPort.set(listen, target); perr != nil {
		r.clusterAppProblems.set(clusterapp.Web, "failed", "port-unavailable")
		err = errors.Join(err, fmt.Errorf("cluster app web port: %w", errClusterAppPort))
	}
	return err
}

// systemTunnelDevice is this server's sfc-system TUN device, the one
// interface other servers' packets for a cluster address come in on ("" if
// it has none yet: then only this server's own connections reach the app).
func (r *Runtime) systemTunnelDevice(v cluster.View) string {
	key := tenancy.SourceIdentity{Kind: "tun", Network: tenancy.SystemNetwork, Node: r.installation.record.Root.Self.ID}.Key()
	o := v.State.Object(key)
	if !o.Present {
		return ""
	}
	spec, err := network.DecodeTunnel(o.Value)
	if err != nil {
		return ""
	}
	name, err := network.TunnelDeviceName(key, o.Generation, spec)
	if err != nil {
		return ""
	}
	return name
}

// reconcileWeb keeps the web container and gives where it listens once
// this server runs it.
func (r *Runtime) reconcileWeb(ctx context.Context, v cluster.View) (netip.AddrPort, error) {
	if r.clusterApps == nil || r.installation == nil {
		return netip.AddrPort{}, nil
	}
	web := r.installation.config.ClusterApps.Web
	if web == nil || !web.Enabled {
		return netip.AddrPort{}, r.clusterApps.Set(ctx, clusterapp.Web, nil)
	}
	resources, err := r.controlPolicy.Resources(v.State)
	if err != nil {
		return netip.AddrPort{}, err
	}
	node := r.installation.record.Root.Self.ID
	key := tenancy.SourceIdentity{Kind: "bridge", Network: tenancy.SystemNetwork, Node: node}.Key()
	o := v.State.Object(key)
	var member *tenancy.Network
	for _, m := range resources.Networks.SystemMembers() {
		if m.Node == node {
			member = &m
		}
	}
	bridge, decodeErr := network.DecodeBridge(o.Value)
	if !o.Present || decodeErr != nil || bridge.Lifecycle.Drain || member == nil || member.Draining {
		// Not joined yet (reconcileSystemNetwork joins), or leaving. A
		// join the cluster would refuse shows its reason meanwhile.
		if block := r.systemNetwork.blocked(); block != "" {
			r.clusterAppProblems.set(clusterapp.Web, "starting", block)
		} else {
			r.clusterAppProblems.set(clusterapp.Web, "", "")
		}
		return netip.AddrPort{}, r.clusterApps.Set(ctx, clusterapp.Web, nil)
	}
	if _, refused := r.clusterAppProblems.refusedBy(clusterapp.Web); refused {
		r.clusterAppProblems.set(clusterapp.Web, "", "")
		return netip.AddrPort{}, r.clusterApps.Set(ctx, clusterapp.Web, nil)
	}
	runner, addr, ok := resources.Networks.ClusterAppPoolAddress(clusterapp.Web, r.controlPolicy.SystemNetworkUsers(v.State, resources.Networks))
	if !ok || runner != node {
		// not claimed yet (claimClusterApps), or about to be refused
		r.clusterAppProblems.set(clusterapp.Web, "", "")
		return netip.AddrPort{}, r.clusterApps.Set(ctx, clusterapp.Web, nil)
	}
	spec, err := r.webSpec(ctx, *web, key, o.Generation, addr, *member)
	if err == nil {
		err = r.clusterApps.Set(ctx, clusterapp.Web, &spec)
		if errors.Is(err, clusterapp.ErrImageNotFound) {
			// The Engine lost the image: pull it again next pass.
			delete(r.clusterAppImages, clusterapp.Web)
		}
	}
	state, reason := clusterAppOutcome(err)
	r.clusterAppProblems.set(clusterapp.Web, state, reason)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, clusterapp.WebDirectPort), nil
}

func (r *Runtime) webSpec(ctx context.Context, web config.ClusterAppWeb, bridge string, generation uint64, addr netip.Addr, member tenancy.Network) (clusterapp.ContainerSpec, error) {
	// Read the bundle every pass: a new image package with a new signed
	// release manifest takes effect without a sfcd rebuild, and its digest
	// changes the container's generation.
	bundle, err := openClusterAppImage(clusterapp.Web)
	if err != nil {
		return clusterapp.ContainerSpec{}, fmt.Errorf("cluster app web: %w", err)
	}
	pin := bundle.Release.Digest
	loaded := r.clusterAppImages[clusterapp.Web]
	if loaded.digest != pin || loaded.id == "" {
		id, err := r.pullClusterAppImage(ctx, clusterapp.Web, bundle)
		if err != nil {
			return clusterapp.ContainerSpec{}, fmt.Errorf("cluster app web: %w: %w", errClusterAppImageLoad, err)
		}
		loaded = loadedClusterAppImage{digest: pin, id: id}
		r.clusterAppImages[clusterapp.Web] = loaded
	}
	id := loaded.id
	dir := clusterAppDir(r.clusterAppStateDir, clusterapp.Web)
	data := filepath.Join(dir, "data")
	uid := web.UID
	if uid == 0 {
		uid = clusterapp.DefaultUID
	}
	if err := ownedDir(data, int(uid)); err != nil {
		return clusterapp.ContainerSpec{}, err
	}
	cluster := r.controlPolicy.Cluster
	s := clusterapp.ContainerSpec{
		Schema: 1, App: clusterapp.Web, Image: id, Digest: pin, Bridge: bridge, BridgeGeneration: generation, Address: addr,
		User: strconv.FormatUint(uint64(uid), 10) + ":" + strconv.FormatUint(uint64(uid), 10),
		Cmd: []string{
			"-socket", clusterapp.ContainerRunDir + "/sfcdp.sock",
			"-cluster", hex.EncodeToString(cluster[:]),
			"-node", r.installation.record.Root.Self.ID,
			"-node-key", hex.EncodeToString(r.Identity.Public[:]),
			"-data-dir", webContainerDataDir,
			"-listen", ":" + strconv.Itoa(int(clusterapp.WebPort)),
			"-acme-listen", ":" + strconv.Itoa(int(clusterapp.WebACMEPort)),
			"-direct-listen", ":" + strconv.Itoa(int(clusterapp.WebDirectPort)),
		},
		Env: []string{"SFC_WEB_TRUSTED_PROXIES=" + trustedProxies(member)},
		Binds: []clusterapp.Bind{
			{Source: clusterapp.RunDir(r.clusterAppStateDir, clusterapp.Web), Target: clusterapp.ContainerRunDir},
			{Source: data, Target: webContainerDataDir},
		},
	}
	if web.SealKeyFile != "" {
		// The container runs as uid, which cannot read a root-only key
		// file: it gets its own copy, owned by uid and readable only by it.
		key := filepath.Join(dir, "seal-key")
		if err := ownedCopy(web.SealKeyFile, key, int(uid)); err != nil {
			return clusterapp.ContainerSpec{}, fmt.Errorf("cluster app web: %w: %w", errClusterAppSealKey, err)
		}
		s.Binds = append(s.Binds, clusterapp.Bind{Source: key, Target: webContainerSealKey, ReadOnly: true})
		s.Env = append(s.Env, "SFC_WEB_SEAL_KEY_FILE="+webContainerSealKey)
	}
	return s, nil
}

// trustedProxies are the addresses ingress connects to sfc-web from: this
// server's own gateway on its pool, and the server addresses (the range's
// last /20, every server's tunnel address) other servers' ingress comes
// through. Other cluster apps sit in
// the pools and are not trusted.
func trustedProxies(member tenancy.Network) string {
	out := []string{network.ServerBlock.String()}
	for _, p := range member.Pools {
		out = append(out, p.Gateway.String())
	}
	return strings.Join(out, ",")
}

// ownedDir makes dir (0700) owned by uid. Its parent stays root's.
func ownedDir(dir string, uid int) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chown(dir, uid, uid); err != nil {
		return err
	}
	return os.Chmod(dir, 0700)
}

// ownedCopy keeps dst a copy of src (at most 64KiB) owned by uid with mode
// 0400, rewriting it only when the contents differ. dst's directory is root's.
func ownedCopy(src, dst string, uid int) error {
	raw, err := readSealKey(src)
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(dst); err == nil && bytes.Equal(old, raw) {
		if err = os.Chown(dst, uid, uid); err != nil {
			return err
		}
		return os.Chmod(dst, 0400)
	}
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err == nil {
		err = os.Chown(tmp, uid, uid)
	}
	if err == nil {
		err = os.Chmod(tmp, 0400)
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// readSealKey reads node.yaml's seal key file: a regular, non-empty file of
// at most 64KiB.
func readSealKey(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > 64<<10 {
		return nil, fmt.Errorf("%s is not a regular non-empty file of at most 64KiB", path)
	}
	return os.ReadFile(path)
}

// shutdownClusterApps removes the cluster app containers when sfcd stops.
func (r *Runtime) shutdownClusterApps() error {
	r.webPort.close()
	var nat error
	if r.clusterAppNAT != nil {
		nat = r.clusterAppNAT(nil)
	}
	if r.clusterApps == nil {
		return nat
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return errors.Join(nat, r.clusterApps.Shutdown(ctx), r.clusterApps.Close())
}
