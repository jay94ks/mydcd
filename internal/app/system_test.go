// SPDX-License-Identifier: Apache-2.0

package app

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/moby/moby/client"
	"github.com/quic-go/quic-go/http3"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"
)

// Real HTTP clients run inside the ingress node's kernel namespace. No helper
// handles TUN packets, implements a backend, or supplies a synthetic response.
func TestSystemHTTPClient(t *testing.T) {
	mode := os.Getenv("SFC_R5_HTTP_MODE")
	if mode == "" {
		t.Skip("R5 namespace client only")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cert, e := os.ReadFile(os.Getenv("SFC_R5_CERT"))
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("certificate")
	}
	tc := &tls.Config{RootCAs: roots, ServerName: "app.test", MinVersion: tls.VersionTLS13}
	transports := []http.RoundTripper{&http.Transport{Proxy: nil, DisableKeepAlives: true}, &http2.Transport{TLSClientConfig: tc}, &http3.Transport{TLSClientConfig: tc}}
	defer transports[0].(*http.Transport).CloseIdleConnections()
	defer transports[1].(*http2.Transport).CloseIdleConnections()
	defer transports[2].(*http3.Transport).Close()
	urls := []string{"http://192.0.2.1:18080", "https://192.0.2.1:18443", "https://192.0.2.1:18443"}
	request := func(n int, path string) (*http.Response, error) {
		r, e := http.NewRequestWithContext(ctx, "GET", urls[n]+path, nil)
		if e != nil {
			return nil, e
		}
		r.Host = "app.test"
		return (&http.Client{Transport: transports[n]}).Do(r)
	}
	check := func(n int, path string, want int) {
		t.Helper()
		res, e := request(n, path)
		if e != nil {
			t.Fatal(n, path, e)
		}
		b, e := io.ReadAll(res.Body)
		res.Body.Close()
		if e != nil || res.StatusCode != want || res.ProtoMajor != n+1 {
			t.Fatal(n, path, res.StatusCode, res.Proto, b, e)
		}
		if want == 200 && string(b) != "sfc-boundary "+path {
			t.Fatal("actual remote body", string(b))
		}
		if n > 0 && (res.TLS == nil || res.TLS.NegotiatedProtocol != []string{"", "h2", "h3"}[n]) {
			t.Fatal("ALPN", res.TLS)
		}
	}
	if mode == "hold" {
		r, e := request(0, "/events")
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		rd := bufio.NewReader(r.Body)
		line, e := rd.ReadString('\n')
		if e != nil || line != "data: ready\n" {
			t.Fatal("SSE", line, e)
		}
		fmt.Println("r5-stream-ready")
		_, _ = io.Copy(io.Discard, rd)
		fmt.Println("r5-stream-ended")
		return
	}
	if mode == "unavailable" {
		for n := range transports {
			check(n, "/ping", 503)
		}
		return
	}
	if mode == "saturation" {
		var bodies []io.ReadCloser
		for range 4 {
			res, e := request(0, "/events")
			if e != nil {
				t.Fatal(e)
			}
			defer res.Body.Close()
			rd := bufio.NewReader(res.Body)
			if _, e = rd.ReadString('\n'); e != nil {
				t.Fatal(e)
			}
			bodies = append(bodies, res.Body)
		}
		check(0, "/ping", 503)
		for _, b := range bodies {
			_ = b.Close()
		}
		return
	}
	if mode == "load" {
		// Finite pressure: four workers, 64 total exchanges, no unbounded loop.
		var wg sync.WaitGroup
		errs := make(chan error, 64)
		var accepted, limited atomic.Int64
		for n := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 16; k++ {
					res, e := request(n%3, "/ping")
					if e != nil {
						errs <- e
						return
					}
					b, e := io.ReadAll(res.Body)
					res.Body.Close()
					if e == nil && res.StatusCode == 503 && string(b) == "ingress unavailable\n" {
						limited.Add(1)
						continue
					}
					if e != nil || res.StatusCode != 200 || res.ProtoMajor != n%3+1 || string(b) != "sfc-boundary /ping" {
						errs <- fmt.Errorf("load %d %q %v", res.StatusCode, b, e)
						return
					}
					accepted.Add(1)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Error(e)
		}
		if accepted.Load() == 0 || accepted.Load()+limited.Load() != 64 {
			t.Fatal("bounded admission counts", accepted.Load(), limited.Load())
		}
		t.Logf("bounded 4 workers / 64 real remote HTTP exchanges: accepted=%d capacityLimited=%d", accepted.Load(), limited.Load())
		return
	}
	for n := range transports {
		check(n, "/ping", 200)
		check(n, "/v6", 200)
		check(n, "/missing", 404)
		check(n, "/slow", 504)
		res, e := request(n, "/events")
		if e != nil {
			t.Fatal(e)
		}
		rd := bufio.NewReader(res.Body)
		line, e := rd.ReadString('\n')
		res.Body.Close()
		if e != nil || line != "data: ready\n" {
			t.Fatal("protocol SSE/cancel", n, line, e)
		}
	}
	c, e := net.DialTimeout("tcp4", "192.0.2.1:18080", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprint(c, "GET /upgrade HTTP/1.1\r\nHost: app.test\r\nConnection: Upgrade\r\nUpgrade: sfc-echo\r\n\r\n")
	rd := bufio.NewReader(c)
	res, e := http.ReadResponse(rd, &http.Request{Method: "GET"})
	if e != nil || res.StatusCode != 101 {
		t.Fatal("Upgrade", res, e)
	}
	fmt.Fprint(c, "remote-echo\n")
	line, e := rd.ReadString('\n')
	if e != nil || line != "remote-echo\n" {
		t.Fatal("Upgrade echo", line, e)
	}
	t.Log("actual remote Docker over TUN: H1/h2/h3 + IPv4/IPv6 + ALPN/SSE/cancel/timeout/Upgrade")
}

type systemProcess struct {
	cmd  *exec.Cmd
	done chan error
	log  string
}

func startSystemProcess(t *testing.T, ctx context.Context, log string, args []string, env []string, attr *syscall.SysProcAttr) *systemProcess {
	t.Helper()
	f, e := os.Create(log)
	if e != nil {
		t.Fatal(e)
	}
	// Owned child lifetime extends through rollback; the test context only bounds work.
	c := exec.Command(args[0], args[1:]...)
	c.Env = append(os.Environ(), env...)
	c.SysProcAttr = attr
	c.Stdout = f
	c.Stderr = f
	if e = c.Start(); e != nil {
		f.Close()
		t.Fatal(args, e)
	}
	p := &systemProcess{c, make(chan error, 1), log}
	go func() { e := c.Wait(); f.Close(); p.done <- e }()
	return p
}
func (p *systemProcess) waitExit(t *testing.T) {
	t.Helper()
	if p == nil || p.cmd == nil {
		return
	}
	select {
	case err := <-p.done:
		if err != nil {
			t.Error("child exit", p.cmd.Args, err)
		}
	case <-time.After(8 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		t.Error("child did not exit", p.cmd.Args)
	}
	p.cmd = nil
}
func (p *systemProcess) stop(t *testing.T, kill bool) {
	t.Helper()
	if p == nil || p.cmd == nil {
		return
	}
	select {
	case err := <-p.done:
		if err != nil && !kill {
			t.Error("child already exited", p.cmd.Args, err)
		}
		p.cmd = nil
		return
	default:
	}
	if kill {
		_ = p.cmd.Process.Kill()
	} else {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case e := <-p.done:
		if e != nil && !kill {
			t.Error("process stop", p.cmd.Args, e)
		}
	case <-time.After(8 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
		t.Error("process did not stop", p.cmd.Args)
	}
	p.cmd = nil
}

func TestSystemNamespaceHolder(t *testing.T) {
	if os.Getenv("SFC_R5_NAMESPACE_HOLDER") != "1" {
		t.Skip("R5 namespace owner only")
	}
	if os.Geteuid() != 0 {
		t.Fatal("namespace owner requires root")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	fmt.Println("r5-private-ns-ready")
	<-ctx.Done()
}

func TestRealSystemRemoteIngressFaultsAndRecovery(t *testing.T) {
	host, bin := os.Getenv("SFC_KERNEL_HOST_NETNS"), os.Getenv("SFC_R5_PRODUCTS")
	if host == "" || bin == "" {
		t.Skip("R5 isolated namespace/prebuilt products and rollback plan required")
	}
	current, e := os.Readlink("/proc/self/ns/net")
	if e != nil || current == host || os.Geteuid() != 0 {
		t.Fatal("refusing host mutation", host, current, e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	root := t.TempDir()
	self, _ := os.Executable()
	run := func(args ...string) []byte {
		t.Helper()
		out, e := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if e != nil {
			t.Fatal(args, e, string(out))
		}
		return out
	}
	view := func() []byte {
		t.Helper()
		v := map[string]json.RawMessage{}
		for k, a := range map[string][]string{"link": {"ip", "-j", "link"}, "r4": {"ip", "-j", "-4", "route", "show", "table", "all"}, "r6": {"ip", "-j", "-6", "route", "show", "table", "all"}, "nft": {"nft", "-j", "list", "ruleset"}} {
			v[k] = run(a...)
		}
		b, _ := json.Marshal(v)
		return b
	}
	baseline := view()
	t.Logf("outer prestate=%s", baseline)
	var ns, mnt [2]*os.File
	var nsPath, mntPath [2]string
	var holders, dockers [2]*systemProcess
	var daemons [5]*systemProcess
	var clients []*systemProcess
	var apis [2]*engine.Client
	var normal bool
	// All cleanup is registered before namespace/link/Engine creation.
	t.Cleanup(func() {
		for _, p := range clients {
			p.stop(t, false)
		}
		for _, p := range daemons {
			p.stop(t, false)
		}
		clean, c := context.WithTimeout(context.Background(), 20*time.Second)
		defer c()
		for i, api := range apis {
			if api == nil {
				continue
			}
			all, err := api.API.ContainerList(clean, client.ContainerListOptions{All: true})
			if err != nil {
				t.Error("cleanup containers", err)
			}
			for _, v := range all.Items {
				if normal {
					t.Error("product retained container", v.ID)
				}
				_, _ = api.API.ContainerRemove(clean, v.ID, client.ContainerRemoveOptions{Force: true})
			}
			nets, err := api.API.NetworkList(clean, client.NetworkListOptions{})
			if err != nil {
				t.Error(err)
			}
			for _, v := range nets.Items {
				if v.Labels["org.sfc.owner"] != "" {
					if normal {
						t.Error("product retained Bridge", v.ID)
					}
					_, _ = api.API.NetworkRemove(clean, v.ID, client.NetworkRemoveOptions{})
				}
			}
			_, _ = api.API.ImageRemove(clean, "sfc-r5:local", client.ImageRemoveOptions{})
			api.Close()
			_ = i
		}
		for _, p := range dockers {
			p.stop(t, false)
		}
		for _, p := range holders {
			p.stop(t, false)
		}
		for i := range ns {
			if mnt[i] != nil {
				mnt[i].Close()
			}
			if ns[i] != nil {
				ns[i].Close()
			}
		}
		if l, err := netlink.LinkByName("r5-underlay"); err == nil {
			if err = netlink.LinkDel(l); err != nil {
				t.Error(err)
			}
		}
		// Removing the owned partition table is idempotent cleanup, not a native
		// product-success assertion. No unrelated table is addressed.
		_ = exec.Command("nft", "delete", "table", "inet", "sfc_r5_partition").Run()
		if lo, err := netlink.LinkByName("lo"); err == nil {
			_ = netlink.LinkSetDown(lo)
		}
		// lo initial activation creates local routes/qdisc until namespace exit.
		for _, pattern := range []string{"*.log", "engine-*/engine.log"} {
			files, _ := filepath.Glob(filepath.Join(root, pattern))
			for _, p := range files {
				b, _ := os.ReadFile(p)
				if len(b) > 16000 {
					b = b[len(b)-16000:]
				}
				t.Logf("%s: %s", filepath.Base(p), b)
			}
		}
	})
	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "r5-underlay"}}
	if e = netlink.LinkAdd(bridge); e != nil {
		t.Fatal(e)
	}
	if e = netlink.AddrAdd(bridge, &netlink.Addr{IPNet: mustIPNet("192.0.2.254/24")}); e != nil {
		t.Fatal(e)
	}
	if e = netlink.LinkSetUp(bridge); e != nil {
		t.Fatal(e)
	}
	run("ip", "link", "set", "lo", "up")
	wait := func(what string, f func() bool) {
		t.Helper()
		for !f() {
			for _, p := range daemons {
				if p != nil && p.cmd != nil {
					select {
					case err := <-p.done:
						p.cmd = nil
						b, _ := os.ReadFile(p.log)
						t.Fatalf("%s: daemon exited: %v: %s", what, err, b)
					default:
					}
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal(what, ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	for i := range ns {
		holders[i] = startSystemProcess(t, ctx, filepath.Join(root, fmt.Sprint("holder-", i, ".log")), []string{self, "-test.run=^TestSystemNamespaceHolder$", "-test.v", "-test.timeout=145s"}, []string{"SFC_R5_NAMESPACE_HOLDER=1"}, &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL})
		wait("private mount propagation", func() bool {
			b, _ := os.ReadFile(holders[i].log)
			return bytes.Contains(b, []byte("r5-private-ns-ready"))
		})
		pid := holders[i].cmd.Process.Pid
		ns[i], e = os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
		if e != nil {
			t.Fatal(e)
		}
		mnt[i], e = os.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid))
		if e != nil {
			t.Fatal(e)
		}
		nsPath[i] = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), ns[i].Fd())
		mntPath[i] = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), mnt[i].Fd())
		name, peer := fmt.Sprint("r5-v", i), fmt.Sprint("r5-n", i)
		v := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: peer}
		if e = netlink.LinkAdd(v); e != nil {
			t.Fatal(e)
		}
		if e = netlink.LinkSetMaster(v, bridge); e != nil {
			t.Fatal(e)
		}
		if e = netlink.LinkSetUp(v); e != nil {
			t.Fatal(e)
		}
		l, e := netlink.LinkByName(peer)
		if e != nil {
			t.Fatal(e)
		}
		if e = netlink.LinkSetNsFd(l, int(ns[i].Fd())); e != nil {
			t.Fatal(e)
		}
		for _, args := range [][]string{{"ip", "link", "set", "lo", "up"}, {"ip", "addr", "add", fmt.Sprintf("192.0.2.%d/24", i+1), "dev", peer}, {"ip", "link", "set", peer, "mtu", "1500", "up"}, {"sysctl", "-w", "net.ipv4.ip_forward=1"}, {"sysctl", "-w", "net.ipv6.conf.all.forwarding=1"}} {
			run(append([]string{"nsenter", "--net=" + nsPath[i], "--"}, args...)...)
		}
		engRoot := filepath.Join(root, fmt.Sprint("engine-", i))
		if e = os.MkdirAll(engRoot, 0700); e != nil {
			t.Fatal(e)
		}
		conf := filepath.Join(engRoot, "daemon.json")
		os.WriteFile(conf, []byte(`{"features":{"containerd-snapshotter":false}}`), 0600)
		socket := filepath.Join(engRoot, "docker.sock")
		args := []string{"nsenter", "--net=" + nsPath[i], "--mount=" + mntPath[i], "--", "dockerd", "--config-file", conf, "--host", "unix://" + socket, "--data-root", filepath.Join(engRoot, "data"), "--exec-root", filepath.Join(engRoot, "exec"), "--pidfile", filepath.Join(engRoot, "docker.pid"), "--storage-driver", "vfs", "--bridge", "none", "--iptables=false", "--ip6tables=false", "--ip-forward=false", "--ip-masq=false", "--userland-proxy=false", "--shutdown-timeout", "3", "--log-level", "error"}
		dockers[i] = startSystemProcess(t, ctx, filepath.Join(engRoot, "engine.log"), args, nil, &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL})
		wait("private Engine socket", func() bool {
			out, err := exec.CommandContext(ctx, "docker", "--host", "unix://"+socket, "info", "--format", "{{.ServerVersion}}").CombinedOutput()
			if err == nil {
				t.Logf("Engine%d=%s", i, out)
				return true
			}
			select {
			case err := <-dockers[i].done:
				dockers[i].cmd = nil
				b, _ := os.ReadFile(dockers[i].log)
				t.Fatal("private Engine exited", err, string(b))
			default:
			}
			return false
		})
	}
	keys := make([]*identity.Identity, 6)
	for i := range keys {
		keys[i], e = identity.Create(filepath.Join(root, fmt.Sprint("key-", i)))
		if e != nil {
			t.Fatal(e)
		}
	}
	id := shaCluster(filepath.Base(root))
	owners := []string{desired.Owner(id, keys[0].Public), desired.Owner(id, keys[1].Public)}
	peers := ""
	names := []string{"a", "b", "c0", "c1", "c2"}
	addresses := []string{"192.0.2.1:44100", "192.0.2.2:44101", "192.0.2.254:45100", "192.0.2.254:45101", "192.0.2.254:45102"}
	for i, name := range names {
		peers += fmt.Sprintf("    - {id: %s, key: '%s', endpoint: '%s', voter: %t}\n", name, keys[i].Actor(), addresses[i], i >= 2)
	}
	cert, _ := systemCertificate(t, root)
	configs := make([]string, 5)
	for i, name := range names {
		modules := "  network: {enabled: false}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n"
		if i < 2 {
			mods := "  network: {enabled: true}\n  workload: {enabled: true}\n"
			if i == 0 {
				mods += "  ingress: {enabled: true}\n"
			} else {
				mods += "  ingress: {enabled: false}\n"
			}
			modules = mods
		}
		text := fmt.Sprintf("version: 1\ncommon:\n  cluster: '%x'\n  admin: '%s'\n  peers:\n%snode:\n  id: %s\n  state_dir: '%s'\n  identity_dir: '%s'\n  listen: '%s'\n  bootstrap: %t\nmodules:\n%s", id, keys[5].Actor(), peers, name, filepath.Join(root, "state-"+name), filepath.Join(root, fmt.Sprint("key-", i)), addresses[i], i == 2, modules)
		configs[i] = filepath.Join(root, name+".yaml")
		if e = os.WriteFile(configs[i], []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		if i < 2 {
			writeTestEngine(t, configs[i], "unix://"+filepath.Join(root, fmt.Sprint("engine-", i), "docker.sock"))
		}
	}
	startDaemon := func(i int) {
		args := append(append([]string{filepath.Join(bin, "sfcd"), "--config", configs[i]}, sfcdEngineFlags(configs[i])...), "run")
		if i < 2 {
			args = append([]string{"nsenter", "--net=" + nsPath[i], "--mount=" + mntPath[i], "--"}, args...)
		}
		daemons[i] = startSystemProcess(t, ctx, filepath.Join(root, fmt.Sprintf("daemon-%d-%d.log", i, time.Now().UnixNano())), args, nil, &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL})
	}
	clientFile := filepath.Join(root, "client.yaml")
	os.WriteFile(clientFile, []byte(fmt.Sprintf("version: 1\ncluster: '%x'\nidentity_dir: '%s'\npeers:\n%s", id, filepath.Join(root, "key-5"), peers)), 0600)
	for i := range daemons {
		startDaemon(i)
	}
	cli := func(peer string, args ...string) (cluster.ManagementReply, error) {
		c, stop := context.WithTimeout(ctx, 4*time.Second)
		defer stop()
		argv := []string{"--config", clientFile, "--peer", peer, "--timeout", "3s"}
		call := append([]string{filepath.Join(bin, "sfc")}, append(argv, args...)...)
		// Node-local authenticated observation remains available when its underlay
		// deliberately cannot carry the transport's initial packet.
		if peer == "a" || peer == "b" {
			i := 0
			if peer == "b" {
				i = 1
			}
			call = append([]string{"nsenter", "--net=" + nsPath[i], "--"}, call...)
		}
		cmd := exec.CommandContext(c, call[0], call[1:]...)
		out, e := cmd.Output()
		var reply cluster.ManagementReply
		if len(out) > 0 {
			if err := json.Unmarshal(out, &reply); err != nil {
				return reply, fmt.Errorf("CLI JSON %s: %w", out, err)
			}
		}
		return reply, e
	}
	wait("real voting group", func() bool { r, e := cli("c0", "status"); return e == nil && r.Leader != "" })
	sequence := 0
	submit := func(key string, value any, expected uint64, remove bool, want state.Code) state.Result {
		t.Helper()
		sequence++
		c := state.Command{Actor: keys[5].Actor(), Epoch: 1, RequestID: fmt.Sprint("r5-", sequence), Key: key, Expected: expected, Delete: remove}
		if !remove {
			c.Value = mustJSON(value)
		}
		b, err := state.EncodeCommand(c)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(root, "command.bin")
		os.WriteFile(p, b, 0600)
		r, err := cli("c0", "submit", p)
		if r.Committed == nil || r.Committed.Result.Code != want || err != nil && want == state.Applied {
			detail, _ := json.Marshal(r)
			t.Fatalf("submit %s want %d: %s %v", key, want, detail, err)
		}
		return r.Committed.Result
	}
	observe := func(peer, key string) ModuleObservation {
		r, e := cli(peer, "observe", key)
		var o ModuleObservation
		if e == nil {
			_ = json.Unmarshal(r.Data, &o)
		}
		return o
	}
	var bridges [2]network.BridgeSpec
	var tasks [2]workload.ContainerSpec
	var tuns [2]network.TunnelSpec
	var bridgeR, taskR, tunR [2]state.Result
	for i := 0; i < 2; i++ {
		api, err := engine.Open(ctx, "unix://"+filepath.Join(root, fmt.Sprint("engine-", i), "docker.sock"), owners[i])
		if err != nil {
			t.Fatal(err)
		}
		apis[i] = api
		image := systemImportBackend(t, ctx, api, filepath.Join(bin, "backend"))
		n := desired.NodeSpec{Schema: 1, Owner: owners[i], CPU: 1_000_000_000, Memory: 128 << 20, MaxBridges: 2, MaxContainers: 2, MaxEndpoints: 16, MaxConsumers: 8, PacketQueuePackets: 16, PacketQueueBytes: 64 << 10, MaxIngressInstances: 2, MaxIngressListeners: 4, MaxIngressRequests: 4, MaxIngressConnections: 16, IngressBufferBytes: 256 << 10}
		submit(desired.NodePrefix+names[i], n, 0, false, state.Applied)
		pool4 := netip.MustParsePrefix(fmt.Sprintf("10.248.%d.0/28", 10*(i+1)))
		pool6 := netip.MustParsePrefix(fmt.Sprintf("fd00:248:%d::/124", 10*(i+1)))
		bridges[i] = network.BridgeSpec{Schema: 1, Owner: owners[i], Network: "r5", MTU: 1280, Pools: []network.Pool{{ID: fmt.Sprint(i, "4"), Network: "r5", Owner: owners[i], Prefix: pool4, Gateway: pool4.Addr().Next(), MTU: 1280}, {ID: fmt.Sprint(i, "6"), Network: "r5", Owner: owners[i], Prefix: pool6, Gateway: pool6.Addr().Next(), MTU: 1280}}}
		bridgeR[i] = submit(desired.BridgePrefix+names[i], bridges[i], 0, false, state.Applied)
		wait("real dual-stack Bridge "+names[i], func() bool { return observe(names[i], desired.BridgePrefix+names[i]).Ready })
		tasks[i] = workload.ContainerSpec{Schema: 1, Node: owners[i], Image: image, Command: []string{"/backend"}, Bridge: desired.BridgePrefix + names[i], BridgeGeneration: bridgeR[i].Generation, IPv4: pool4.Addr().Next().Next(), IPv6: pool6.Addr().Next().Next(), Memory: 32 << 20, NanoCPU: 100_000_000}
		taskR[i] = submit(desired.TaskPrefix+names[i], tasks[i], 0, false, state.Applied)
		wait("real dual-stack container "+names[i], func() bool { return observe(names[i], desired.TaskPrefix+names[i]).Ready })
	}
	for i := 0; i < 2; i++ {
		other := 1 - i
		tuns[i] = network.TunnelSpec{Schema: 1, Owner: owners[i], Network: "r5", MTU: 1280, RouteMetric: 130, Addresses: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("10.248.30.%d/32", i+1)), netip.MustParsePrefix(fmt.Sprintf("fd00:248:30::%d/128", i+1))}, Routes: []netip.Prefix{bridges[other].Pools[0].Prefix, netip.MustParsePrefix(fmt.Sprintf("10.248.30.%d/32", other+1)), bridges[other].Pools[1].Prefix, netip.MustParsePrefix(fmt.Sprintf("fd00:248:30::%d/128", other+1))}}
		tunR[i] = submit(desired.TunnelPrefix+names[i], tuns[i], 0, false, state.Applied)
	}
	wait("actual bilateral native packet paths", func() bool {
		return observe("a", desired.TunnelPrefix+"a").Ready && observe("b", desired.TunnelPrefix+"b").Ready
	})
	var udp [2]*systemProcess
	for i := range udp {
		addresses := tuns[i].Addresses[0].Addr().String() + "," + tuns[i].Addresses[1].Addr().String()
		udp[i] = startSystemProcess(t, ctx, filepath.Join(root, fmt.Sprintf("udp-%d.log", i)), []string{"nsenter", "--net=" + nsPath[i], "--", self, "-test.run=^TestTunnelUDPHelper$", "-test.v", "-test.timeout=145s"}, []string{"SFC_TUN_HELPER=echo", "SFC_TUN_ADDRESSES=" + addresses}, &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL})
		clients = append(clients, udp[i])
		wait("actual native UDP echo", func() bool { b, _ := os.ReadFile(udp[i].log); return bytes.Contains(b, []byte("echo ready")) })
	}
	probeUDP := func() {
		t.Helper()
		for i := range udp {
			other := 1 - i
			addresses := tuns[other].Addresses[0].Addr().String() + "," + tuns[other].Addresses[1].Addr().String()
			c := exec.CommandContext(ctx, "nsenter", "--net="+nsPath[i], "--", self, "-test.run=^TestTunnelUDPHelper$", "-test.v", "-test.timeout=10s")
			c.Env = append(os.Environ(), "SFC_TUN_HELPER=probe", "SFC_TUN_ADDRESSES="+addresses)
			b, err := c.CombinedOutput()
			if err != nil {
				t.Fatal("native1280", err, string(b))
			}
			t.Logf("node%d native1280: %s", i, b)
		}
	}
	probeUDP()
	appKey := desired.IngressPrefix + "remote"
	spec := ingress.Spec{Schema: 1, Owner: owners[0], Listeners: []ingress.Listener{{ID: "clear", Address: "192.0.2.1:18080"}, {ID: "tls", Address: "192.0.2.1:18443", TLS: true, HTTP3: true}}, MaxRequests: 4, MaxConnections: 16, MaxHeaderBytes: 4096, BufferBytes: 256 << 10, MaxBodyBytes: 1024, RequestTimeoutMS: 800, ResponseHeaderTimeoutMS: 2000, DialTimeoutMS: 200, HealthIntervalMS: 100}
	for i, a := range []netip.Addr{tasks[1].IPv4, tasks[1].IPv6} {
		svc := fmt.Sprint("v", i)
		spec.Services = append(spec.Services, ingress.Service{ID: svc, Backends: []ingress.BackendSpec{{ID: svc, Task: desired.TaskPrefix + "b", Network: "r5", Generation: taskR[1].Generation, Address: a, Port: 8080, Weight: 1, Capacity: 4, HealthPath: "/ping"}}})
		paths := []string{"/ping", "/events", "/upgrade", "/slow"}
		if i == 1 {
			paths = []string{"/v6"}
		}
		for _, p := range paths {
			spec.Routes = append(spec.Routes, ingress.Route{ID: svc + p, Host: "app.test", Prefix: p, Service: svc})
		}
	}
	appR := submit(appKey, spec, 0, false, state.Applied)
	wait("actual remote ingress health", func() bool { o := observe("a", appKey); return o.Ready && o.Ingress != nil && o.Ingress.Requests == 0 })
	blockedTask := tasks[1]
	blockedTask.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{7}}
	submit(desired.TaskPrefix+"b", blockedTask, taskR[1].Revision, false, state.Invalid)
	blockedTun := tuns[0]
	blockedTun.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{8}}
	submit(desired.TunnelPrefix+"a", blockedTun, tunR[0].Revision, false, state.Invalid)
	probe := func(mode string) {
		t.Helper()
		args := []string{"nsenter", "--net=" + nsPath[0], "--", self, "-test.run=^TestSystemHTTPClient$", "-test.v", "-test.timeout=15s"}
		c := exec.CommandContext(ctx, args[0], args[1:]...)
		c.Env = append(os.Environ(), "SFC_R5_HTTP_MODE="+mode, "SFC_R5_CERT="+cert)
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatal(mode, err, string(out))
		}
		t.Logf("HTTP %s: %s", mode, out)
	}
	probe("normal")
	probe("saturation")
	wait("cancelled saturation requests returned", func() bool { o := observe("a", appKey); return o.Ingress != nil && o.Ingress.Requests == 0 })
	probe("load")
	wait("bounded load request refs returned", func() bool { o := observe("a", appKey); return o.Ingress != nil && o.Ingress.Requests == 0 })
	probe("normal")
	startHold := func() *systemProcess {
		p := startSystemProcess(t, ctx, filepath.Join(root, fmt.Sprintf("holder-http-%d.log", time.Now().UnixNano())), []string{"nsenter", "--net=" + nsPath[0], "--", self, "-test.run=^TestSystemHTTPClient$", "-test.v", "-test.timeout=15s"}, []string{"SFC_R5_HTTP_MODE=hold", "SFC_R5_CERT=" + cert}, &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL})
		clients = append(clients, p)
		wait("real held SSE", func() bool { b, _ := os.ReadFile(p.log); return bytes.Contains(b, []byte("r5-stream-ready")) })
		return p
	}
	beforeTun := observe("a", desired.TunnelPrefix+"a")
	original := observe("b", desired.TaskPrefix+"b")
	held := startHold()
	wait("one durable live request", func() bool { o := observe("a", appKey); return o.Ingress != nil && o.Ingress.Requests == 1 })
	daemons[0].stop(t, true)
	held.waitExit(t)
	startDaemon(0)
	wait("same DB/old HTTP pins settled/original native refs", func() bool {
		o := observe("a", appKey)
		n := observe("a", desired.TunnelPrefix+"a")
		return o.Ready && o.Ingress != nil && o.Ingress.Requests == 0 && n.NativeID == beforeTun.NativeID && n.Journal.Pins["packet-plane"] == beforeTun.Journal.Pins["packet-plane"] && n.Journal.Consumers == 3
	})
	probe("normal")
	if _, err := apis[1].API.ContainerStop(ctx, original.NativeID, client.ContainerStopOptions{}); err != nil {
		t.Fatal(err)
	}
	wait("settled original container resumed", func() bool {
		o := observe("b", desired.TaskPrefix+"b")
		return o.Ready && o.NativeID == original.NativeID
	})
	wait("remote health after original resume", func() bool { return observe("a", appKey).Ready })
	// A real native MTU change invalidates the observed path, not Desired/IDs.
	run("nsenter", "--net="+nsPath[0], "--", "ip", "link", "set", "r5-n0", "mtu", "1300")
	wait("path unavailable after native MTU decrease", func() bool {
		o := observe("a", desired.TunnelPrefix+"a")
		return !o.Ready && o.Tunnel != nil && o.Tunnel.PacketUsers == 0
	})
	wait("remote ingress observed unavailable", func() bool { return !observe("a", appKey).Ready })
	probe("unavailable")
	run("nsenter", "--net="+nsPath[0], "--", "ip", "link", "set", "r5-n0", "mtu", "1500")
	wait("native path/health restored", func() bool { return observe("a", appKey).Ready })
	probeUDP()
	probe("normal")
	// All controls stay alive through a real UDP partition of the old leader.
	status, err := cli("c0", "status")
	if err != nil {
		t.Fatal(err)
	}
	old := status.Leader
	oldIndex := -1
	for i, n := range names {
		if n == old {
			oldIndex = i
		}
	}
	if oldIndex < 2 {
		t.Fatal(status)
	}
	port := 45100 + oldIndex - 2
	file := filepath.Join(root, "partition.nft")
	script := fmt.Sprintf("add table inet sfc_r5_partition\nadd chain inet sfc_r5_partition output { type filter hook output priority -20; policy accept; }\nadd rule inet sfc_r5_partition output udp sport %d udp dport { 45100, 45101, 45102 } drop\nadd rule inet sfc_r5_partition output udp dport %d udp sport { 45100, 45101, 45102 } drop\n", port, port)
	os.WriteFile(file, []byte(script), 0600)
	run("nft", "-f", file)
	majority := ""
	wait("new majority while old control alive", func() bool {
		for _, n := range names[2:] {
			if n == old {
				continue
			}
			r, e := cli(n, "status")
			if e == nil && r.Leader != "" && r.Leader != old {
				majority = r.Leader
				return true
			}
		}
		return false
	})
	// Submit through a surviving control explicitly; automatic client retry is
	// never the mechanism that discovers or commits this majority write.
	sequence++
	c := state.Command{Actor: keys[5].Actor(), Epoch: 1, RequestID: fmt.Sprint("r5-", sequence), Key: "workload/checkpoint/majority", Value: "majority"}
	b, _ := state.EncodeCommand(c)
	p := filepath.Join(root, "majority.bin")
	os.WriteFile(p, b, 0600)
	r, err := cli(majority, "submit", p)
	if err != nil || r.Committed == nil || r.Committed.Result.Code != state.Applied {
		t.Fatal("majority commit", r, err)
	}
	c.RequestID = "partition-no-quorum"
	c.Key = "workload/checkpoint/minority"
	b, _ = state.EncodeCommand(c)
	os.WriteFile(p, b, 0600)
	r, err = cli(old, "submit", p)
	if err == nil || r.Committed != nil {
		t.Fatal("minority accepted", r, err)
	}
	probe("normal")
	run("nft", "delete", "table", "inet", "sfc_r5_partition")
	wait("old control rejoined prefix", func() bool {
		r, e := cli(old, "--local", "get", "workload/checkpoint/majority")
		return e == nil && r.Object != nil && string(r.Object.Value) == "majority"
	})
	r, err = cli(majority, "get", "workload/checkpoint/minority")
	if err != nil || r.Object == nil || r.Object.Present {
		t.Fatal("minority changed Shared", r, err)
	}
	// Keep all service data and packet ownership while the voting group stops.
	for i := 2; i < 5; i++ {
		daemons[i].stop(t, false)
	}
	probe("normal")
	for i := 2; i < 5; i++ {
		startDaemon(i)
	}
	wait("same voting DB restored", func() bool { r, e := cli("c0", "status"); return e == nil && r.Leader != "" })
	// Drain with a real active stream: no synthetic Gone and no early pin return.
	held = startHold()
	spec.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{9}}
	d := submit(appKey, spec, appR.Revision, false, state.Applied)
	var o ModuleObservation
	wait("owner applied committed Drain with original active request", func() bool {
		o = observe("a", appKey)
		return o.Revision == d.Revision && o.Ingress != nil && o.Ingress.Revision == d.Revision && o.Ingress.Draining
	})
	if o.Ingress.Gone || o.Ingress.Requests != 1 {
		t.Fatal("premature Gone", o)
	}
	probe("unavailable")
	held.stop(t, false)
	retire := func(peer, key string, revision uint64) state.Result {
		t.Helper()
		var o ModuleObservation
		wait("native Gone "+key, func() bool { o = observe(peer, key); return o.Ready && len(o.Retirement) > 0 })
		// Preserve the owner's canonical typed field order and integer bytes.
		r := submit(key, json.RawMessage(o.Retirement), revision, false, state.Applied)
		return submit(key, nil, r.Revision, true, state.Applied)
	}
	retire("a", appKey, d.Revision)
	wait("all original ingress path refs returned", func() bool { return observe("a", desired.TunnelPrefix+"a").Journal.Consumers == 1 })
	for i := 0; i < 2; i++ {
		tasks[i].Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{byte(20 + i)}}
		r := submit(desired.TaskPrefix+names[i], tasks[i], taskR[i].Revision, false, state.Applied)
		retire(names[i], desired.TaskPrefix+names[i], r.Revision)
	}
	for _, p := range udp {
		p.stop(t, false)
	}
	for i := 0; i < 2; i++ {
		tuns[i].Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{byte(30 + i)}}
		r := submit(desired.TunnelPrefix+names[i], tuns[i], tunR[i].Revision, false, state.Applied)
		retire(names[i], desired.TunnelPrefix+names[i], r.Revision)
	}
	for i := 0; i < 2; i++ {
		bridges[i].Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{byte(40 + i)}}
		r := submit(desired.BridgePrefix+names[i], bridges[i], bridgeR[i].Revision, false, state.Applied)
		retire(names[i], desired.BridgePrefix+names[i], r.Revision)
	}
	normal = true
	t.Logf("full actual services: 3 voters/2 nonvoters, independent Engines/dual-stack container/TUN, H1/h2/h3, bounded pressure, SIGKILL same DB/request+path pins, original stopped ID resume, native MTU fault/recovery, alive-control partition/%s majority handoff/minority refusal/rejoin, all controls offline service retention, active-stream Drain, signed Gone and exact native retirement", majority)
}

func mustIPNet(s string) *net.IPNet {
	ip, n, e := net.ParseCIDR(s)
	if e != nil {
		panic(e)
	}
	n.IP = ip
	return n
}
func systemCertificate(t *testing.T, root string) (string, string) {
	t.Helper()
	// The certificate store refuses Ed25519; ECDSA P-256 is its default.
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	pub := &key.PublicKey
	s := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "app.test"}, DNSNames: []string{"app.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, s, s, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	cert, private := filepath.Join(root, "cert.pem"), filepath.Join(root, "private.pem")
	if e = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600); e != nil {
		t.Fatal(e)
	}
	return cert, private
}
func systemImportBackend(t *testing.T, ctx context.Context, c *engine.Client, path string) string {
	t.Helper()
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		t.Fatal(e)
	}
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if e = w.WriteHeader(&tar.Header{Name: "backend", Mode: 0755, Size: info.Size()}); e != nil {
		t.Fatal(e)
	}
	if _, e = io.Copy(w, f); e != nil {
		t.Fatal(e)
	}
	w.Close()
	stream, e := c.API.ImageImport(ctx, client.ImageImportSource{Source: &b, SourceName: "-"}, "sfc-r5:local", client.ImageImportOptions{Changes: []string{`CMD ["/backend"]`}})
	if e != nil {
		t.Fatal(e)
	}
	defer stream.Close()
	d := json.NewDecoder(stream)
	for {
		var msg struct{ Error string }
		e = d.Decode(&msg)
		if e == io.EOF {
			break
		}
		if e != nil || msg.Error != "" {
			t.Fatal("image import", msg.Error, e)
		}
	}
	im, e := c.API.ImageInspect(ctx, "sfc-r5:local")
	if e != nil {
		t.Fatal(e)
	}
	return im.ID
}
