// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/tests/enginefixture"
	"github.com/miekg/dns"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

type kernelDNSPlan struct {
	Config        services.DNSConfig
	Reference     services.ReferenceConsumer
	Allocation    network.Allocation
	Task, Tag     string
	Gateway       netip.Addr
	BackendDigest [32]byte
}

type kernelDNSClient struct {
	Schema          uint8
	Image, ImageRef string
	Spec            workload.ContainerSpec
}

type kernelDNSReady struct {
	Status       services.DNSOwnerStatus
	Authority    json.RawMessage
	Config       services.DNSConfig
	NativeID     string
	DBDigest     [32]byte
	ClientDigest [32]byte
	Consumers    map[string]reconcile.Lease
}

type kernelDNSRuntime struct {
	root          string
	plan          kernelDNSPlan
	client        kernelDNSClient
	c             *engine.Client
	n             *network.Manager
	w             *workload.Manager
	o             *services.DNSOwner
	key           ed25519.PrivateKey
	mu            sync.Mutex
	policy        services.DNSOwnerPolicy
	denied        atomic.Bool
	done          bool
	claim         *services.ReferenceClose
	imageAdmitted bool
	clientGone    bool
}

type kernelDNSImageAdmission struct {
	Schema        uint8
	Tag           string
	BackendDigest [32]byte
}

// Pure policy input plus one test-owned upstream socket; no fake query/native
// facts. The host must reset immediately after ready while its query is live.
func planKernelDNS(t *testing.T, guest string, catalog access.Catalog, networks tenancy.Networks, authority services.Authority, source services.Source) (kernelDNSPlan, services.Authority, *net.UDPConn) {
	t.Helper()
	backend := os.Getenv("SFC_DOCKER_TEST_BACKEND")
	if !filepath.IsAbs(backend) {
		t.Fatal("physical DNS fixture requires its explicit prebuilt static backend")
	}
	var upstream *net.UDPConn
	t.Cleanup(func() {
		if upstream != nil {
			_ = upstream.Close()
		}
	})
	var err error
	upstream, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	task := "workload/task/first/kernel/probe"
	networkID := source.Tenant + "/" + source.Network
	authority, allocation, err := authority.ReserveStatic(task+"/lan/0", hex.EncodeToString(source.Owner[:]), networkID, networkID+"/"+source.Pool, 2, source.Gateway.Next())
	if err != nil {
		t.Fatal(err)
	}
	cfg := services.DNSConfig{Tenant: source.Tenant, ID: "kernel-dns", Network: source.Network, Pool: source.Pool, Source: 1, Serial: 1, Enabled: true, Zone: "kernel.sfc.test.", TTL: 5, NegativeTTL: 3, QuerySeconds: 30, MaxQueries: 4, MaxCacheEntries: 2, MaxResponseBytes: 4096,
		Names: []services.DNSName{{Name: "probe", Endpoint: allocation.Endpoint, Generation: allocation.Generation}}, Upstreams: []netip.AddrPort{upstream.LocalAddr().(*net.UDPAddr).AddrPort()}}
	authority, ref, err := authority.GrantDNSInstance(catalog, networks, "admin", 0, cfg)
	if err != nil {
		t.Fatal(err)
	}
	tag := sha256.Sum256([]byte(guest + "/dns-backend"))
	return kernelDNSPlan{Config: cfg, Reference: ref, Allocation: allocation, Task: task, Gateway: source.Gateway, Tag: fmt.Sprintf("e3-kernel-%x", tag[:8]), BackendDigest: kernelFileDigest(t, backend)}, authority, upstream
}

func newKernelDNS(t *testing.T, root string, input kernelRouteInput, c *engine.Client, n *network.Manager, key ed25519.PrivateKey) *kernelDNSRuntime {
	t.Helper()
	catalog, err := access.Decode(input.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	networks, err := tenancy.Decode(input.Networks)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := services.DecodeAuthority(input.Authority)
	if err != nil {
		t.Fatal(err)
	}
	s := &kernelDNSRuntime{root: root, plan: input.DNS, c: c, n: n, key: key,
		policy: services.DNSOwnerPolicy{Catalog: catalog, Networks: networks, Authority: authority, Actor: "admin", Config: input.DNS.Config, Bridge: input.Reference.Native.Key, BridgeGeneration: input.Reference.Native.Generation, MaxConnections: 4}}
	s.denied.Store(true)
	if _, err := os.Lstat(filepath.Join(root, "dns-image-admitted.json")); err == nil {
		admission := readKernelRouteFile[kernelDNSImageAdmission](t, filepath.Join(root, "dns-image-admitted.json"))
		if admission.Schema != 1 || admission.Tag != s.plan.Tag || admission.BackendDigest != s.plan.BackendDigest {
			t.Fatal("original DNS image admission changed")
		}
		s.imageAdmitted = true
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return s
}

func (s *kernelDNSRuntime) openOwner() error {
	options := services.DNSOwnerOptions{Cluster: s.policy.Networks.Cluster(), Key: s.key, Network: s.n, Workload: s.w, Roots: []string{"sfc.test."}, MaxViews: 16, MaxQueries: 8, MaxConnections: 4, IdleTimeout: time.Second,
		Current: func(_ context.Context, tenant, id string) (services.DNSOwnerPolicy, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if tenant != s.policy.Config.Tenant || id != s.policy.Config.ID {
				return services.DNSOwnerPolicy{}, services.ErrLease
			}
			return s.policy, nil
		}, Permit: func(ctx context.Context, _ services.DNSOwnerPolicy) error {
			if s.denied.Load() {
				return errors.New("kernel fixture current DNS permit denied")
			}
			return ctx.Err()
		}}
	var err error
	s.o, err = services.OpenDNSOwner(filepath.Join(s.root, "dns.db"), options)
	return err
}

func (s *kernelDNSRuntime) configure(cfg services.DNSConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	authority, _, err := s.policy.Authority.GrantDNSInstance(s.policy.Catalog, s.policy.Networks, "admin", s.plan.Reference.Generation, cfg)
	if err == nil {
		s.policy.Authority, s.policy.Config = authority, cfg
	}
	return err
}

func (s *kernelDNSRuntime) prepare(t *testing.T, ctx context.Context, upstream *net.UDPConn) kernelDNSReady {
	t.Helper()
	backend := os.Getenv("SFC_DOCKER_TEST_BACKEND")
	if kernelFileDigest(t, backend) != s.plan.BackendDigest {
		t.Fatal("prepared backend changed after immutable input")
	}
	imageRef := "sfc-boundary/" + s.plan.Tag + ":local"
	if _, err := s.c.API.ImageInspect(ctx, imageRef); !cerrdefs.IsNotFound(err) {
		t.Fatal("refuse existing kernel DNS image", err)
	}
	writeKernelRouteJSON(t, filepath.Join(s.root, "dns-image-admitted.json"), kernelDNSImageAdmission{Schema: 1, Tag: s.plan.Tag, BackendDigest: s.plan.BackendDigest})
	s.imageAdmitted = true
	native := enginefixture.ImportPrepared(t, ctx, s.c, s.plan.Tag, backend, []string{`USER 10001:10001`, `ENV SFC_DNS_FIXTURE=1`})
	image, err := s.c.Image(ctx, native.Image, false)
	if err != nil {
		t.Fatal(err)
	}
	process, err := workload.ResolveImageProcess(image, workload.ProcessOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	s.client = kernelDNSClient{Schema: 1, Image: native.Image, ImageRef: native.ImageRef, Spec: workload.ContainerSpec{Schema: 1, Node: s.c.Owner, Image: native.Image, Bridge: s.policy.Bridge, BridgeGeneration: s.policy.BridgeGeneration, IPv4: s.plan.Allocation.Address, Memory: 32 << 20, NanoCPU: 100000000, Process: &process,
		Resolver: &workload.Resolver{Servers: []netip.Addr{s.plan.Gateway}, Search: []string{"kernel.sfc.test"}}, Readiness: &workload.HTTPReadiness{Path: "/ping", Port: 8080}}}
	s.w, err = workload.OpenManager(filepath.Join(s.root, "dns-workload.db"), s.c, s.n)
	if err != nil {
		t.Fatal(err)
	}
	// Persist the original task intent before publishing its recovery descriptor
	// or borrowing DNS resources. Early DNS failure can then retire that same
	// unsent task rather than finding a descriptor with no task journal.
	if err := s.w.Desired(s.plan.Task, 2, 2, &s.client.Spec, 2); err != nil {
		t.Fatal(err)
	}
	writeKernelRouteJSON(t, filepath.Join(s.root, "dns-client.json"), s.client)
	if err := s.openOwner(); err != nil {
		t.Fatal(err)
	}
	s.permitAndApply(t, ctx)
	if err := s.w.Step(ctx, s.plan.Task); err != nil {
		t.Fatal(err)
	}
	s.waitClient(t, ctx, "")
	s.query(t, ctx, "udp")
	s.query(t, ctx, "tcp")
	for s.o.Status(s.plan.Config.Tenant, s.plan.Config.ID).Queries != 0 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	seen := make(chan error, 1)
	if deadline, ok := ctx.Deadline(); ok {
		_ = upstream.SetReadDeadline(deadline)
	}
	go func() {
		var raw [4096]byte
		n, _, err := upstream.ReadFromUDP(raw[:])
		var message dns.Msg
		if err == nil && (message.Unpack(raw[:n]) != nil || len(message.Question) != 1 || message.Question[0].Name != "hold.example.net.") {
			err = errors.New("unexpected held DNS upstream query")
		}
		seen <- err // Never sends an answer; the original query stays unfinished.
	}()
	request := new(dns.Msg)
	request.SetQuestion("hold.example.net.", dns.TypeA)
	raw, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = s.exchange(ctx, "udp", raw) }()
	select {
	case err := <-seen:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	next := s.plan.Config
	next.Source++
	next.Serial++
	if err := s.configure(next); err != nil {
		t.Fatal(err)
	}
	if err := s.o.Apply(ctx, next.Tenant, next.ID); err != nil {
		t.Fatal(err)
	}
	status := s.o.Status(next.Tenant, next.ID)
	if status.Queries != 1 || status.Settings.Users != 1 || !status.Ready {
		t.Fatal("actual unfinished DNS query/user was not retained across hot change", status)
	}
	viewFound := false
	for _, view := range status.Views {
		if view.Retired && view.Queries == 1 && view.Source == s.plan.Config.Source {
			viewFound = true
		}
	}
	if !viewFound {
		t.Fatal("held original DNS view was not retired")
	}
	owner, err := s.w.Status(ctx, s.plan.Task)
	if err != nil || !owner.Running {
		t.Fatal("actual DNS fixture client", err)
	}
	row, err := s.n.View(s.policy.Bridge)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := s.policy.Authority.Encode()
	if err != nil {
		t.Fatal(err)
	}
	digest := kernelFileDigest(t, filepath.Join(s.root, "dns.db"))
	if current := s.o.Status(next.Tenant, next.ID); current.Queries != 1 || current.Settings.Users != 1 {
		t.Fatal("original query ended while capturing pre-reset checkpoint")
	}
	return kernelDNSReady{Status: status, Authority: authority, Config: next, NativeID: owner.NativeID, DBDigest: digest, ClientDigest: kernelFileDigest(t, filepath.Join(s.root, "dns-client.json")), Consumers: row.Consumers}
}

func (s *kernelDNSRuntime) permitAndApply(t *testing.T, ctx context.Context) {
	t.Helper()
	before, err := s.n.View(s.policy.Bridge)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.o.Apply(ctx, s.policy.Config.Tenant, s.policy.Config.ID); err == nil || s.o.Status(s.policy.Config.Tenant, s.policy.Config.ID).Ready {
		t.Fatal("DNS rebind bypassed current permit", err)
	}
	after, err := s.n.View(s.policy.Bridge)
	a, _ := json.Marshal(before.Consumers)
	b, _ := json.Marshal(after.Consumers)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("denied DNS permit changed original Bridge consumers", err)
	}
	s.denied.Store(false)
	if err := s.o.Apply(ctx, s.policy.Config.Tenant, s.policy.Config.ID); err != nil {
		t.Fatal(err)
	}
}

func (s *kernelDNSRuntime) resume(t *testing.T, ctx context.Context, saved kernelDNSReady, boot [32]byte) {
	t.Helper()
	s.client = readKernelRouteFile[kernelDNSClient](t, filepath.Join(s.root, "dns-client.json"))
	if s.client.Schema != 1 || s.client.Image != s.client.Spec.Image || s.client.Spec.Node != s.c.Owner || s.client.Spec.Bridge != s.policy.Bridge || s.client.Spec.BridgeGeneration != s.policy.BridgeGeneration || s.client.Spec.IPv4 != s.plan.Allocation.Address || s.client.Spec.Resolver == nil || len(s.client.Spec.Resolver.Servers) != 1 || s.client.Spec.Resolver.Servers[0] != s.plan.Gateway {
		t.Fatal("original DNS client descriptor changed")
	}
	s.policy.Config = saved.Config
	var err error
	s.policy.Authority, err = services.DecodeAuthority(saved.Authority)
	if err != nil {
		t.Fatal(err)
	}
	image, err := s.c.API.ImageInspect(ctx, s.client.ImageRef)
	if err != nil || image.ID != s.client.Image || image.Config == nil || image.Config.Labels["org.sfc.test.owner"] != s.plan.Tag {
		t.Fatal("original DNS fixture image changed across boot", err)
	}
	s.w, err = workload.OpenManager(filepath.Join(s.root, "dns-workload.db"), s.c, s.n)
	if err != nil {
		t.Fatal(err)
	}
	row, err := s.w.View(s.plan.Task)
	wanted, _ := json.Marshal(s.client.Spec)
	if err != nil || !row.State.Applied.Present || row.State.Applied.Generation != 2 || row.State.Applied.Spec != string(wanted) {
		t.Fatal("original DNS task journal/spec changed", err)
	}
	var started unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &started); err != nil {
		t.Fatal(err)
	}
	if err := s.openOwner(); err != nil {
		t.Fatal(err)
	}
	status := s.o.Status(saved.Config.Tenant, saved.Config.ID)
	if status.Ready || status.Queries != 0 || status.Settings.Users != 0 || status.Settings.Current != saved.Status.Settings.Current {
		t.Fatal("boot resume lost original group or promoted stored sockets to Ready", status)
	}
	for _, old := range saved.Status.Views {
		if !old.Retired || old.Queries == 0 {
			continue
		}
		found := false
		for _, view := range status.Views {
			if view.ID == old.ID && view.Retired && view.Queries == 0 && view.Hold.Boot == boot && view.Hold.Certain && view.Hold.Mono >= started.Sec {
				found = true
			}
		}
		if !found {
			t.Fatal("old query view lost its current-boot full TTL hold")
		}
	}
	state, err := s.w.Status(ctx, s.plan.Task)
	if err != nil || state.NativeID != saved.NativeID || state.Running || !state.Startable {
		t.Fatal("DNS client must be its original exited, startable native", err)
	}
	// This starts the fixture CLIENT explicitly, not a product restart policy.
	if _, err := s.c.API.ContainerStart(ctx, saved.NativeID, client.ContainerStartOptions{}); err != nil {
		t.Fatal(err)
	}
	s.waitClient(t, ctx, saved.NativeID)
	s.permitAndApply(t, ctx)
	s.query(t, ctx, "udp")
	s.query(t, ctx, "tcp")
	row, err = s.n.View(s.policy.Bridge)
	a, _ := json.Marshal(saved.Consumers)
	b, _ := json.Marshal(row.Consumers)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("DNS boot rebind replaced original Bridge pins", err)
	}
}

// Running is not proof that the client HTTP listener has started. Reuse the
// product's bounded HTTP readiness probe; no DNS query or Start is retried.
func (s *kernelDNSRuntime) waitClient(t *testing.T, ctx context.Context, expected string) {
	t.Helper()
	for {
		status, err := s.w.Status(ctx, s.plan.Task)
		if err != nil || !status.Running || expected != "" && status.NativeID != expected {
			t.Fatal("original DNS client native readiness", err, status)
		}
		if status.HTTPConfigured && status.HTTPReady && status.Ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("DNS client HTTP listener not ready", ctx.Err(), status)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (s *kernelDNSRuntime) exchange(ctx context.Context, protocol string, wire []byte) ([]byte, error) {
	server := s.client.Spec.Resolver.Servers[0]
	url := "http://" + s.plan.Allocation.Address.String() + ":8080/dns-query?transport=" + protocol + "&server=" + netip.AddrPortFrom(server, 53).String()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 4 * time.Second}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(raw) > 4096 || response.StatusCode != http.StatusOK {
		return nil, errors.Join(err, fmt.Errorf("DNS fixture HTTP status=%d", response.StatusCode))
	}
	return raw, nil
}

func (s *kernelDNSRuntime) query(t *testing.T, ctx context.Context, protocol string) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("probe.kernel.sfc.test.", dns.TypeA)
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.exchange(ctx, protocol, wire)
	if err != nil {
		t.Fatal("actual DNS query", protocol, err)
	}
	var reply dns.Msg
	if err := reply.Unpack(raw); err != nil || reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
		t.Fatal("actual DNS reply", protocol, err)
	}
	a, ok := reply.Answer[0].(*dns.A)
	if !ok || a.A.String() != s.plan.Allocation.Address.String() {
		t.Fatal("DNS resolved a different original allocation")
	}
}

// Cleanup may explicitly disable a partially applied policy, but does not
// recreate a lost DNS/Task journal, re-import an image or resubmit a Start.
func (s *kernelDNSRuntime) finish(ctx context.Context) error {
	if s == nil || s.done {
		return nil
	}
	if s.w == nil && !s.clientGone {
		if _, err := os.Lstat(filepath.Join(s.root, "dns-client.json")); err == nil {
			return errors.New("original DNS client journal must be recovered before cleanup")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if s.w != nil {
		if _, err := s.w.View(s.plan.Task); err != nil {
			return errors.Join(err, errors.New("preserve missing original DNS client task record"))
		}
		if err := s.w.Desired(s.plan.Task, 3, 2, nil, 2); err != nil {
			return err
		}
		if err := s.w.Step(ctx, s.plan.Task); err != nil {
			return err
		}
		if gone, err := s.w.Gone(ctx, s.plan.Task, 3, 2); err != nil || !gone {
			return errors.Join(err, errors.New("original DNS client termination unknown"))
		}
		s.clientGone = true
	}
	if s.o != nil {
		cfg := s.plan.Config
		cfg.Source += 2
		cfg.Serial += 2
		cfg.Enabled = false
		if err := s.configure(cfg); err != nil {
			return err
		}
		for {
			proof, err := s.o.Retire(ctx, cfg.Tenant, cfg.ID)
			if err == nil {
				s.claim = proof
				break
			}
			if !errors.Is(err, reconcile.ErrPending) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if s.claim == nil || !s.claim.Settled || !ed25519.Verify(s.key.Public().(ed25519.PublicKey), services.ReferenceCloseBytes(*s.claim), s.claim.Signature) {
			return errors.New("DNS retirement lacks original signed closure")
		}
		if err := s.o.Close(); err != nil {
			return err
		}
		s.o = nil
	}
	if s.w != nil {
		if err := s.w.Close(); err != nil {
			return err
		}
		s.w = nil
	}
	if !s.imageAdmitted {
		s.done = true
		return nil
	}
	imageRef := "sfc-boundary/" + s.plan.Tag + ":local"
	image, err := s.c.API.ImageInspect(ctx, imageRef)
	if err == nil {
		if image.Config == nil || image.Config.Labels["org.sfc.test.owner"] != s.plan.Tag || s.client.Image != "" && image.ID != s.client.Image {
			return engine.ErrOwnership
		}
		if _, err := s.c.API.ImageRemove(ctx, imageRef, client.ImageRemoveOptions{}); err != nil {
			return err
		}
	} else if !cerrdefs.IsNotFound(err) {
		return err
	}
	s.done = true
	return nil
}

func (s *kernelDNSRuntime) reopenRollback(t *testing.T) error {
	if _, err := os.Lstat(filepath.Join(s.root, "dns-client.json")); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	s.client = readKernelRouteFile[kernelDNSClient](t, filepath.Join(s.root, "dns-client.json"))
	checkKernelRoutePrivate(t, filepath.Join(s.root, "dns-workload.db"), false)
	var err error
	s.w, err = workload.OpenManager(filepath.Join(s.root, "dns-workload.db"), s.c, s.n)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(s.root, "dns.db")); errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Lstat(filepath.Join(s.root, "dns.db.owner")); !errors.Is(markerErr, os.ErrNotExist) {
			return errors.New("original DNS owner DB missing; preserve references")
		}
		return nil
	} else if err != nil {
		return err
	}
	checkKernelRoutePrivate(t, filepath.Join(s.root, "dns.db"), false)
	cfg := s.plan.Config
	cfg.Source += 2
	cfg.Serial += 2
	cfg.Enabled = false
	if err := s.configure(cfg); err != nil {
		return err
	}
	return s.openOwner()
}

func (s *kernelDNSRuntime) close() {
	if s == nil {
		return
	}
	if s.o != nil {
		_ = s.o.Close()
		s.o = nil
	}
	if s.w != nil {
		_ = s.w.Close()
		s.w = nil
	}
}

func kernelFileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		t.Fatal("bounded kernel fixture file", path, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(raw)
}
