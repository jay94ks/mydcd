// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"testing"

	"github.com/moby/moby/client"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
)

func TestRealBoundaryManagedAppDNSCLIAndRetirement(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppDNS, true, true)
}

func TestRealBoundaryManagedAppDNSSecondLifecycle(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppDNSSecondLifecycle, true, true)
}

func TestE7ManagedDNSRetainedVolumeAndBoundedLoad(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppE7DNSRetained, true, true, true)
}

func verifyManagedAppDNS(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View, wait func(string, func() bool)) {
	t.Helper()
	key := services.ManagedDNSKey("tenant", "shared-services")
	var row control.AppDNSOwner
	wait("actual managed DNS/current source observation", func() bool {
		apps, err := p.Apps(read().State)
		if err != nil {
			return false
		}
		_, rows, ok := apps.NetworkDNS(r.Identity.Public)
		if !ok || len(rows) != 1 {
			return false
		}
		row = rows[0]
		if r.dnsOwner() == nil || row.Managed == nil || row.Source.Key != key {
			return false
		}
		status := r.dnsOwner().Status(row.Config.Tenant, row.Config.ID)
		e, ok := apps.Execution("tenant", "app")
		if !ok {
			return false
		}
		stage, ok := e.Stage(deployment.ResourceKey("task", "tenant", "app", "web"))
		raw, observeErr := r.observeManaged(ctx, key, read())
		var observed ModuleObservation
		return ok && stage.Observation != nil && stage.Observation.Applied && observeErr == nil && json.Unmarshal(raw, &observed) == nil && observed.Ready && observed.DNS != nil && observed.DNS.Desired > 0 && observed.DNS.Desired == observed.DNS.Applied && observed.DNS.Applied == observed.DNS.Observed && status.Ready && status.Settings.Applied == row.Config.Source
	})
	v := read()
	material, actual, err := p.AppDNSMaterial(v.State, r.Identity.Public, "tenant", row.Config.ID)
	if err != nil || control.AppDNSNativeDigest(actual) != control.AppDNSNativeDigest(row) {
		t.Fatal("current exact DNS source", err)
	}
	permit, err := p.NativePermit(v.State, r.Identity.Public, control.NativeRequest{Source: row.Source, DNS: row.Config.ID})
	if err != nil || permit.Kind != "dns" || permit.Spec != control.AppDNSNativeDigest(row) {
		t.Fatal("current DNS native permit", err)
	}
	wrong := row.Source
	wrong.Generation++
	if _, err = p.NativePermit(v.State, r.Identity.Public, control.NativeRequest{Source: wrong, DNS: row.Config.ID}); err == nil {
		t.Fatal("wrong DNS generation permitted")
	}
	if _, err = p.NativePermit(v.State, [32]byte{55}, control.NativeRequest{Source: row.Source, DNS: row.Config.ID}); err == nil {
		t.Fatal("uninstalled DNS owner permitted")
	}
	var address string
	for _, record := range material.Config.Names {
		if record.Name == "web."+material.Config.Zone {
			if a, ok := material.Authority.AddressBook().Allocation(record.Endpoint); ok {
				address = a.Address.String()
			}
		}
	}
	if address == "" {
		t.Fatal("committed Task address was not projected")
	}
	c := &http.Client{Timeout: 3e9, Transport: &http.Transport{Proxy: nil}}
	defer c.CloseIdleConnections()
	for _, protocol := range []string{"udp", "tcp"} {
		req, e := http.NewRequestWithContext(ctx, "GET", "http://"+address+":8080/resolve?name=web&transport="+protocol, nil)
		if e != nil {
			t.Fatal(e)
		}
		response, e := c.Do(req)
		if e != nil {
			t.Fatal("actual container DNS request", protocol, e)
		}
		raw, e := io.ReadAll(io.LimitReader(response.Body, 128))
		_ = response.Body.Close()
		if e != nil || response.StatusCode != 200 || string(raw) != address {
			status := r.dnsOwner().Status(row.Config.Tenant, row.Config.ID)
			t.Fatal("name/source/native mismatch", protocol, response.StatusCode, string(raw), e, "DNS failures", status.QueryFailures, "last", status.LastQueryError, "settings", status.Settings, "queries", status.Queries, "ready", status.Ready)
		}
	}
	verifyManagedDNSLibc(t, ctx, r, address, row.Config.ID)
	raw, _ := json.Marshal(control.NativeRequest{Source: row.Source, DNS: row.Config.ID})
	reply, err := r.appCall(ctx, "app-native-permit", raw)
	if err != nil || len(reply.Data) == 0 {
		t.Fatal("actual quorum DNS permit", err)
	}
	t.Log("actual CLI/managed Runtime/current quorum permit -> shared DNS source -> UDP/TCP/search in native container; original native view/query store survives same DB; wrong generation/member rejected")
}

func verifyManagedDNSLibc(t *testing.T, ctx context.Context, r *Runtime, address, serviceID string) {
	t.Helper()
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	native, running, err := r.workload.NativeIdentity(ctx, key)
	if err != nil || !running {
		t.Fatal("original DNS client identity", err)
	}
	info, err := r.docker.API.ContainerInspect(ctx, native, client.ContainerInspectOptions{})
	if err != nil || info.Container.State == nil || !info.Container.State.Running || info.Container.State.Pid < 1 || info.Container.ResolvConfPath == "" {
		t.Fatal("original DNS client namespace/resolver", err)
	}
	// Only the child mount namespace sees Docker's original resolver file.
	// The original host file is never written; clients use the same PHP/libc
	// binaries as the prepared image. No SQL or second orchestration fixture.
	program := `import subprocess,sys,pathlib,time,json,concurrent.futures
original=pathlib.Path('/etc/resolv.conf').read_bytes()
subprocess.run(['mount','--bind',sys.argv[1],'/etc/resolv.conf'],check=True)
try:
 print('actual Docker resolver',pathlib.Path('/etc/resolv.conf').read_text(),flush=True)
 def php_lookup(name):
  at=time.monotonic()
  php='for($i=0;$i<3;$i++){echo gethostbyname($argv[1]),"\\n";}'
  p=subprocess.run(['/usr/bin/php8.3','-n','-r',php,name],capture_output=True,text=True,timeout=8)
  print('actual PHP',name,p.returncode,p.stdout,p.stderr,'elapsed',time.monotonic()-at,flush=True)
  assert p.returncode==0 and p.stdout.splitlines()==[sys.argv[2]]*3
 def addrinfo_lookup(name):
  script='import socket,sys,json; print(json.dumps(sorted(set(a[4][0] for a in socket.getaddrinfo(sys.argv[1],None)))))'
  p=subprocess.run(['python3','-c',script,name],capture_output=True,text=True,timeout=8)
  print('actual glibc getaddrinfo',name,p.returncode,p.stdout,p.stderr,flush=True)
  assert p.returncode==0 and json.loads(p.stdout)==[sys.argv[2]]
 for name in ['web.app.sfc.test.','web']:
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   jobs=[pool.submit(f,name) for f in [php_lookup,addrinfo_lookup]]
   for job in jobs:job.result()
finally:
 subprocess.run(['umount','/etc/resolv.conf'],check=True)
 assert pathlib.Path('/etc/resolv.conf').read_bytes()==original
`
	cmd := exec.CommandContext(ctx, "nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", info.Container.State.Pid), "--", "unshare", "--mount", "--propagation", "private", "python3", "-c", program, info.Container.ResolvConfPath, address)
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal("actual managed Docker/libc DNS client", err, r.dnsOwner().Status("tenant", serviceID))
	}
}
