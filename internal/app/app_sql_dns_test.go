// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/miekg/dns"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

// The parent enters each ORIGINAL running container's network namespace. This
// is a wire client only; it does not bind a server, change routes or spoof IPs.
func TestManagedDNSQueryHelper(t *testing.T) {
	server := os.Getenv("SFC_SQL_DNS_SERVER")
	if server == "" {
		t.Skip("explicit owned container namespace client only")
	}
	for _, protocol := range []string{"udp", "tcp"} {
		for _, row := range []struct{ name, address string }{{"web.app.sfc.test.", "198.19.80.2"}, {"db.app.sfc.test.", "198.19.80.18"}, {"app.sfc.test.", ""}} {
			q := new(dns.Msg)
			kind := uint16(dns.TypeA)
			if row.address == "" {
				kind = dns.TypeSOA
			}
			q.SetQuestion(row.name, kind)
			c := dns.Client{Net: protocol, Timeout: 2 * time.Second}
			r, _, err := c.Exchange(q, net.JoinHostPort(server, "53"))
			if err != nil || r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
				t.Fatal("original native DNS view", protocol, row.name, r, err)
			}
			if row.address == "" {
				if got := fmt.Sprint(r.Answer[0].(*dns.SOA).Serial); got != os.Getenv("SFC_SQL_DNS_SERIAL") {
					t.Fatal("native SOA differs from shared serial", got)
				}
			} else if r.Answer[0].(*dns.A).A.String() != row.address {
				t.Fatal("native DNS differs from committed Task address", r)
			}
		}
	}
}

// App down returns its own addresses/borrowers. The management DNS instances
// remain until this separate explicit policy change obtains original positive
// closure from BOTH owners. Fixture bridge cleanup is not a DNS close proof.
func retireManagedSQLDNS(t *testing.T, ctx context.Context, a *Runtime, remote sfcp.Peer, root string, cli func([]*os.File, ...string) []byte, read func() cluster.View, wait func(string, func() bool)) {
	t.Helper()
	v := read()
	sources, err := a.controlPolicy.ManagedDNS(v.State)
	key := services.ManagedDNSKey("tenant", "app-services")
	source, found := sources[key]
	if err != nil || !found || !source.Definition.Policy.Enabled {
		t.Fatal("original managed DNS policy before explicit cleanup", err)
	}
	// Both app borrows are already gone, but their management servers remain.
	apps, err := a.controlPolicy.Apps(v.State)
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range [][32]byte{a.Identity.Public, [32]byte(remote.Key)} {
		authority, rows, known := apps.NetworkDNS(owner)
		if !known || len(rows) != 1 || !rows[0].Config.Enabled {
			t.Fatal("app down removed management DNS")
		}
		ref, exists := authority.ReferenceConsumer(rows[0].Reference)
		if !exists || ref.Closed != nil {
			t.Fatal("app down closed management instance")
		}
	}
	source.Definition.Policy.Enabled = false
	encoded, err := json.Marshal(source.Definition)
	var payload map[string]any
	if err != nil || json.Unmarshal(encoded, &payload) != nil {
		t.Fatal(err)
	}
	input := struct {
		Schema  uint8            `yaml:"schema"`
		Tenant  string           `yaml:"tenant"`
		Changes []map[string]any `yaml:"changes"`
	}{Schema: 1, Tenant: "tenant", Changes: []map[string]any{{"id": "disable-dns", "action": "configure-network-dns", "expected": v.State.Object(key).Revision, "payload": payload}}}
	raw, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	applyManagementChanges(t, root, "sql-dns-close", raw, func(args ...string) { cli(nil, args...) })
	wait("both original management DNS instances positively close and return Bridge pins", func() bool {
		apps, err := a.controlPolicy.Apps(read().State)
		if err != nil {
			return false
		}
		for _, owner := range [][32]byte{a.Identity.Public, [32]byte(remote.Key)} {
			authority, rows, known := apps.NetworkDNS(owner)
			if !known || len(rows) != 1 || rows[0].Config.Enabled {
				return false
			}
			ref, exists := authority.ReferenceConsumer(rows[0].Reference)
			if !exists || ref.Closed == nil {
				return false
			}
		}
		return true
	})
	local := a.dnsOwner()
	apps, _ = a.controlPolicy.Apps(read().State)
	_, rows, _ := apps.NetworkDNS(a.Identity.Public)
	if local == nil || len(rows) != 1 {
		t.Fatal("original local DNS journal missing")
	}
	status := local.Status(rows[0].Config.Tenant, rows[0].Config.ID)
	if status.Ready || status.Failed || status.Queries != 0 || status.Sockets != 0 || status.Settings.Users != 0 {
		t.Fatal("positive closure retained local I/O", status)
	}
	reply, err := cluster.CallManagement(ctx, a.Mesh, a.Identity, a.controlPolicy.Cluster, remote, cluster.ManagementRequest{Method: "observe", Key: key, Latest: false})
	var observation ModuleObservation
	if err != nil || json.Unmarshal(reply.Data, &observation) != nil || observation.Ready || observation.DNS == nil || observation.DNS.Failed || observation.DNS.Queries != 0 || observation.DNS.Sockets != 0 {
		t.Fatal("positive closure retained remote I/O", err)
	}
	t.Log("explicit tenant DNS disable: both original signed instance closures, queries/sockets/Bridge pins returned; app down did not delete the management policy or sources")
}

func verifyManagedSQLDNS(t *testing.T, ctx context.Context, a *Runtime, engines [2]*engine.Client, natives [2]string, remote sfcp.Peer, read func() cluster.View) {
	t.Helper()
	v := read()
	apps, err := a.controlPolicy.Apps(v.State)
	if err != nil {
		t.Fatal(err)
	}
	var serial uint32
	var source uint64
	var names []string
	for n, key := range [][32]byte{a.Identity.Public, [32]byte(remote.Key)} {
		_, rows, ok := apps.NetworkDNS(key)
		if !ok || len(rows) != 1 {
			t.Fatal("original shared owner missing", n)
		}
		row := rows[0]
		material, _, err := a.controlPolicy.AppDNSMaterial(v.State, key, "tenant", row.Config.ID)
		if err != nil || row.Managed == nil || row.Source.Key != services.ManagedDNSKey("tenant", "app-services") || material.RequestTimeout != 1500*time.Millisecond || row.Config.QuerySeconds != 3 || len(row.Config.Members) != 2 {
			t.Fatal("exact declaration/native policy and two owners", n, err)
		}
		currentNames := []string{}
		for _, name := range row.Config.Names {
			currentNames = append(currentNames, fmt.Sprintf("%s/%s/%d", name.Name, name.Endpoint, name.Generation))
		}
		slices.Sort(currentNames)
		if n == 0 {
			serial, source, names = row.Config.Serial, row.Config.Source, currentNames
		} else if serial != row.Config.Serial || source != row.Config.Source || !slices.Equal(names, currentNames) {
			t.Fatal("owners published different shared projection/source/serial")
		}
		if len(currentNames) != 4 {
			t.Fatal("exact committed web/db default names and explicit aliases missing", currentNames)
		}
		taskKey := deployment.ResourceKey("task", "tenant", "app", []string{"web", "db"}[n])
		task := v.State.Object(taskKey)
		required, err := a.controlPolicy.ManagedTaskDNS(v.State, deployment.ObjectRef{Key: taskKey, Generation: task.Generation, Revision: task.Revision})
		if err != nil || len(required) != 1 || required[0].Reference != row.Reference {
			t.Fatal("exact original Task/DNS activation requirement", n, err)
		}
		var observation ModuleObservation
		var raw []byte
		if n == 0 {
			raw, err = a.observeManaged(ctx, row.Source.Key, v)
		} else {
			reply, callErr := cluster.CallManagement(ctx, a.Mesh, a.Identity, a.controlPolicy.Cluster, remote, cluster.ManagementRequest{Method: "observe", Key: row.Source.Key, Latest: false})
			raw, err = reply.Data, callErr
		}
		if err != nil || json.Unmarshal(raw, &observation) != nil || !observation.Ready || observation.NativeID != appDNSNativeID(row) || observation.DNS == nil || observation.DNS.Desired != row.Config.Source || observation.DNS.Applied != row.Config.Source || observation.DNS.Observed != row.Config.Source {
			t.Fatal("actual source-bound native owner application missing", n, err)
		}
		info, err := engines[n].API.ContainerInspect(ctx, natives[n], client.ContainerInspectOptions{})
		gateway := []string{"198.19.80.1", "198.19.80.17"}[n]
		if err != nil || info.Container.State == nil || !info.Container.State.Running || len(info.Container.HostConfig.DNS) != 1 || info.Container.HostConfig.DNS[0].String() != gateway || !slices.Equal(info.Container.HostConfig.DNSSearch, []string{"app.sfc.test"}) || len(info.Container.HostConfig.ExtraHosts) != 0 {
			t.Fatal("actual container resolver/search/provenance", n, err)
		}
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, "nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", info.Container.State.Pid), "--", self, "-test.run=^TestManagedDNSQueryHelper$", "-test.v")
		cmd.Env = append(os.Environ(), "SFC_SQL_DNS_SERVER="+gateway, "SFC_SQL_DNS_SERIAL="+fmt.Sprint(serial))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatal("original container namespace DNS client", n, err, string(output))
		}
	}
	t.Log("both original workload namespaces queried UDP/TCP A/SOA at their managed owner gateway; exact Task default names/aliases, source/serial, declared ms policy, actual resolver/search and source-bound native observations agree; no app-owned DNS Goal")
}
