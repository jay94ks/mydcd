// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
	"gopkg.in/yaml.v3"
)

func TestL1ManagedTwoOwnerRemoteChecksAndCompiledCache(t *testing.T) {
	if (os.Getenv("SFC_LIFECYCLE_COMPILER_IMAGE") == "" && os.Getenv("SFC_LIFECYCLE_COMPILER_CACHE") == "") || os.Getenv("SFC_DOCKER_TEST_REMOTE_CIDR") == "" {
		t.Skip("explicit compiler image and owned second CIDR baseline required")
	}
	runManagedAppOwner(t, true, true, true, true, managedAppRemoteCompiledChecker, true, false, false, true)
}

func checkerRemoteNativeCIDR(t *testing.T) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(os.Getenv("SFC_DOCKER_TEST_REMOTE_CIDR"))
	source, sourceErr := netip.ParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
	if err != nil || sourceErr != nil || !prefix.Addr().Is4() || prefix.Bits() != 24 || prefix != prefix.Masked() || prefix.Overlaps(source) {
		t.Fatal("explicit separate owned IPv4 /24 pair required", err, sourceErr)
	}
	return prefix
}

func prepareManagedRemoteCheckerOwner(t *testing.T, ctx context.Context, target *Runtime, root string, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), public map[string]any, save func()) {
	t.Helper()
	if target == nil || target.docker == nil || target.workload == nil || target.network == nil {
		t.Fatal("installed native second owner required")
	}
	prefix := checkerRemoteNativeCIDR(t)
	users, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant("tenant")
	change("checker-second-owner", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a", "node-b"}))
	for _, scope := range []string{"", "tenant"} {
		change("checker-second-quota-"+scope, "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-b", Capacity: workload.Resources{CPU: 2e9, Memory: 1 << 30}, Networks: 2, MaxConsumers: 8})
	}
	key := (tenancy.SourceIdentity{Kind: "bridge", Tenant: "tenant", Network: "checker-remote-network", Node: "node-b"}).Key()
	public["Target"] = map[string]any{"Owner": target.docker.Owner, "Cluster": p.Cluster, "NodeKey": target.Identity.Public, "Root": root, "Key": key, "CIDR": prefix.String()}
	save() // before the management change can create any second-owner native
	t.Cleanup(func() {
		if err := target.Close(); err != nil {
			t.Error(err)
		}
		clean, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		owned, err := engine.Open(clean, "unix:///var/run/docker.sock", target.docker.Owner)
		if err != nil {
			t.Error(err)
			return
		}
		defer owned.Close()
		cleanupMoveTargetRuntime(t, clean, owned, root, p.Cluster, target.Identity.Public)
	})
}

func prepareManagedRemoteCheckerApp(t *testing.T, document, management []byte, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) ([]byte, []byte) {
	t.Helper()
	input, err := deployment.ParseApp(document)
	if err != nil {
		t.Fatal(err)
	}
	prefix := checkerRemoteNativeCIDR(t)
	service := input.Services["web"]
	service.Sfc.Node = "node-b"
	service.Sfc.Lifecycle = &deployment.ServiceLifecycle{Checks: []deployment.LifecycleCheck{{ID: "native", Phase: contract.Readiness, Interval: "1s", Timeout: "3s", LifecycleTemplate: deployment.LifecycleTemplate{Builtin: "docker_health"}}}}
	service.Networks = map[string]deployment.Attachment{"remote": {IPv4: prefix.Addr().Next().Next().String()}}
	service.Volumes = deployment.Mounts{{Type: "volume", Source: "remote-data", Target: "/data"}}
	service.DependsOn = nil
	input.Services["z-remote"] = service
	input.Networks["remote"] = deployment.ComposeNetwork{External: true, Name: "checker-remote-network"}
	volume := input.Volumes["data"]
	volume.Sfc.Node = "node-b"
	// app.yaml local volumes are retained by contract. App retirement returns
	// their writer; the original owner fixture removes its retained test data.
	input.Volumes["remote-data"] = volume
	sum := sha256.Sum256([]byte("volume-original"))
	script := fmt.Sprintf(`package checker
import("context"; lifecycle "github.com/jay94ks/seafield/lifecycle/v1")
func Check(ctx context.Context,in lifecycle.Request,p lifecycle.Probe)(lifecycle.Result,error){
 fail:=lifecycle.Result{Schema:1,Status:"fail",Reason:"remote-not-ready"}
 switch in.Parameters["kind"] {
 case "healthz":
 h,err:=p.Healthz(ctx,lifecycle.HTTPProbe{Service:"z-remote",Port:8080,Path:"/readyz",Method:"GET",ExpectedStatus:[]int{200},MaxBytes:4096});if err!=nil{return lifecycle.Result{},err};if !h.Match{return fail,nil}
 case "file":
 f,err:=p.File(ctx,lifecycle.FileProbe{Service:"z-remote",Path:"/data/marker",Kind:"regular",ContentDigest:"%x",MaxBytes:4096});if err!=nil{return lifecycle.Result{},err};if !f.Exists||!f.Match{return fail,nil}
 case "exec":
 e,err:=p.Exec(ctx,lifecycle.ExecProbe{Service:"z-remote",Argv:[]string{"/backend","--volume-probe"},MaxBytes:4096});if err!=nil{return lifecycle.Result{},err};if !e.Exited||e.ExitCode!=0{return fail,nil}
 case "connect":
 c,err:=p.Connect(ctx,lifecycle.TCPProbe{Service:"z-remote",Port:8080});if err!=nil{return lifecycle.Result{},err};if !c.Connected{return fail,nil}
 default:return lifecycle.Result{Schema:1,Status:"unknown",Reason:"invalid-probe-kind"},nil
 }
 return lifecycle.Result{Schema:1,Status:"pass",Reason:"remote-ready"},nil
}`, sum)
	for _, compiled := range []bool{false, true} {
		alias := fmt.Sprintf("remote-%t", compiled)
		selected := compiled
		input.Sfc.Lifecycle.Scripts[alias] = checker.Script{Source: script + fmt.Sprintf("\n// compiled=%t\n", compiled), Compile: &selected}
		for _, kind := range []string{"healthz", "file", "exec", "connect"} {
			input.Sfc.Lifecycle.Checks = append(input.Sfc.Lifecycle.Checks, deployment.LifecycleCheck{ID: alias + "-" + kind, Phase: contract.Readiness, Interval: "45s", Timeout: "3s", LifecycleTemplate: deployment.LifecycleTemplate{Script: alias, Parameters: deployment.LifecycleParameters(fmt.Sprintf(`{"kind":%q}`, kind))}})
		}
	}
	// Eleven required checks share one coordinator worker. Each has the same
	// original 3s execution bound, including one remote effect, not a forced
	// four-effect batch. Cadence45s/freshness48s exceeds serial33s plus overhead.
	for index := range input.Sfc.Lifecycle.Checks {
		input.Sfc.Lifecycle.Checks[index].Interval = "45s"
	}
	for name, definition := range input.Services {
		if definition.Sfc.Lifecycle != nil {
			for index := range definition.Sfc.Lifecycle.Checks {
				definition.Sfc.Lifecycle.Checks[index].Interval = "45s"
			}
			input.Services[name] = definition
		}
	}
	// Network creation CAS is the shared network catalog revision, not zero
	// for each new name. Prepare the provider network through the same signed
	// management path, then freeze the observed revision in the CLI's separate
	// partial change. Do not predict a Raft revision or bypass the CAS.
	resources, err := p.Resources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	change("checker-remote-network", "create-tun-network", resources.Networks.Revision(), tenancy.TUNDefinition{Tenant: "tenant", Name: "checker-remote-network", Members: []tenancy.TUNNode{{Node: "node-b", Pools: []tenancy.Subnet{{ID: "pool", Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}}}})
	resources, err = p.Resources(read().State)
	if err != nil || strings.Count(string(management), "   expected: 0\n") != 1 {
		t.Fatal("original CLI network management input", err)
	}
	management = []byte(strings.Replace(string(management), "   expected: 0\n", fmt.Sprintf("   expected: %d\n", resources.Networks.Revision()), 1))
	encoded, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, management
}

func managedRemoteCheckerKind(name string) string {
	for _, mode := range []string{"false", "true"} {
		for _, kind := range []string{"healthz", "file", "exec", "connect"} {
			if name == "remote-"+mode+"-"+kind {
				return kind
			}
		}
	}
	return ""
}

func verifyManagedRemoteCheckerResults(t *testing.T, ctx context.Context, source, provider *Runtime, wait func(string, func() bool)) {
	t.Helper()
	wait("original remote checkers have joined", func() bool {
		source.checkerRunMu.Lock()
		defer source.checkerRunMu.Unlock()
		rows, err := source.reports.ScanBounded(checkerObservationPrefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, raw := range rows {
			point, err := schema.Decode[checkerObservation](raw)
			if err != nil {
				t.Fatal(err)
			}
			name := point.Checkpoint.Definition.Request.Checker
			if managedRemoteCheckerKind(name) == "" {
				continue
			}
			if point.Checkpoint.Active != nil || point.Checkpoint.Last == nil || point.Checkpoint.Last.Result.Status != contract.Pass || len(point.RemoteCalls) != 1 {
				return false
			}
			found++
		}
		return found == 8
	})
	t.Helper()
	source.checkerRunMu.Lock()
	defer source.checkerRunMu.Unlock()
	rows, err := source.reports.ScanBounded(checkerObservationPrefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string]bool{}
	expected := map[[32]byte]string{}
	for _, raw := range rows {
		point, err := schema.Decode[checkerObservation](raw)
		if err != nil || point.validate(source.controlPolicy.Cluster, source.Identity.Public) != nil {
			t.Fatal("source original checkpoint", err)
		}
		name := point.Checkpoint.Definition.Request.Checker
		if managedRemoteCheckerKind(name) == "" {
			continue
		}
		if point.Checkpoint.Last == nil || point.Checkpoint.Last.Result.Status != contract.Pass || len(point.RemoteCalls) != 1 {
			t.Fatal("actual remote app checker missing positive result", name)
		}
		call := point.RemoteCalls[0]
		if call.Provider != provider.Identity.Public || call.Phase != "closed" || call.Kind != managedRemoteCheckerKind(name) {
			t.Fatal("original typed source/provider closure missing", name)
		}
		expected[call.Header] = name
		modes[name] = true
	}
	if len(modes) != 8 || len(expected) != 8 {
		t.Fatal("Yaegi and compiled remote result both required")
	}
	provider.checkerRemoteMu.Lock()
	defer provider.checkerRemoteMu.Unlock()
	rows, err = provider.reports.ScanBounded(checkerRemotePrefix, checkerRemoteSlots, checkerRemoteTotalBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 8 {
		t.Fatal("provider did not persist actual native calls")
	}
	matched := map[[32]byte]bool{}
	for _, raw := range rows {
		call, err := schema.Decode[checkerRemoteCall](raw)
		if err != nil || call.validate(provider.controlPolicy.Cluster, provider.Identity.Public) != nil || call.Consumer != source.Identity.Public {
			t.Fatal("provider original metadata", err)
		}
		if call.Phase != "closed" {
			t.Fatal("original provider native effect remains unsettled")
		}
		if name, ok := expected[call.Header]; ok {
			if call.Query.Run.Request.Checker != name || call.Query.Kind != managedRemoteCheckerKind(name) || call.Execution != nil && !call.Execution.Terminal() {
				t.Fatal("source closure differs from original provider", name)
			}
			matched[call.Header] = true
		}
	}
	if len(matched) != 8 {
		t.Fatal("both modes require each original typed provider closure", len(matched))
	}
	book, err := source.controlPolicy.Lifecycles(mustCheckerView(t, ctx, source).State)
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range book.BuildJobs() {
		if job.Intent.Owner != provider.Identity.Public || job.Phase != "closed" {
			t.Fatal("remote finite builder did not close")
		}
		for _, input := range job.Intent.Inputs {
			fact, data, err := source.checkerSources.CompiledArtifact(ctx, job.Intent.Tenant, input.Recipe)
			clear(data)
			if err != nil || fact.Build.Builder != provider.Identity.Public || fact.Owner != source.Identity.Public {
				t.Fatal("member transfer changed original builder", err)
			}
		}
	}
}
