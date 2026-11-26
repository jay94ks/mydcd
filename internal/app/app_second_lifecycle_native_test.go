// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/tests/vaultfixture"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

func TestRealBoundaryManagedAppSecondLifecycle(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppSecondLifecycle, true, true, true)
}

func verifySecondAppLifecycle(t *testing.T, ctx context.Context, r *Runtime, root string, original []byte, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), vault *vaultfixture.Vault, reuseOriginal bool) {
	t.Helper()
	vault.UnsealOriginal()
	catalog, _ := p.Catalog(read().State)
	tenant, _ := catalog.Tenant("tenant")
	change("second-lifecycle-node", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: []string{"node-a"}})
	file, profile := filepath.Join(root, "compose.yaml"), filepath.Join(root, "cli.yaml")
	input, err := deployment.ParseApp(original)
	if err != nil {
		t.Fatal(err)
	}
	var originalVolume string
	if reuseOriginal {
		registry, err := p.Volumes(read().State)
		ready, found := registry.Native("tenant", "app", "data")
		if err != nil || !found {
			t.Fatal("original retained volume", err)
		}
		originalVolume = ready.Owner.Native
	} else {
		volume := input.Volumes["data"]
		delete(input.Volumes, "data")
		input.Volumes["restored"] = volume
		for name, service := range input.Services {
			for i := range service.Volumes {
				if service.Volumes[i].Source == "data" {
					service.Volumes[i].Source = "restored"
				}
			}
			input.Services[name] = service
		}
	}
	document, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, document, 0600); err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) {
		t.Helper()
		out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), profile, args, nil)
		if err != nil {
			t.Fatal("second lifecycle CLI", args, err, string(diagnostic), string(out))
		}
	}
	await := func(label string, test func(control.Apps) bool) {
		t.Helper()
		last, changed := "", time.Now()
		for {
			apps, err := p.Apps(read().State)
			if err != nil {
				t.Fatal(err)
			}
			if test(apps) {
				return
			}
			i, _ := apps.Inventory("tenant", "app")
			execution, _ := i.Execution()
			progress := execution.ActiveOperation() + "/" + execution.Status()
			for _, step := range execution.Steps() {
				stage, _ := execution.Stage(step.Key)
				progress += fmt.Sprintf("/%s:%t:%t", step.Key, stage.Result != nil, stage.Observation != nil && stage.Observation.Applied)
			}
			if retirement, ok := i.Retirement(); ok {
				for _, target := range retirement.Targets {
					progress += fmt.Sprintf("/%s:%t:%t:%t:%t", target.Original.Step.Key, target.Closed, target.Drain != nil && target.Drain.Result != nil, target.Proof != nil && target.Proof.Result != nil, target.Delete != nil && target.Delete.Result != nil)
				}
			}
			if progress != last {
				last, changed = progress, time.Now()
				t.Log("second lifecycle progress", time.Now().Format("15:04:05.000"), progress)
			}
			if time.Since(changed) > 30*time.Second {
				if retirement, ok := i.Retirement(); ok {
					for _, target := range retirement.Targets {
						if !target.Closed {
							t.Log("original pending retirement target", target.Original.Step.Kind, target.Original.Step.Key, "can retire", i.CanRetire(target.Original.Step.Key), "generation", target.Original.Result.Generation)
							for phase, m := range map[string]*deployment.Mutation{"drain": target.Drain, "proof": target.Proof, "delete": target.Delete} {
								if m != nil {
									t.Log("phase", phase, "original", m.Command.RequestID, "expected", m.Command.Expected, "result", m.Result, "pending", m.Journal.Pending != nil)
								}
							}
						}
					}
				}
				r.mu.RLock()
				cause := r.moduleError
				r.mu.RUnlock()
				if owner := r.dnsOwner(); owner != nil {
					_, rows, _ := apps.NetworkDNS(r.Identity.Public)
					for _, row := range rows {
						t.Log("second lifecycle DNS", row.Config.ID, "source", row.Config.Source, owner.Status(row.Config.Tenant, row.Config.ID))
					}
				}
				t.Fatal("second lifecycle stalled", label, cause)
			}
			select {
			case <-ctx.Done():
				live := []string{}
				for _, b := range apps.Bindings().Live() {
					live = append(live, fmt.Sprintf("%+v", b.Needs()))
				}
				r.mu.RLock()
				cause := r.moduleError
				r.mu.RUnlock()
				t.Fatal(label, ctx.Err(), "last progress", last, "live bindings", live, "module error", cause)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	cli("compose", "up", "--tenant", "tenant", "-f", file, "--operation", "second-rollout", "--no-input")
	await("new Volume/task/Secret/Ingress", func(apps control.Apps) bool {
		e, ok := apps.Execution("tenant", "app")
		return ok && e.Status() == "Succeeded"
	})
	if r.dnsOwner() != nil {
		verifyManagedAppDNS(t, ctx, r, p, read, func(label string, ready func() bool) {
			await(label, func(control.Apps) bool { return ready() })
		})
	}
	if reuseOriginal {
		registry, err := p.Volumes(read().State)
		ready, found := registry.Native("tenant", "app", "data")
		if err != nil || !found || ready.Owner.Native != originalVolume {
			t.Fatal("redeployment replaced retained volume identity", err)
		}
		disk, err := r.docker.API.VolumeInspect(ctx, originalVolume, client.VolumeInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		marker, err := os.ReadFile(filepath.Join(disk.Volume.Mountpoint, "marker"))
		if err != nil || string(marker) != "volume-original" {
			t.Fatal("redeployment lost original volume data", err)
		}
		verifyE7BoundedDNSIngress(t, ctx, r, p, read)
	}
	cli("compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "second-down")
	await("second down and whole reference return", func(apps control.Apps) bool {
		i, _ := apps.Inventory("tenant", "app")
		_, pending := i.Retirement()
		return !pending && len(apps.Bindings().Live()) == 0
	})
	t.Log("actual same app stable keys: first down/reopen -> new logical Volume selection/task generation -> second healthy -> second down/whole references; no SQL or restore-file claim")
}

// The final product budget is two requests at once, sixteen requests total.
// Each request traverses the actual Ingress and container's DNS client.
func verifyE7BoundedDNSIngress(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View) {
	t.Helper()
	projection, err := p.ProjectResources(read().State)
	ingress := projection.Goals[deployment.ResourceKey("ingress", "tenant", "app", "http")].Ingress
	row, nativeErr := r.workload.View(deployment.ResourceKey("task", "tenant", "app", "web"))
	spec, specErr := workload.DecodeContainer(row.State.Applied.Spec)
	if err != nil || nativeErr != nil || specErr != nil || ingress == nil || len(ingress.Listeners) == 0 || !spec.IPv4.IsValid() {
		t.Fatal("bounded original Ingress/Task input", err, nativeErr, specErr)
	}
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 2}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	jobs := make(chan int, 16)
	results := make(chan error, 16)
	for i := 0; i < 16; i++ {
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	for worker := 0; worker < 2; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				protocol := []string{"udp", "tcp"}[i%2]
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ingress.Listeners[0].Address+"/resolve?name=web&transport="+protocol, nil)
				if err != nil {
					results <- err
					continue
				}
				req.Host = "app.test"
				response, err := httpClient.Do(req)
				if err != nil {
					results <- err
					continue
				}
				body, err := io.ReadAll(io.LimitReader(response.Body, 256))
				_ = response.Body.Close()
				if err == nil && (response.StatusCode != http.StatusOK || string(body) != spec.IPv4.String()) {
					err = fmt.Errorf("request %d: status %d, DNS result %q", i, response.StatusCode, body)
				}
				results <- err
			}
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("bounded2/16 actual Ingress/DNS", err)
		}
	}
	t.Log("bounded native Ingress/DNS: concurrency2, total16, UDP/TCP resolver, exact current container address, no retries")
}
