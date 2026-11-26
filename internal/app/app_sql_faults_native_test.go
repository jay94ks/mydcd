// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/moby/moby/client"
	"github.com/vishvananda/netlink"
)

// These are finite faults in the existing private netns/two-Engine fixture.
// Both rollback closures are registered before their first external effect.
func verifyE7SQLPauseAndUnderlay(t *testing.T, ctx context.Context, a *Runtime, docker [2]*engine.Client, sessionQuery func(context.Context) error, old ModuleObservation, observeDB func() (ModuleObservation, error), wait func(string, func() bool), readyURL string, checkRows func()) map[string]any {
	t.Helper()
	key := deployment.ResourceKey("task", "tenant", "app", "db")
	initial, err := docker[1].API.ContainerInspect(ctx, old.NativeID, client.ContainerInspectOptions{})
	if err != nil || initial.Container.State == nil || !initial.Container.State.Running || initial.Container.State.Paused || initial.Container.State.Restarting || initial.Container.State.Dead || initial.Container.Config == nil || initial.Container.Config.Labels["org.mydc.owner"] != docker[1].Owner || initial.Container.Config.Labels["org.mydc.key"] != key {
		t.Fatal("owned original SQL pause precondition", err)
	}
	started := initial.Container.State.StartedAt
	restorePause := func(call context.Context) error {
		current, err := docker[1].API.ContainerInspect(call, old.NativeID, client.ContainerInspectOptions{})
		if err != nil {
			return err
		}
		if current.Container.State == nil || current.Container.Config == nil || current.Container.State.StartedAt != started || current.Container.Config.Labels["org.mydc.owner"] != docker[1].Owner || current.Container.Config.Labels["org.mydc.key"] != key {
			return fmt.Errorf("original SQL pause identity changed")
		}
		if current.Container.State.Paused {
			_, err = docker[1].API.ContainerUnpause(call, old.NativeID, client.ContainerUnpauseOptions{})
		}
		return err
	}
	restoredPause := false
	defer func() {
		if !restoredPause {
			clean, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			if err := restorePause(clean); err != nil {
				t.Error("original SQL unpause rollback", err)
			}
		}
	}()
	if _, err := docker[1].API.ContainerPause(ctx, old.NativeID, client.ContainerPauseOptions{}); err != nil {
		t.Fatal("actual SQL pause", err)
	}
	paused, err := docker[1].API.ContainerInspect(ctx, old.NativeID, client.ContainerInspectOptions{})
	if err != nil || paused.Container.State == nil || !paused.Container.State.Paused || !paused.Container.State.Running {
		t.Fatal("positive paused Engine fact", err)
	}
	wait("paused MySQL is not Ready despite stale Engine health", func() bool {
		current, err := observeDB()
		return err == nil && current.NativeID == old.NativeID && !current.Ready && current.Journal.LastID == old.Journal.LastID
	})
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	request, err := http.NewRequestWithContext(call, http.MethodGet, readyURL, nil)
	if err != nil {
		stop()
		t.Fatal(err)
	}
	request.Host = "app.test"
	response, probeErr := (&http.Client{Transport: transport}).Do(request)
	code := 0
	if response != nil {
		code = response.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
	}
	stop()
	if probeErr == nil && code != http.StatusServiceUnavailable && code != http.StatusBadGateway && code != http.StatusGatewayTimeout {
		t.Fatal("paused SQL was presented as available", code)
	}
	if err := restorePause(ctx); err != nil {
		t.Fatal("same original SQL unpause", err)
	}
	restoredPause = true
	wait("same SQL native and writer after unpause", func() bool {
		current, err := observeDB()
		if err != nil || !current.Ready || current.NativeID != old.NativeID || current.Journal.LastID != old.Journal.LastID {
			return false
		}
		now, err := docker[1].API.ContainerInspect(ctx, old.NativeID, client.ContainerInspectOptions{})
		return err == nil && now.Container.State != nil && !now.Container.State.Paused && now.Container.State.StartedAt == started && reflect.DeepEqual(now.Container.Mounts, initial.Container.Mounts)
	})
	unpauseReady := waitManagedSQLHTTPReady(t, ctx, wait, readyURL)
	checkRows()
	// The inherited parent fixture owns mda0 only inside this private namespace.
	ownNS, err := os.Readlink("/proc/self/ns/net")
	hostNS := os.Getenv("MYDC_KERNEL_HOST_NETNS")
	if err != nil || hostNS == "" || ownNS == hostNS {
		t.Fatal("underlay fault requires original private netns", err)
	}
	link, err := netlink.LinkByName("mda0")
	if err != nil || link.Type() != "veth" || link.Attrs().Flags&net.FlagUp == 0 {
		t.Fatal("owned underlay precondition", err)
	}
	index, mac := link.Attrs().Index, link.Attrs().HardwareAddr.String()
	restoreLink := func() error {
		current, err := netlink.LinkByName("mda0")
		if err != nil {
			return err
		}
		if current.Type() != "veth" || current.Attrs().Index != index || current.Attrs().HardwareAddr.String() != mac {
			return fmt.Errorf("original underlay identity changed")
		}
		if current.Attrs().Flags&net.FlagUp == 0 {
			return netlink.LinkSetUp(current)
		}
		return nil
	}
	restoredLink := false
	defer func() {
		if !restoredLink {
			if err := restoreLink(); err != nil {
				t.Error("original underlay rollback", err)
			}
		}
	}()
	if err := netlink.LinkSetDown(link); err != nil {
		t.Fatal(err)
	}
	bounded, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	queryErr := sessionQuery(bounded)
	cancel()
	if queryErr == nil {
		t.Fatal("partitioned N2/Q2 latest read succeeded")
	}
	current, err := docker[1].API.ContainerInspect(ctx, old.NativeID, client.ContainerInspectOptions{})
	if err != nil || current.Container.State == nil || !current.Container.State.Running || current.Container.State.StartedAt != started {
		t.Fatal("underlay partition replaced/stopped original SQL", err)
	}
	installed, err := a.Engine().InstalledConfiguration(ctx, false)
	if err != nil || len(installed.Configuration.Servers) != 2 {
		t.Fatal("partition changed original voting configuration", err)
	}
	if err := restoreLink(); err != nil {
		t.Fatal(err)
	}
	restoredLink = true
	wait("N2 quorum and original SQL after underlay restore", func() bool {
		call, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		if sessionQuery(call) != nil {
			return false
		}
		current, err := observeDB()
		return err == nil && current.Ready && current.NativeID == old.NativeID && current.Journal.LastID == old.Journal.LastID
	})
	underlayReady := waitManagedSQLHTTPReady(t, ctx, wait, readyURL)
	checkRows()
	t.Log("finite SQL pause/unpause (Running preserved, Ready false, no exit/fence); exact original underlay down/up (N2/Q2 denial, same SQL native/data); original rollback identities restored")
	return map[string]any{"pause_ready_false": true, "pause_http_status": code, "pause_probe_unknown": probeErr != nil, "underlay_interface": "mda0", "underlay_identity_restored": true, "original_sql_id": old.NativeID, "original_started_at": strings.TrimSpace(started), "quorum_denied": true, "unpause_http_recovery": unpauseReady, "underlay_http_recovery": underlayReady}
}

// Control quorum and the original native DB can recover before DNS, packet
// paths and Ingress converge. Observe the real read-only application boundary
// before checking preserved rows or issuing any new writes. A failed CRUD
// operation is never retried by this readiness wait.
func waitManagedSQLHTTPReady(t *testing.T, ctx context.Context, wait func(string, func() bool), readyURL string) map[string]any {
	t.Helper()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport}
	started, attempts := time.Now(), 0
	var lastFailure string
	wait("actual PHP/DNS/MySQL/Ingress read-only recovery", func() bool {
		attempts++
		call, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		request, err := http.NewRequestWithContext(call, http.MethodGet, readyURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "app.test"
		response, err := httpClient.Do(request)
		failure := fmt.Sprint(err)
		if response != nil {
			raw, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			var result struct {
				Ready  bool   `json:"ready"`
				Driver string `json:"driver"`
				DBHost string `json:"db_host"`
			}
			if err == nil && readErr == nil && response.StatusCode == http.StatusOK && json.Unmarshal(raw, &result) == nil && result.Ready && result.Driver == "mysql" && result.DBHost == "db" {
				return true
			}
			failure = fmt.Sprintf("HTTP %d read=%v", response.StatusCode, readErr)
		}
		if failure != lastFailure {
			t.Log("read-only recovery pending", failure)
			lastFailure = failure
		}
		return false
	})
	return map[string]any{"attempts": attempts, "elapsed_ms": time.Since(started).Milliseconds(), "last_pending": lastFailure}
}

// Four independent rows, each with create/read/update/delete: exactly sixteen
// CRUD requests, at most two concurrent. Uncertain writes are never retried.
func verifyE7SQLBoundedLoad(t *testing.T, ctx context.Context, base string) map[string]any {
	t.Helper()
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	rows := make(chan int, 4)
	for row := range 4 {
		rows <- row
	}
	close(rows)
	failures := make(chan error, 2)
	var completed atomic.Int32
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for row := range rows {
				key := fmt.Sprintf("e7-load-%d", row)
				first := strings.Repeat(fmt.Sprintf("%d", row), 1024)
				updated := strings.Repeat(fmt.Sprintf("%d", row+4), 1024)
				for _, step := range []struct{ method, path, body, want string }{
					{http.MethodPost, "/row?key=" + key + "&operation=" + key + "-create", first, first},
					{http.MethodGet, "/row?key=" + key, "", first},
					{http.MethodPut, "/row?key=" + key + "&operation=" + key + "-update", updated, updated},
					{http.MethodDelete, "/row?key=" + key + "&operation=" + key + "-delete", "", ""},
				} {
					request, err := http.NewRequestWithContext(ctx, step.method, base+step.path, strings.NewReader(step.body))
					if err != nil {
						failures <- err
						return
					}
					request.Host = "app.test"
					response, err := httpClient.Do(request)
					if err != nil {
						failures <- fmt.Errorf("original %s %s outcome unresolved: %w", step.method, key, err)
						return
					}
					raw, err := io.ReadAll(io.LimitReader(response.Body, 4096))
					_ = response.Body.Close()
					var result map[string]any
					if err != nil || response.StatusCode != http.StatusOK || json.Unmarshal(raw, &result) != nil || step.method != http.MethodDelete && result["value"] != step.want || step.method == http.MethodDelete && result["deleted"] != true {
						failures <- fmt.Errorf("bounded original %s %s failed status=%d read=%v", step.method, key, response.StatusCode, err)
						return
					}
					completed.Add(1)
				}
			}
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if t.Failed() || completed.Load() != 16 {
		t.Fatalf("bounded load completed %d/16 original requests", completed.Load())
	}
	return map[string]any{"concurrent": 2, "crud_requests": 16, "completed": completed.Load(), "retries": 0, "row_payload_bytes": 1024}
}
