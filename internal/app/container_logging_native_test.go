// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

func TestRV4RealPlainLoggingRotationAndOriginalStopRecovery(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppLoggingPlain, true, false, false)
}
func TestRV4RealCDLoggingOverride(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppLoggingCD, true, false, false)
}

type loggingNative struct {
	id, name, driver, path, address, volume string
	logFiles                                []string
}

func verifyManagedContainerLogging(t *testing.T, ctx context.Context, runtime **Runtime, cfg config.Node, root string, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, wait func(string, func() bool), stopFault *managedCreateReplyFault, remote *Runtime, cd bool) string {
	t.Helper()
	call := func(want int, args ...string) []byte {
		t.Helper()
		body, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), append([]string{"--tenant", "tenant"}, args...), nil)
		code := 0
		if err != nil {
			if exited, ok := err.(interface{ ExitCode() int }); ok {
				code = exited.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != want {
			t.Fatal("logging CLI", args, "code", code, "want", want, string(diagnostic), string(body))
		}
		return body
	}
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	inspect := func() loggingNative {
		t.Helper()
		r := *runtime
		status, err := r.workload.Status(ctx, key)
		if err != nil || !status.Ready {
			t.Fatal("owned logging target", err)
		}
		x, err := r.docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
		if err != nil || x.Container.HostConfig == nil || x.Container.Config == nil || x.Container.NetworkSettings == nil {
			t.Fatal("inspect logging target", err)
		}
		n := loggingNative{id: status.NativeID, name: x.Container.Name, driver: x.Container.HostConfig.LogConfig.Type, path: x.Container.LogPath}
		for _, net := range x.Container.NetworkSettings.Networks {
			if net.IPAddress.Is4() {
				n.address = net.IPAddress.String() + ":8080"
				break
			}
		}
		for _, mount := range x.Container.Mounts {
			if mount.Destination == "/data" {
				n.volume = mount.Name
			}
		}
		if n.address == "" || n.volume == "" {
			t.Fatal("missing actual address/Volume/log path", n)
		}
		if n.path != "" {
			if _, err := os.Stat(n.path); err != nil {
				t.Fatal("actual native log path", err)
			}
			n.logFiles = []string{n.path}
		} else {
			// The pinned Engine intentionally omits LogPath for the local
			// driver. Discover existing log files only within this exact owned
			// native's directory at the Engine-reported data root. Product code
			// never depends on or modifies these host implementation paths.
			info, err := r.docker.API.Info(ctx, client.InfoOptions{})
			if err != nil || !filepath.IsAbs(info.Info.DockerRootDir) {
				t.Fatal("actual Engine data root", err)
			}
			directory := filepath.Join(info.Info.DockerRootDir, "containers", n.id)
			err = filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".log") {
					n.logFiles = append(n.logFiles, path)
				}
				return nil
			})
			if err != nil || len(n.logFiles) == 0 {
				t.Fatal("discover exact native local log files", err)
			}
		}
		return n
	}
	allLogs := func(id string) string {
		t.Helper()
		logs, err := (*runtime).docker.API.ContainerLogs(ctx, id, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "all"})
		if err != nil {
			t.Fatal("native logger read", err)
		}
		var out, diag bytes.Buffer
		_, copyErr := stdcopy.StdCopy(&out, &diag, io.LimitReader(logs, 256<<10))
		closeErr := logs.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatal("native log framing", copyErr, closeErr)
		}
		return out.String() + diag.String()
	}
	wait("initial logging task owner fact", func() bool {
		a, err := p.ReadApps(read().State)
		if err != nil {
			return false
		}
		e, ok := a.Execution("tenant", "app")
		if !ok || e.Status() != "Succeeded" {
			return false
		}
		s, _ := e.Stage(key)
		return s.Observation != nil && s.Observation.LogDriver != "" && s.Observation.StartedAt > 0
	})
	old := inspect()
	wantDriver := "local"
	if cd {
		wantDriver = "json-file"
	}
	if old.driver != wantDriver {
		t.Fatal("declared logging driver not applied", old.driver)
	}
	marker := "rv4-" + wantDriver
	httpClient := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	defer httpClient.CloseIdleConnections()
	response, err := httpClient.Post("http://"+old.address+"/logburst?marker="+marker, "text/plain", nil)
	if err != nil {
		t.Fatal("finite rotation input", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("rotation fixture rejected input", response.StatusCode)
	}
	wait("actual configured local log rotation", func() bool {
		value := allLogs(old.id)
		return !strings.Contains(value, marker+"-000:") && strings.Contains(value, marker+"-031:")
	})
	// Logs are cleared from the sfcd log store (logs-clear); the container
	// is never recreated for it.
	next := old
	latest := ""
	if cd {
		wait("real Git source candidate for logging override", func() bool {
			a, err := p.ReadApps(read().State)
			d, ok := a.Delivery("tenant", "app")
			_, selected := d.CandidateSelection()
			return err == nil && ok && selected
		})
		call(0, "cd", "override", "app", "services/web/logging", `{"driver":"local","options":{"max-size":"16k","max-file":"2","compress":"false"}}`, "--id", "logging-policy")
		if inspect().id != next.id {
			t.Fatal("metadata override changed native before sync")
		}
		call(0, "cd", "field", "app", "services/web/logging")
		call(0, "cd", "sync", "app", "--id", "logging-config")
		wait("actual logging policy native replacement", func() bool {
			a, err := p.ReadApps(read().State)
			e, ok := a.Execution("tenant", "app")
			return err == nil && ok && e.ActiveOperation() == "logging-config" && e.Status() == "Succeeded"
		})
		configured := inspect()
		if configured.id == next.id || configured.driver != "local" || configured.volume != old.volume {
			t.Fatal("logging override did not recreate with preserved data", configured)
		}
		next, latest = configured, "logging-config"
	} else {
		call(0, "compose", "up", "-f", filepath.Join(root, "compose.yaml"), "--operation", "post-clear-acceptance")
		wait("new explicit plain app acceptance", func() bool {
			a, err := p.ReadApps(read().State)
			e, ok := a.Execution("tenant", "app")
			return err == nil && ok && e.ActiveOperation() == "post-clear-acceptance" && e.Status() == "Succeeded"
		})
		if inspect().id != next.id {
			t.Fatal("unchanged explicit acceptance replaced the current native")
		}
		latest = "post-clear-acceptance"
	}
	// The current native/driver is observable over the ordinary User path.
	q := containerops.Query{Schema: 1, Selection: containerops.Selection{App: "app", Service: "web"}, Kind: "logs", Tail: 200, Stdout: true, Stderr: true, MaxBytes: 16384}
	observed, err := user.ObserveContainer(ctx, peer, session, "tenant", q)
	if err != nil || observed.Container == nil || observed.Container.Target.NativeID != next.id || observed.Container.LogDriver != next.driver {
		t.Fatal("current user logging observation", err)
	}
	t.Logf("actual %s rotation; CDpolicy=%t", wantDriver, cd)
	return latest
}
