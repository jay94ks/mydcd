// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

func TestRV4RealPlainLoggingRotationAndOriginalStopRecovery(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppLoggingPlain, true, false, false)
}
func TestRV4RealCDLoggingOverrideAndExplicitRecreation(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppLoggingCD, true, false, false)
}

type loggingNative struct {
	id, name, driver, path, address, volume string
	logFiles                                []string
}

func verifyManagedContainerLogging(t *testing.T, ctx context.Context, runtime **Runtime, cfg config.Node, root string, user userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, wait func(string, func() bool), stopFault *managedCreateReplyFault, remote *Runtime, cd bool) string {
	t.Helper()
	call := func(want int, args ...string) []byte {
		t.Helper()
		body, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), append([]string{"--tenant", "tenant"}, args...), nil)
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
	var preview struct{ Plan control.AppLogClearPlan }
	if json.Unmarshal(call(0, "compose", "logs-clear", "-p", "app", "web", "--preview"), &preview) != nil || preview.Plan.LogDriver != wantDriver || preview.Plan.Container.NativeID != old.id {
		t.Fatal("actual user impact plan")
	}
	call(2, "compose", "logs-clear", "-p", "app", "web")
	if inspect().id != old.id {
		t.Fatal("missing consent changed native target")
	}
	var policyBefore any
	if cd {
		a, _ := p.ReadApps(read().State)
		d, _ := a.Delivery("tenant", "app")
		policyBefore = d.Policy()
	}
	if remote != nil {
		remotePeer, ok := (*runtime).Mesh.Peer(mydcp.Identity(remote.Identity.Public))
		if !ok {
			t.Fatal("missing real remote control")
		}
		if err := (*runtime).Engine().TransferLeadership(ctx, remotePeer.ID, remotePeer.Endpoint); err != nil {
			t.Fatal(err)
		}
		wait("remote control owns logging command admission", func() bool { return remote.Engine().IsLeader() })
		defer func() {
			if err := remote.Engine().TransferLeadership(ctx, peer.ID, peer.Endpoint); err != nil {
				t.Error("restore logging fixture leader", err)
				return
			}
			wait("restored original logging owner control", func() bool { return (*runtime).Engine().IsLeader() })
		}()
	}
	if stopFault != nil {
		stopFault.holdStopResponse(old.id, old.name)
	}
	var accepted map[string]json.RawMessage
	if json.Unmarshal(call(0, "compose", "logs-clear", "-p", "app", "web", "--recreate", "--operation", "clear-original"), &accepted) != nil {
		t.Fatal("missing accepted original clear")
	}
	if stopFault != nil {
		select {
		case <-stopFault.stopEntered:
		case <-ctx.Done():
			t.Fatal("original Stop did not reach actual Engine", ctx.Err())
		}
		if err := (*runtime).Engine().Snapshot(ctx); err != nil {
			t.Fatal(err)
		}
		if err := (*runtime).Close(); err != nil {
			t.Fatal(err)
		}
		*runtime = nil
		stopFault.releaseStop()
		reopened, err := Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		*runtime = reopened
		if _, err := reopened.InstallConfiguration(ctx); err != nil {
			t.Fatal(err)
		}
		wait("same DB control after lost native Stop response", func() bool { return reopened.Engine().IsLeader() })
	}
	wait("original logs removed and replacement ready", func() bool {
		a, err := p.ReadApps(read().State)
		if err != nil {
			return false
		}
		s := a.LogClearStatus("tenant", "app", "clear-original")
		return s != nil && s.Status == "Succeeded" && len(s.NewContainers) > 0
	})
	next := inspect()
	if next.id == old.id || next.volume != old.volume || next.driver != old.driver {
		t.Fatal("wrong replacement or lost Volume/driver", old.id, next.id, old.volume, next.volume, old.driver, next.driver)
	}
	if _, err := (*runtime).docker.API.ContainerInspect(ctx, old.id, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("old native still present", err)
	}
	for _, file := range old.logFiles {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Fatal("old Engine local logs not physically removed", err)
		}
	}
	if strings.Contains(allLogs(next.id), marker) {
		t.Fatal("replacement retained deleted original logs")
	}
	if stopFault != nil && stopFault.stoppedCalls() != 1 {
		t.Fatal("lost Stop response was replayed as another native effect", stopFault.stoppedCalls())
	}
	vol, err := (*runtime).docker.API.VolumeInspect(ctx, next.volume, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(vol.Volume.Mountpoint, "marker")); err != nil || string(data) != "volume-original" {
		t.Fatal("volume data was lost", err)
	}
	latest := "clear-original"
	if cd {
		a, _ := p.ReadApps(read().State)
		d, _ := a.Delivery("tenant", "app")
		if !reflect.DeepEqual(policyBefore, d.Policy()) {
			t.Fatal("recreation changed CD policy")
		}
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
		// A completed recreation must not pin future explicit app acceptance
		// to its old source proof, nor erase the old clear's native history.
		call(0, "compose", "up", "-f", filepath.Join(root, "compose.yaml"), "--operation", "post-clear-acceptance")
		wait("new explicit plain app acceptance after recreation", func() bool {
			a, err := p.ReadApps(read().State)
			e, ok := a.Execution("tenant", "app")
			return err == nil && ok && e.ActiveOperation() == "post-clear-acceptance" && e.Status() == "Succeeded"
		})
		if inspect().id != next.id {
			t.Fatal("unchanged explicit acceptance replaced the current native")
		}
		latest = "post-clear-acceptance"
	}
	var repeated map[string]json.RawMessage
	if json.Unmarshal(call(0, "compose", "logs-clear", "-p", "app", "web", "--recreate", "--operation", "clear-original"), &repeated) != nil {
		t.Fatal("missing original repeated result")
	}
	for _, field := range []string{"target", "request", "epoch", "root_revision", "expected_revision"} {
		if !bytes.Equal(accepted[field], repeated[field]) {
			t.Fatal("repeated request rebuilt original intent", field)
		}
	}
	if inspect().id != next.id {
		t.Fatal("same log-clear ID deleted a replacement")
	}
	call(0, "compose", "logs-clear-status", "-p", "app", "--operation", "clear-original")
	// The same current native/driver remains observable over the ordinary User
	// path; metadata alone was not treated as the physical deletion proof.
	q := containerops.Query{Schema: 1, Selection: containerops.Selection{App: "app", Service: "web"}, Kind: "logs", Tail: 200, Stdout: true, Stderr: true, MaxBytes: 16384}
	observed, err := user.ObserveContainer(ctx, peer, session, "tenant", q)
	if err != nil || observed.Container == nil || observed.Container.Target.NativeID != next.id || observed.Container.LogDriver != next.driver {
		t.Fatal("current user logging observation", err)
	}
	t.Logf("actual %s rotation -> explicit user recreation -> old native/log path Gone; original ID preserved; Volume retained; faultStop=%t remoteOwner=%t CDpolicy=%t", wantDriver, stopFault != nil, remote != nil, cd)
	return latest
}
