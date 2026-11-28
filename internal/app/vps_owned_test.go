// SPDX-License-Identifier: Apache-2.0

package app

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/vps"
)

func TestOwnedCheckFailure(t *testing.T) {
	running := vps.Instance{Status: vps.StatusActive, PublicIPv4: "203.0.113.9"}
	manual := control.OwnedVPS{Name: "edge-1", Install: control.OwnedInstallManual}
	var none membership.Directory
	for _, c := range []struct {
		name   string
		inst   vps.Instance
		server control.OwnedVPS
		d      membership.Directory
		want   string
	}{
		{"running", running, manual, none, ""},
		{"stopped", vps.Instance{Status: vps.StatusOff, PublicIPv4: "203.0.113.9"}, manual, none, "NOT_RUNNING"},
		{"no address", vps.Instance{Status: vps.StatusActive}, manual, none, "NO_PUBLIC_IP"},
		{"private address", vps.Instance{Status: vps.StatusActive, PublicIPv4: "10.0.0.5"}, manual, none, "NO_PUBLIC_IP"},
		{"existing, not a member", running, control.OwnedVPS{Name: "edge-1", Install: control.OwnedInstallExisting}, none, "IP_MISMATCH"},
		{"existing, other address", running, control.OwnedVPS{Name: "edge-1", Install: control.OwnedInstallExisting},
			membership.Directory{Entries: []membership.Entry{{Peer: config.Peer{ID: "edge-1", Endpoint: "198.51.100.7:7443"}, Phase: membership.Active}}}, "IP_MISMATCH"},
		{"existing, same address", running, control.OwnedVPS{Name: "edge-1", Install: control.OwnedInstallExisting},
			membership.Directory{Entries: []membership.Entry{{Peer: config.Peer{ID: "edge-1", Endpoint: "203.0.113.9:7443"}, Phase: membership.Active}}}, ""},
	} {
		if got := ownedCheckFailure(c.inst, c.d, c.server); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestOwnedTargetJoinsWithItsOwnID(t *testing.T) {
	v := control.OwnedVPS{Name: "edge-1", Request: "op-1", PublicIP: "203.0.113.9", Port: 7443}
	tg := ownedTarget(v)
	if tg.Endpoint != "203.0.113.9:7443" || tg.JoinID != v.JoinID() || tg.JoinID[:6] != "owned-" {
		t.Fatalf("target = %+v", tg)
	}
	if m := managedTarget(control.VPSServer{Name: "edge-1", Request: "op-1"}); m.JoinID == tg.JoinID {
		t.Fatal("managed and owned share a join ID")
	}
}

func TestVPSInstallScriptParses(t *testing.T) {
	script := fmt.Sprintf(vpsInstallScript, "sfc.example.com", "edge-1")
	if !strings.Contains(script, "NAME=edge-1\n") || !strings.Contains(script, "X-Sfc-Endpoint") || strings.Contains(script, "%!") || !strings.Contains(script, "ExecStart=/usr/local/bin/sfcd") {
		t.Fatalf("script:\n%s", script)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh -n: %v %s", err, out)
	}
	for _, host := range []string{"sfc.example.com", "203.0.113.9:8443"} {
		if !vpsScriptHost.MatchString(host) {
			t.Errorf("host %q refused", host)
		}
	}
	for _, host := range []string{"a;rm -rf /", "$(id)", "a b", ""} {
		if vpsScriptHost.MatchString(host) {
			t.Errorf("host %q accepted", host)
		}
	}
}
