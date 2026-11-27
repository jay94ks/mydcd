// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Each interpreter case runs in a fresh test process. This exercises the real
// Yaegi/SDK code without leaving a canceled interpreter's goroutine in the
// parent test. Actual Task scheduling, container I/O and Docker control are
// separate L1 adapters; this is the interpreter/SDK execution boundary.
func TestCheckerInterpreterUsesRealSDKInBoundedChildProcesses(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"sdk-probe", "tcp-probe", "external-init", "private-handles", "probe-error", "panic", "deadline", "output", "stale-source", "host-switch"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "-test.run=^TestCheckerInterpreterProcess$", "-test.count=1", "-test.timeout=4s")
			command.Env = []string{"SFC_INTERPRETER_CASE=" + scenario, "GOMAXPROCS=2", "GOTOOLCHAIN=local"}
			out, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v: %s", scenario, err, out)
			}
			if bytes.Contains(out, []byte("private-panic-sentinel")) || bytes.Contains(out, []byte("private-probe-sentinel")) {
				t.Fatal("raw diagnostic escaped child")
			}
		})
	}
}

func TestCheckerInterpreterProcess(t *testing.T) {
	scenario := os.Getenv("SFC_INTERPRETER_CASE")
	if scenario == "" {
		t.Skip("isolated interpreter case only")
	}
	body := `r, err := probe.File(ctx, lifecycle.FileProbe{Service:"web", Path:in.Parameters["path"], Kind:"regular"}); if err != nil || !r.Exists || !r.Match { return lifecycle.Result{Schema:1, Status:lifecycle.Fail, Reason:"not-ready"}, nil }; ` + passBody
	extra := ""
	var archives []ModuleArchive
	var allowed []string
	switch scenario {
	case "tcp-probe":
		body = `r, err := probe.Connect(ctx, lifecycle.TCPProbe{Service:"web", Port:80, Request:[]byte("PING"), ReadBytes:4}); if err != nil || !r.Connected || string(r.Data) != "PONG" { return lifecycle.Result{Schema:1, Status:lifecycle.Fail, Reason:"not-alive"}, nil }; _, err = probe.Connect(ctx, lifecycle.TCPProbe{Service:"web", Port:80, Request:[]byte("ALIVE")}); if err != nil { return lifecycle.Result{Schema:1, Status:lifecycle.Unknown, Reason:"action-error"}, err }; ` + passBody
	case "sdk-probe", "stale-source", "host-switch", "probe-error":
		if scenario == "probe-error" {
			body = `_, err := probe.File(ctx, lifecycle.FileProbe{Service:"web", Path:"/ready", Kind:"regular"}); if err == nil || err.Error() != "checker probe failed" { return lifecycle.Result{}, nil }; ` + passBody
		}
	case "external-init":
		extra = `"example.invalid/safe";`
		body = `if safe.Ready != "initialized" { return lifecycle.Result{}, nil }; ` + body
		archives = []ModuleArchive{moduleArchive(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte(`package safe
var Ready string
func init() { Ready = "initialized" }
`)})}
		allowed = []string{"example.invalid/safe"}
	case "private-handles":
		extra = `"fmt"; "strings";`
		allowed = []string{"fmt", "strings"}
		body = `if ctx.Value("private-context") != nil || strings.Contains(fmt.Sprintf("%#v %#v", ctx, probe), "private-handle-sentinel") { return lifecycle.Result{}, nil }; ` + body
	case "panic":
		body = `panic("private-panic-sentinel")`
	case "deadline":
		body = `for {}`
	case "output":
		extra, allowed, body = `"fmt";`, []string{"fmt"}, `fmt.Print("012345678901234567890123456789"); `+passBody
	default:
		t.Fatal("unknown child scenario")
	}
	root := scriptSource(extra, body)
	p, d, target := resolverInput(root, archives, allowed...)
	if scenario == "tcp-probe" {
		p.Execution.Capabilities = append([]string{"connect"}, p.Execution.Capabilities...)
	}
	if scenario == "output" {
		p.Execution.OutputBytes = 8
	}
	source, err := ResolveSource(context.Background(), p, d, root, archives, target)
	if err != nil {
		t.Fatal(err)
	}
	request := testDefinition().Request
	request.RunID = hashText("interpreter-child-run")
	digest := d.ContentDigest()
	request.SourceDigest = hex.EncodeToString(digest[:])
	request.DeadlineUnixMilli = time.Now().Add(time.Second).UnixMilli()
	if scenario == "deadline" {
		request.DeadlineUnixMilli = time.Now().Add(50 * time.Millisecond).UnixMilli()
	}
	if scenario == "stale-source" {
		request.SourceDigest = hashText("different-source")
	}
	if scenario == "host-switch" {
		t.Setenv("YAEGI_DOT_CMD", "must-never-execute")
	}
	probe := &interpretedProbe{secret: "private-handle-sentinel", fail: scenario == "probe-error"}
	ctx := context.WithValue(context.Background(), interpreterContextKey("private-context"), "private-handle-sentinel")
	var diagnostic bytes.Buffer
	result, err := evaluateInterpreted(ctx, source, request, probe, &diagnostic)
	bad := scenario == "panic" || scenario == "deadline" || scenario == "output" || scenario == "stale-source" || scenario == "host-switch"
	if bad {
		if err == nil || result.Status != contract.Unknown {
			t.Fatal("failure became success", result.Status)
		}
		if scenario == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("deadline cause lost", err)
		}
	} else if err != nil || result.Status != contract.Pass || result.Reason != "ready" {
		t.Fatal("real SDK execution failed", result.Status, result.Reason, err)
	}
	if (scenario == "sdk-probe" || scenario == "external-init" || scenario == "private-handles" || scenario == "probe-error") && probe.calls != 1 {
		t.Fatal("native probe did not execute exactly once")
	}
	if scenario == "tcp-probe" && probe.calls != 2 {
		t.Fatal("custom check and alive side effect did not both run")
	}
	for _, private := range []string{"private-panic-sentinel", "private-probe-sentinel", "private-handle-sentinel"} {
		if strings.Contains(diagnostic.String(), private) || strings.Contains(result.Reason, private) || err != nil && strings.Contains(err.Error(), private) {
			t.Fatal("private state escaped interpreter")
		}
	}
}

type interpreterContextKey string
type interpretedProbe struct {
	secret string
	fail   bool
	calls  int
}

func (p *interpretedProbe) Healthz(context.Context, contract.HTTPProbe) (contract.HTTPResult, error) {
	return contract.HTTPResult{}, ErrContract
}
func (p *interpretedProbe) Connect(_ context.Context, q contract.TCPProbe) (contract.TCPResult, error) {
	p.calls++
	if q.Service != "web" || q.Port != 80 {
		return contract.TCPResult{}, ErrContract
	}
	if string(q.Request) == "PING" && q.ReadBytes == 4 {
		return contract.TCPResult{Connected: true, Data: []byte("PONG")}, nil
	}
	if string(q.Request) == "ALIVE" && q.ReadBytes == 0 {
		return contract.TCPResult{Connected: true}, nil
	}
	return contract.TCPResult{}, ErrContract
}
func (p *interpretedProbe) Exec(context.Context, contract.ExecProbe) (contract.ExecResult, error) {
	return contract.ExecResult{}, ErrContract
}
func (p *interpretedProbe) Dependency(context.Context, contract.DependencyProbe) (contract.DependencyResult, error) {
	return contract.DependencyResult{}, ErrContract
}
func (p *interpretedProbe) File(_ context.Context, in contract.FileProbe) (contract.FileResult, error) {
	p.calls++
	if p.fail {
		return contract.FileResult{}, errors.New("private-probe-sentinel")
	}
	if in.Service != "web" || in.Kind != "regular" || in.Path != "/readyz" {
		return contract.FileResult{}, ErrContract
	}
	return contract.FileResult{Exists: true, Match: true, Kind: "regular"}, nil
}
