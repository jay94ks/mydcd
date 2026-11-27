// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func TestAppProbeRoutesForeignTypedCallsWithoutLocalJournalBorrow(t *testing.T) {
	owner, provider := sha256.Sum256([]byte("source")), sha256.Sum256([]byte("provider"))
	point, _, cluster := checkerRemoteSourceFixture(t, owner, provider)
	d := point.Checkpoint.Definition
	d.Timing = checker.Timing{IntervalMS: 5000, TimeoutMS: 5000, FreshForMS: 6000, Retries: 1}
	m, err := checker.New(d, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	_, run, err := m.Plan(time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	request := run.Request
	manager, err := workload.OpenManager(filepath.Join(t.TempDir(), "workload.db"), &engine.Client{Owner: engine.Owner(cluster, owner)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	denied := errors.New("source target authority denied")
	service, err := manager.OpenServiceProbe(context.Background(), request, func(_ context.Context, _ string, target contract.Target) error {
		if target.Service == request.Targets[0].Service {
			return denied
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close(context.Background())
	calls := uint64(0)
	badReply := false
	probe := &appCheckProbe{ServiceProbe: service, request: request, localOwner: request.Targets[0].Owner, remote: func(_ context.Context, call checker.ProbeCall) (checker.ProbeReply, error) {
		calls++
		name, err := call.TargetService(request)
		if err != nil || name != request.Targets[1].Service || call.Sequence != calls || call.Binding != checker.ProbeBinding(request) {
			t.Error("foreign call changed native sequence/target", call.Sequence, name)
		}
		reply := checker.ProbeReply{Schema: 1, Binding: call.Binding, Sequence: call.Sequence, Kind: call.Kind}
		switch call.Kind {
		case "connect":
			reply.TCP = &contract.TCPResult{Connected: true, Data: []byte("ok")}
		case "healthz":
			reply.HTTP = &contract.HTTPResult{StatusCode: 200, Match: true}
		case "file":
			reply.File = &contract.FileResult{Exists: true, Kind: "regular", Match: true}
		case "exec":
			reply.Exec = &contract.ExecResult{Exited: true, ExitCode: 7}
		default:
			t.Error("unrequested remote capability", call.Kind)
		}
		if badReply {
			reply.Binding[0] ^= 1
		}
		return reply, nil
	}}
	ctx := context.Background()
	target := request.Targets[1].Service
	if value, err := probe.Connect(ctx, contract.TCPProbe{Service: target, Port: 8080, ReadBytes: 2}); err != nil || !value.Connected || string(value.Data) != "ok" {
		t.Fatal("foreign TCP route", err)
	}
	if value, err := probe.Healthz(ctx, contract.HTTPProbe{Service: target, Port: 8080, Path: "/ready", Method: "GET", ExpectedStatus: []int{200}, MaxBytes: 4096}); err != nil || !value.Match {
		t.Fatal("foreign HTTP route", err)
	}
	if value, err := probe.File(ctx, contract.FileProbe{Service: target, Path: "/ready", Kind: "regular"}); err != nil || !value.Exists {
		t.Fatal("foreign file route", err)
	}
	// Remote exec needs the provider's receipt, not a local Exec saver/API.
	if value, err := probe.Exec(ctx, contract.ExecProbe{Service: target, Argv: []string{"/check"}, MaxBytes: 4096}); err != nil || !value.Exited || value.ExitCode != 7 {
		t.Fatal("foreign exec route", err)
	}
	badReply = true
	if _, err := probe.File(ctx, contract.FileProbe{Service: target, Path: "/ready", Kind: "regular"}); !errors.Is(err, checker.ErrProbeRPC) {
		t.Fatal("wrong binding response accepted", err)
	}
	// The source has no native Task journal row: current denial must precede
	// all reads/borrows and cannot accidentally become another remote call.
	if _, err := probe.File(ctx, contract.FileProbe{Service: request.Targets[0].Service, Path: "/ready", Kind: "regular"}); !errors.Is(err, denied) || calls != 5 {
		t.Fatal("local target routed remotely or borrowed before authority", err, calls)
	}
}
