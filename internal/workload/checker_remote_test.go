// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engine"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func TestServiceProbeRemoteSharesNativeOrdinalAndCloseJoinsIO(t *testing.T) {
	request := serviceProbeRequest()
	request.DeadlineUnixMilli = time.Now().Add(10 * time.Second).UnixMilli()
	foreign := request.Targets[0]
	foreign.Service = "z-remote"
	foreign.TaskKey = "remote/task"
	owner := sha256.Sum256([]byte("remote-owner"))
	foreign.Owner = hex.EncodeToString(owner[:])
	request.Targets = append(request.Targets, foreign)
	manager := &Manager{driver: &DockerDriver{Engine: &engine.Client{Owner: request.Cluster + "/" + request.Targets[0].Owner}}}
	denied := errors.New("local current permission denied")
	authorizations := 0
	p, err := manager.OpenServiceProbe(context.Background(), request, func(_ context.Context, _ string, target contract.Target) error {
		authorizations++
		if target.Service == "web" {
			return denied
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background())
	// Local denial is before borrow (no journal/client exists), but consumes
	// the same native ordinal as the next authorized remote call.
	if _, err = p.File(context.Background(), contract.FileProbe{Service: "web", Path: "/ready", Kind: "regular"}); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	query := checker.ProbeCall{Kind: "file", File: &contract.FileProbe{Service: foreign.Service, Path: "/ready", Kind: "regular"}}
	calls := 0
	reply, err := p.RemoteCall(context.Background(), query, func(_ context.Context, call checker.ProbeCall) (checker.ProbeReply, error) {
		calls++
		if call.Sequence != 2 || call.Schema != 1 || call.Binding != checker.ProbeBinding(request) || call.DeadlineUnixMilli > request.DeadlineUnixMilli || call.File.Service != foreign.Service {
			t.Error("remote call changed run ordinal/target", call.Sequence)
		}
		return checker.ProbeReply{Schema: 1, Binding: call.Binding, Sequence: call.Sequence, Kind: call.Kind, File: &contract.FileResult{Exists: true, Match: true, Kind: "regular"}}, nil
	})
	if err != nil || reply.File == nil || calls != 1 || authorizations != 2 {
		t.Fatal("remote dispatch used local journal or reset ordinal", err, calls, authorizations)
	}
	local := query
	local.File = &contract.FileProbe{Service: "web", Path: "/ready", Kind: "regular"}
	if _, err = p.RemoteCall(context.Background(), local, func(context.Context, checker.ProbeCall) (checker.ProbeReply, error) {
		t.Error("local target entered remote dispatcher")
		return checker.ProbeReply{}, nil
	}); err == nil || authorizations != 2 {
		t.Fatal("local target misrouted", err)
	}
	started, joined, returned := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := p.RemoteCall(context.Background(), query, func(ctx context.Context, call checker.ProbeCall) (checker.ProbeReply, error) {
			close(started)
			<-ctx.Done()
			close(joined)
			return checker.ProbeReply{}, ctx.Err()
		})
		returned <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("remote callback did not start")
	}
	if err = p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-joined:
	default:
		t.Fatal("Close abandoned remote I/O")
	}
	if err = <-returned; !errors.Is(err, context.Canceled) {
		t.Fatal("Close did not cancel original call", err)
	}
	if _, err = p.RemoteCall(context.Background(), query, func(context.Context, checker.ProbeCall) (checker.ProbeReply, error) {
		t.Error("closed run dispatched late call")
		return checker.ProbeReply{}, nil
	}); err == nil {
		t.Fatal("late remote call admitted")
	}
}
