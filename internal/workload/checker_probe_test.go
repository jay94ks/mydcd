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
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func serviceProbeRequest() contract.Request {
	h := sha256.Sum256([]byte("service-probe-fixture"))
	digest := hex.EncodeToString(h[:])
	return contract.Request{Schema: 1, Cluster: digest, Tenant: "tenant", App: "app", Checker: "alive", RunID: digest, SourceDigest: digest, Phase: contract.Liveness, DeadlineUnixMilli: time.Now().Add(time.Second).UnixMilli(), Targets: []contract.Target{{Service: "web", TaskKey: "workload/task", NativeID: "original-native", Owner: digest, OwnerBoot: digest, Generation: 1, Revision: 1}}}
}

func TestAppRequestNeverUsesLocalJournalForAnotherOwner(t *testing.T) {
	request := serviceProbeRequest()
	manager := &Manager{driver: &DockerDriver{Engine: &engine.Client{Owner: request.Cluster + "/" + request.Targets[0].Owner}}}
	foreign := request.Targets[0]
	foreign.Service, foreign.TaskKey = "z-remote", "remote/task"
	hash := sha256.Sum256([]byte("remote-owner"))
	foreign.Owner = hex.EncodeToString(hash[:])
	request.Targets = append(request.Targets, foreign)
	calls := 0
	probe, err := manager.OpenServiceProbe(context.Background(), request, func(context.Context, string, contract.Target) error { calls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close(context.Background())
	if _, err = probe.File(context.Background(), contract.FileProbe{Service: foreign.Service, Path: "/ready", Kind: "regular"}); err == nil || calls != 0 {
		t.Fatal("remote target entered local authority/journal", err, calls)
	}
}

func TestServiceProbeKeepsRequestAndAuthorityBeforeBorrowAndRejectsLateCalls(t *testing.T) {
	request := serviceProbeRequest()
	// No journal/API: denial must precede any read, borrow or native request.
	manager := &Manager{driver: &DockerDriver{Engine: &engine.Client{Owner: request.Cluster + "/" + request.Targets[0].Owner}}}
	denied := errors.New("original Task authority revoked")
	calls := 0
	p, err := manager.OpenServiceProbe(context.Background(), request, func(_ context.Context, kind string, target contract.Target) error {
		calls++
		if kind != "connect" || target.Service != "web" || target.NativeID != "original-native" {
			t.Fatal("script changed original target", target)
		}
		return denied
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background())
	request.Targets[0].Service = "changed"
	if _, err = p.Connect(context.Background(), contract.TCPProbe{Service: "web", Port: 80}); !errors.Is(err, denied) || calls != 1 {
		t.Fatal("authority not checked before native borrow", err, calls)
	}
	if _, err = p.Connect(context.Background(), contract.TCPProbe{Service: "other", Port: 80}); err == nil || calls != 1 {
		t.Fatal("foreign service reached current authorization")
	}
	if err = p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Connect(context.Background(), contract.TCPProbe{Service: "web", Port: 80}); err == nil || calls != 1 {
		t.Fatal("closed check admitted a late call")
	}
	if err = p.Close(context.Background()); err != nil {
		t.Fatal("Close replay changed cleanup", err)
	}
	if err = (&ServiceProbe{}).Close(context.Background()); err == nil {
		t.Fatal("zero probe fabricated a completed owner")
	}
}
