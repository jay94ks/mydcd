// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/storage"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Real SourceStore DB/cache and real Yaegi; the TCP/authority adapters here
// inject observations. Docker, node scheduling and control are not simulated
// as successful by this test.
func TestStoredSourceRunsSameInterpreterAndRetainsUnknownAfterAuthorityChange(t *testing.T) {
	for _, scenario := range []string{"accepted", "denied", "revoked-after-check", "bounded-local", "bounded-revoked", "bounded-local-denied"} {
		t.Run(scenario, func(t *testing.T) {
			root := scriptSource("", `r, err := probe.Connect(ctx, lifecycle.TCPProbe{Service:"web", Port:80, Request:[]byte("PING"), ReadBytes:2}); if err != nil { return lifecycle.Result{}, err }; if !r.Connected || string(r.Data) != "OK" { return lifecycle.Result{Schema:1, Status:lifecycle.Fail, Reason:"dead"}, nil }; `+passBody)
			policy, descriptor, _ := resolverInput(root, nil)
			policy.Execution.Capabilities = append([]string{"connect"}, policy.Execution.Capabilities...)
			request := probeRequest()
			content := descriptor.ContentDigest()
			request.SourceDigest = hex.EncodeToString(content[:])
			request.RunID = hashText("stored-interpreter/" + scenario)
			request.DeadlineUnixMilli = time.Now().Add(2 * time.Second).UnixMilli()
			clusterBytes, _ := hex.DecodeString(request.Cluster)
			var cluster [32]byte
			copy(cluster[:], clusterBytes)
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{143}, 32))
			defer clear(key)
			db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			store, err := OpenSources(db, cluster, key)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if _, err = store.Stage(context.Background(), descriptor, root, policy); err != nil {
				t.Fatal(err)
			}
			checks, permits, localCalls := 0, 0, 0
			denied := errors.New("current Task denied")
			authorize := func(context.Context) error {
				permits++
				if scenario == "denied" || scenario == "revoked-after-check" && permits == 3 || scenario == "bounded-revoked" && permits == 2 {
					return denied
				}
				return nil
			}
			probe := &probeFixture{connect: func(context.Context, contract.TCPProbe) (contract.TCPResult, error) {
				checks++
				return contract.TCPResult{Connected: true, Data: []byte("OK")}, nil
			}}
			var before []func(context.Context) error
			if strings.HasPrefix(scenario, "bounded-") {
				before = append(before, func(context.Context) error {
					localCalls++
					if scenario == "bounded-local-denied" {
						return denied
					}
					return nil
				})
			}
			result, err := store.RunInterpreted(context.Background(), descriptor, policy, request, probe, authorize, nil, before...)
			if scenario == "accepted" || scenario == "bounded-local" {
				wantPermits, wantLocal := 3, 0
				if scenario == "bounded-local" {
					wantPermits, wantLocal = 2, 1
				}
				if err != nil || result.Status != contract.Pass || checks != 1 || permits != wantPermits || localCalls != wantLocal {
					t.Fatal(result, err, checks, permits)
				}
			} else if !errors.Is(err, denied) || result.Status != contract.Unknown || scenario == "denied" && checks != 0 || scenario == "revoked-after-check" && checks != 1 || scenario == "bounded-revoked" && (checks != 1 || permits != 2 || localCalls != 1) || scenario == "bounded-local-denied" && (checks != 0 || permits != 1 || localCalls != 1) {
				t.Fatal("lost authority changed execution facts", result, err, checks, permits)
			}
		})
	}
}
