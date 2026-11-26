// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestManagedPassEarlyReportsCannotStarveDNSPrerequisite(t *testing.T) {
	for _, visited := range []bool{false, true} {
		var calls []string
		dnsReady := false
		for range 4 {
			err := reconcileManagedPass(context.Background(), func() (bool, error) {
				calls = append(calls, "owners")
				if visited {
					dnsReady = true
				}
				// Every pass may publish another valid owner report. There is
				// no promise that this stream will ever become quiescent.
				return visited, nil
			}, func() error {
				calls = append(calls, "dns")
				dnsReady = true
				return nil
			}, func() error {
				calls = append(calls, "workloads")
				if !dnsReady {
					t.Fatal("attempted Start without live DNS opportunity")
				}
				dnsReady = false
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		one := []string{"owners", "dns", "workloads"}
		if visited {
			one = []string{"owners", "workloads"}
		}
		var want []string
		for range 4 {
			want = append(want, one...)
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatal("missing prerequisite or duplicate DNS reconciliation", calls, want)
		}
	}
}

func TestManagedPassErrorsAndCancellationRetainTheirBoundary(t *testing.T) {
	for _, phase := range []string{"before", "owner-error", "after-owner", "dns-error", "after-dns", "workload-error"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("original boundary failure")
			var calls []string
			if phase == "before" {
				cancel()
			}
			err := reconcileManagedPass(ctx, func() (bool, error) {
				calls = append(calls, "owners")
				if phase == "owner-error" {
					return false, failure
				}
				if phase == "after-owner" {
					cancel()
				}
				return false, nil
			}, func() error {
				calls = append(calls, "dns")
				if phase == "dns-error" {
					return failure
				}
				if phase == "after-dns" {
					cancel()
				}
				return nil
			}, func() error { calls = append(calls, "workloads"); return failure })
			want := map[string][]string{
				"before": nil, "owner-error": {"owners"}, "after-owner": {"owners"},
				"dns-error": {"owners", "dns"}, "after-dns": {"owners", "dns"},
				"workload-error": {"owners", "dns", "workloads"},
			}[phase]
			cause := failure
			if ctx.Err() != nil {
				cause = context.Canceled
			}
			if !errors.Is(err, cause) || !reflect.DeepEqual(calls, want) {
				t.Fatal("lost original cause or crossed a failed/cancelled boundary", err, calls, want)
			}
		})
	}
}
