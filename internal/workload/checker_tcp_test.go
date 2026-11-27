// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Real owned loopback connections only. No Docker, routes, namespaces or host
// configuration change; the L1 final run closes each listener/connection.
func TestLifecycleTCPReadsExactCustomPrefixAndPreservesUnknownErrors(t *testing.T) {
	for _, scenario := range []string{"fragment", "short", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			number, _ := strconv.Atoi(port)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer func() { _ = conn.Close(); done <- err }()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				var request [4]byte
				if _, err = io.ReadFull(conn, request[:]); err == nil && string(request[:]) == "PING" {
					if scenario == "cancel" {
						cancel()
					} else {
						_, err = conn.Write([]byte("PO"))
						if err == nil && scenario == "fragment" {
							_, err = conn.Write([]byte("NG"))
						}
					}
				}
			}()
			result, err := probeTCP(ctx, netip.MustParseAddr(host), contract.TCPProbe{Port: uint16(number), Request: []byte("PING"), ReadBytes: 4})
			if scenario == "fragment" {
				if err != nil || !result.Connected || string(result.Data) != "PONG" {
					t.Fatal("custom request/fragmented response", result, err)
				}
			} else if err == nil || len(result.Data) != 0 {
				t.Fatal("partial/cancelled check became a complete result", result, err)
			}
			_ = listener.Close()
			select {
			case serverErr := <-done:
				if serverErr != nil {
					t.Fatal(serverErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("owned connection did not finish")
			}
		})
	}
}
