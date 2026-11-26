// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/mydcp"

	"github.com/hashicorp/raft"
)

// A count that fits maximum management commands need not fit a legal SDK
// configuration followed by a command. Do not tune the batch count using only
// the common small-log case or bypass the authenticated frame byte budget.
func TestRaftAppendFrameBudgetIncludesConfiguration(t *testing.T) {
	command, err := state.EncodeCommand(state.Command{Actor: strings.Repeat("a", 256), RequestID: strings.Repeat("r", 256), Key: strings.Repeat("k", 512), Value: strings.Repeat("v", 64<<10), Target: strings.Repeat("t", 256), Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = state.DecodeCommand(command); err != nil {
		t.Fatal(err)
	}
	var configuration raft.Configuration
	for i := 0; i < 400; i++ {
		id := fmt.Sprintf("node-%04d-", i) + strings.Repeat("x", 53)
		host := fmt.Sprintf("n%03d", i) + strings.Repeat("a", 59) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
		address := host + ":65535"
		if err := config.ValidateCanonicalEndpoint(address); err != nil {
			t.Fatal(err)
		}
		configuration.Servers = append(configuration.Servers, raft.Server{ID: raft.ServerID(id), Address: raft.ServerAddress(address), Suffrage: raft.Voter})
	}
	maxCommand := &raft.Log{Index: 2, Term: 1, Type: raft.LogCommand, Data: command}
	membership := &raft.Log{Index: 1, Term: 1, Type: raft.LogConfiguration, Data: raft.EncodeConfiguration(configuration)}
	second := *maxCommand
	second.Index = 3
	third := *maxCommand
	third.Index = 4
	for _, test := range []struct {
		name    string
		entries []*raft.Log
		fits    bool
	}{
		{"two-management", []*raft.Log{maxCommand, &second}, true},
		{"three-management", []*raft.Log{maxCommand, &second, &third}, false},
		{"one-configuration", []*raft.Log{membership}, true},
		{"configuration-and-management", []*raft.Log{membership, maxCommand}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := &raft.AppendEntriesRequest{RPCHeader: raft.RPCHeader{ProtocolVersion: raft.ProtocolVersionMax, ID: []byte("node-a"), Addr: []byte("127.0.0.1:7443")}, Term: 1, PrevLogEntry: test.entries[0].Index - 1, PrevLogTerm: 1, Entries: test.entries}
			payload, err := rpcBytes(1, request)
			if err != nil {
				t.Fatal(err)
			}
			_, err = mydcp.Encode(rpcFrame(1, payload))
			t.Logf("entries=%d rpc_bytes=%d frame_body_limit=%d fits=%v", len(test.entries), len(payload), mydcp.MaxBody, err == nil)
			if (err == nil) != test.fits {
				t.Fatal("Raft frame bound", err, test.fits)
			}
		})
	}
}
