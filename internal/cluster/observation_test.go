// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func TestReplicationObservationUsesAcceptedPrefixNotFollowerLastLog(t *testing.T) {
	transport := &raftTransport{}
	request := &raft.AppendEntriesRequest{Term: 4, PrevLogEntry: 10}
	response := &raft.AppendEntriesResponse{Term: 4, Success: false, LastLog: 500}
	transport.observeAppend("node-b", request, response, time.Millisecond, nil)
	if p := transport.replication["node-b"]; p.MatchKnown || p.MatchIndex != 0 || !p.Reply {
		t.Fatal("rejected append inferred match", p)
	}
	response.Success = true
	transport.observeAppend("node-b", request, response, time.Millisecond, nil)
	if p := transport.replication["node-b"]; !p.MatchKnown || p.MatchIndex != 10 {
		t.Fatal("accepted heartbeat prefix", p)
	}
	request.Entries = []*raft.Log{{Index: 11}, {Index: 12}}
	transport.observeAppend("node-b", request, response, time.Millisecond, nil)
	if p := transport.replication["node-b"]; p.MatchIndex != 12 {
		t.Fatal("accepted entry prefix", p)
	}
	response.Success = false
	transport.observeAppend("node-b", request, response, time.Millisecond, errors.New("unreachable"))
	if p := transport.replication["node-b"]; p.Reply || p.MatchIndex != 12 {
		t.Fatal("failed contact rewrote positive prefix", p)
	}
	transport.observeSnapshot("node-b", &raft.InstallSnapshotRequest{Term: 4, LastLogIndex: 50}, &raft.InstallSnapshotResponse{Term: 4, Success: true}, time.Millisecond, nil)
	if p := transport.replication["node-b"]; !p.MatchKnown || p.MatchIndex != 50 {
		t.Fatal("exact snapshot ACK lost", p)
	}
	request.Term = 5
	response.Term = 6
	transport.observeAppend("node-b", request, response, time.Millisecond, nil)
	if p := transport.replication["node-b"]; p.Term != 5 || p.MatchKnown || p.Reply {
		t.Fatal("old/higher-term response counted for current leader", p)
	}
}
