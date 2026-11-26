// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/storage"

	"github.com/hashicorp/raft"
)

func TestFSMReplayDurableFloor(t *testing.T) {
	for _, mode := range []string{"matching", "state", "term", "configuration", "configuration-index", "prefix-decode", "prefix-validator", "prefix-order"} {
		t.Run(mode, func(t *testing.T) {
			db, err := storage.Open(filepath.Join(t.TempDir(), "fsm.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			logs := raft.NewInmemStore()
			configuration := raft.Configuration{Servers: []raft.Server{{ID: "node", Address: "127.0.0.1:1", Suffrage: raft.Voter}}}
			for _, index := range []uint64{1, 2} {
				if err := logs.StoreLog(&raft.Log{Index: index, Term: 1, Type: raft.LogConfiguration, Data: raft.EncodeConfiguration(configuration)}); err != nil {
					t.Fatal(err)
				}
			}
			open := func() *fsm {
				t.Helper()
				f, err := newFSM(db, logs, "cluster", "admin", nil)
				if err != nil {
					t.Fatal(err)
				}
				f.trackConfiguration = true
				return f
			}
			command := func(id, value string, expected uint64) []byte {
				t.Helper()
				b, err := state.EncodeCommand(state.Command{Actor: "admin", Epoch: 1, RequestID: id, Key: "network/original", Value: value, Expected: expected})
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			first, last := command("first", "prefix", 0), command("last", "checkpoint", 1)
			apply := func(f *fsm, index, term uint64, b []byte) application {
				return f.Apply(&raft.Log{Index: index, Term: term, Type: raft.LogCommand, Data: b}).(application)
			}
			f := open()
			f.StoreConfiguration(1, configuration)
			for _, log := range []struct {
				index uint64
				data  []byte
			}{{3, first}, {4, last}} {
				if r := apply(f, log.index, 1, log.data); r.Err != nil || r.Result.Code != state.Applied {
					t.Fatal(r)
				}
			}
			original, err := db.Get("fsm")
			if err != nil {
				t.Fatal(err)
			}
			f = open()
			notification := f.changes
			assertUnpublished := func() {
				t.Helper()
				s, index, term, err := f.view(false)
				if err != nil || index != 4 || term != 1 || s.Object("network/original").Value != "checkpoint" {
					t.Fatal("prefix replaced durable read", index, term, err)
				}
				if _, _, _, err := f.view(true); !errors.Is(err, ErrRecovering) {
					t.Fatal("prefix granted strict read", err)
				}
				current, err := db.Get("fsm")
				if err != nil || !bytes.Equal(original, current) {
					t.Fatal("prefix rewrote durable checkpoint", err)
				}
				select {
				case <-notification:
					t.Fatal("prefix emitted durable change")
				default:
				}
			}
			assertUnpublished()
			configIndex := uint64(1)
			if mode == "configuration" {
				configuration.Servers[0].Address = "127.0.0.1:2"
			}
			if mode == "configuration-index" {
				configIndex = 2
			}
			f.StoreConfiguration(configIndex, configuration)
			assertUnpublished()
			if mode == "prefix-validator" {
				f.validate = func(state.State, state.State, state.Command) error { return errors.New("invalid prefix") }
			}
			if mode == "prefix-decode" {
				first = []byte("malformed command")
			}
			prefix := apply(f, 3, 1, first)
			prefixFailure := mode == "prefix-decode" || mode == "prefix-order"
			if mode == "prefix-order" {
				if prefix.Err != nil {
					t.Fatal(prefix)
				}
				prefix = apply(f, 3, 1, first)
			}
			if prefixFailure {
				if prefix.Err == nil {
					t.Fatal("invalid prefix accepted")
				}
			} else {
				want := state.Applied
				if mode == "prefix-validator" {
					want = state.Invalid
				}
				if prefix.Err != nil || prefix.Result.Code != want {
					t.Fatal(prefix)
				}
				assertUnpublished()
				term := uint64(1)
				if mode == "state" {
					last = command("last", "contradiction", 1)
				}
				if mode == "term" {
					term = 2
				}
				reply := apply(f, 4, term, last)
				if mode == "matching" {
					if reply.Err != nil || reply.Result.Code != state.Applied {
						t.Fatal(reply)
					}
					if _, index, _, err := f.view(true); err != nil || index != 4 {
						t.Fatal("matching checkpoint not ready", index, err)
					}
					if reply := apply(f, 5, 2, command("suffix", "new durable", 2)); reply.Err != nil || reply.Result.Code != state.Applied {
						t.Fatal(reply)
					}
					select {
					case <-notification:
					default:
						t.Fatal("suffix did not notify")
					}
					if s, index, term, err := open().view(false); err != nil || index != 5 || term != 2 || s.Object("network/original").Value != "new durable" {
						t.Fatal("suffix not durable", index, term, err)
					}
					return
				}
				if reply.Err == nil {
					t.Fatal("contradictory checkpoint accepted")
				}
			}
			for _, strict := range []bool{false, true} {
				if _, _, _, err := f.view(strict); err == nil {
					t.Fatal("failed replay remained readable", strict)
				}
			}
			current, err := db.Get("fsm")
			if err != nil || !bytes.Equal(original, current) {
				t.Fatal("failed replay replaced durable checkpoint", err)
			}
		})
	}
}
