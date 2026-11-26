// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"testing"
)

func FuzzCommandCodec(f *testing.F) {
	seed, _ := EncodeCommand(Command{Actor: "admin", Epoch: 1, RequestID: "r", Key: "test/key", Value: "value"})
	f.Add(seed)
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxCommand+1 {
			return
		}
		c, e := DecodeCommand(b)
		if e != nil {
			return
		}
		wire, e := EncodeCommand(c)
		if e != nil || !bytes.Equal(wire, b) {
			t.Fatal("noncanonical command accepted", e)
		}
	})
}
