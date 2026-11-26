// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/schema"
)

// WriteSessionRecord does not allocate or accumulate a whole session. The
// caller first applies the direction/spec SessionFlow and serializes writes.
func WriteSessionRecord(w io.Writer, request uint64, intent [32]byte, r containerops.SessionRecord) error {
	if request == 0 || intent == ([32]byte{}) || r.Schema != 1 || r.Sequence == 0 || len(r.Data) > containerops.SessionChunkBytes {
		return ErrFrame
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return WriteFrame(w, Frame{Purpose: ContainerSession, Kind: 5, Request: request, Fields: []Field{{Tag: 1, Required: true, Value: body}, {Tag: 2, Required: true, Value: intent[:]}}})
}

func ReadSessionRecord(r io.Reader, request uint64, intent [32]byte) (containerops.SessionRecord, error) {
	var record containerops.SessionRecord
	if request == 0 || intent == ([32]byte{}) {
		return record, ErrFrame
	}
	f, err := ReadFrame(r, 128<<10)
	if err != nil {
		return record, err
	}
	if f.Purpose != ContainerSession || f.Kind != 5 || f.Request != request || !bytes.Equal(f.Fields[1].Value, intent[:]) {
		return record, ErrFrame
	}
	record, err = schema.Decode[containerops.SessionRecord](f.Fields[0].Value)
	if err != nil || record.Schema != 1 || record.Sequence == 0 || len(record.Data) > containerops.SessionChunkBytes {
		return containerops.SessionRecord{}, ErrFrame
	}
	return record, nil
}
