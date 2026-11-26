// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"io"
)

// FilePage contains one bounded byte range of a complete regular file. Entry
// identifies the whole file; Data is never a partially verified upload.
type FilePage struct {
	Entry               Entry
	Offset, Total, Next uint64
	Data                []byte `json:",omitempty"`
}

func (p FilePage) Valid(path string, offset uint64) bool {
	if !validContentEntry(p.Entry) || p.Entry.Directory || p.Entry.Path != path || p.Offset != offset || p.Total != uint64(p.Entry.Bytes) || p.Offset > p.Total {
		return false
	}
	end := min(p.Total, p.Offset+PartBytes)
	return uint64(len(p.Data)) == end-p.Offset && (end < p.Total && p.Next == end || end == p.Total && p.Next == 0)
}

// readAtFilePage reads from an already admitted, complete native blob. Its
// identity and completion receipt are checked by the native caller.
func readAtFilePage(ctx context.Context, entry Entry, offset uint64, source io.ReaderAt) (FilePage, error) {
	if !validContentEntry(entry) || entry.Directory || offset > uint64(entry.Bytes) || source == nil {
		return FilePage{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return FilePage{}, err
	}
	out := FilePage{Entry: entry, Offset: offset, Total: uint64(entry.Bytes)}
	end := min(out.Total, offset+PartBytes)
	out.Data = make([]byte, end-offset)
	n, err := source.ReadAt(out.Data, int64(offset))
	if err != nil && err != io.EOF || n != len(out.Data) {
		return FilePage{}, ErrStorage
	}
	if end < out.Total {
		out.Next = end
	}
	if err := ctx.Err(); err != nil {
		return FilePage{}, err
	}
	return out, nil
}
