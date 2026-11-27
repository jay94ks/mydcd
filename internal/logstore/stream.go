// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"context"
	"encoding/binary"
	"io"
	"time"
)

// ReadOptions selects what Stream returns, the way the Engine API's
// container logs query does.
type ReadOptions struct {
	Since, Until   time.Time // zero: unbounded
	Tail           int       // last N records; 0 means all
	Stdout, Stderr bool
	Timestamps     bool
	TTY            bool // raw bytes instead of stdcopy frames
	Follow         bool // keep sending new records until ctx ends or the log is deleted
}

func (o ReadOptions) wants(r Record) bool {
	if r.Stderr && !o.Stderr || !r.Stderr && !o.Stdout {
		return false
	}
	if !o.Since.IsZero() && r.Time.Before(o.Since) {
		return false
	}
	return o.Until.IsZero() || !r.Time.After(o.Until)
}

// Stream returns the container's log in the Engine API's container logs
// encoding: stdcopy frames (stream 1 stdout, 2 stderr) or, for a TTY
// container, the raw bytes. A full line gets its newline back; a partial
// line does not. Callers that parsed `ContainerLogs` keep working.
func (s *Store) Stream(ctx context.Context, id string, o ReadOptions) (io.ReadCloser, error) {
	if _, err := s.get(id, nil); err != nil {
		return nil, err
	}
	start := uint64(0)
	if o.Tail > 0 {
		ring := make([]uint64, 0, o.Tail)
		if _, err := s.Read(id, 0, func(r Record) bool {
			if o.wants(r) {
				if len(ring) == o.Tail {
					ring = ring[1:]
				}
				ring = append(ring, r.Seq)
			}
			return true
		}); err != nil {
			return nil, err
		}
		if len(ring) > 0 {
			start = ring[0] - 1
		} else {
			start = s.Last(id)
		}
	}
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		defer cancel()
		after := start
		for {
			var werr error
			changed, err := s.Read(id, after, func(r Record) bool {
				after = r.Seq
				if !o.wants(r) {
					return true
				}
				werr = writeRecord(pw, r, o)
				return werr == nil
			})
			if err == nil {
				err = werr
			}
			if err != nil || !o.Follow {
				_ = pw.CloseWithError(err)
				return
			}
			select {
			case <-changed:
				if _, err := s.get(id, nil); err != nil {
					_ = pw.Close() // deleted
					return
				}
			case <-ctx.Done():
				_ = pw.Close()
				return
			}
		}
	}()
	return &streamReader{PipeReader: pr, cancel: cancel}, nil
}

type streamReader struct {
	*io.PipeReader
	cancel context.CancelFunc
}

func (r *streamReader) Close() error {
	r.cancel()
	return r.PipeReader.Close()
}

func writeRecord(w io.Writer, r Record, o ReadOptions) error {
	var line []byte
	if o.Timestamps {
		line = append(r.Time.UTC().AppendFormat(line, time.RFC3339Nano), ' ')
	}
	line = append(line, r.Data...)
	if !r.Partial {
		line = append(line, '\n')
	}
	if o.TTY {
		_, err := w.Write(line)
		return err
	}
	var h [8]byte
	h[0] = 1
	if r.Stderr {
		h[0] = 2
	}
	binary.BigEndian.PutUint32(h[4:], uint32(len(line)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(line)
	return err
}
