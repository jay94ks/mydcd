// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jay94ks/seafield/internal/engineevents"
	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
)

// routeEngineOps registers every op of table with the engine socket. Each
// request body goes to table.Serve; the answer, its descriptors and any
// stream go back on the request's stream.
func routeEngineOps(t *sfcp.Transport, table *engineops.Table) error {
	var err error
	table.Each(func(p engineops.Purpose, op string) {
		purpose := sfcp.Purpose(p)
		err = errors.Join(err, t.HandleEngine(purpose, op, func(ctx context.Context, _ *sfcp.EngineSession, st sfcp.EngineStream, first sfcp.Frame, _ sfcp.EngineRequest) error {
			// Descriptors the engine sent with the request are not used by any op yet.
			for _, fd := range st.TakeFDs() {
				_ = syscall.Close(fd)
			}
			a := table.Serve(ctx, p, first.Fields[0].Value)
			return writeEngineAnswer(st, purpose, first, a)
		}))
	})
	return err
}

func writeEngineAnswer(st sfcp.EngineStream, p sfcp.Purpose, first sfcp.Frame, a engineops.Answer) error {
	defer func() {
		for _, f := range a.Files {
			_ = f.Close()
		}
		if a.Stream != nil {
			_ = a.Stream.Close()
		}
	}()
	if len(a.Files) > 0 {
		// Attach owns the numbers it is given and closes them after sending,
		// so it gets duplicates and the answer's files are closed here.
		fds := make([]int, 0, len(a.Files))
		for _, f := range a.Files {
			fd, err := syscall.Dup(int(f.Fd()))
			if err != nil {
				for _, d := range fds {
					_ = syscall.Close(d)
				}
				return err
			}
			fds = append(fds, fd)
		}
		if err := st.Attach(fds...); err != nil {
			return err
		}
	}
	if err := st.WriteFrame(sfcp.Frame{Purpose: p, Kind: 2, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: a.Body}}}); err != nil {
		return err
	}
	if a.Stream == nil {
		return nil
	}
	w := &engineChunkWriter{st: st, p: p, header: sha256.Sum256(first.Fields[0].Value)}
	if _, err := io.Copy(w, a.Stream); err != nil {
		st.CancelWrite(0)
		return err
	}
	return nil
}

// engineCursorKey holds the engine event cursor in the reports store.
const engineCursorKey = "engine-events/cursor"

// ListenEngine opens the engine-only socket the Seafield engine (sfed) dials,
// answers its volume, network and image requests from engineOpEntries, and
// follows its event feed into engineEventHandlers each time it connects.
// socket "" is sfcp.DefaultEngineSocket; tests pass their own.
func (r *Runtime) ListenEngine(socket string) error {
	table, err := r.newEngineOps()
	if err != nil {
		return err
	}
	return r.listenEngine(socket, table)
}

func (r *Runtime) listenEngine(socket string, table *engineops.Table) error {
	cursor, err := r.loadEngineCursor()
	if err != nil {
		return err
	}
	events, err := engineevents.New(r.engineEventHandlers(), cursor, r.saveEngineCursor)
	if err != nil {
		return err
	}
	if err := routeEngineOps(r.Mesh, table); err != nil {
		return err
	}
	r.engineEvents = events
	r.Mesh.OnEngine(r.followEngineEvents)
	if socket == "" {
		socket = sfcp.DefaultEngineSocket
		// /run/sfe is shared with sfed (its API socket); root only.
		if err := os.MkdirAll(filepath.Dir(socket), 0755); err != nil {
			return err
		}
	}
	return r.Mesh.ListenEngine(socket)
}

func (r *Runtime) loadEngineCursor() (engineevents.Cursor, error) {
	if r.reports == nil {
		return engineevents.Cursor{}, nil
	}
	raw, err := r.reports.GetBounded(engineCursorKey, 4096)
	if errors.Is(err, storage.ErrMissing) {
		return engineevents.Cursor{}, nil
	}
	if err != nil {
		return engineevents.Cursor{}, err
	}
	return schema.Decode[engineevents.Cursor](raw)
}

func (r *Runtime) saveEngineCursor(c engineevents.Cursor) error {
	if r.reports == nil {
		return nil
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return r.reports.Write(map[string][]byte{engineCursorKey: raw})
}

// followEngineEvents subscribes to purpose 32 on a newly connected engine and
// applies every pushed batch until the session ends. A feed behind the saved
// cursor is subscribed again from the reset cursor.
func (r *Runtime) followEngineEvents(e *sfcp.EngineSession) {
	r.engineFollowMu.Lock() // one subscription at a time; a new engine replaces the old
	defer r.engineFollowMu.Unlock()
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	go func() {
		select {
		case <-e.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	for ctx.Err() == nil {
		err := r.subscribeEngineEvents(ctx, e)
		if errors.Is(err, engineevents.ErrResubscribe) {
			continue
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("engine events: subscription ended: %v", err)
		}
		return
	}
}

func (r *Runtime) subscribeEngineEvents(ctx context.Context, e *sfcp.EngineSession) error {
	st, err := e.Open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	stop := context.AfterFunc(ctx, func() { st.CancelRead(0); st.CancelWrite(0) })
	defer stop()
	body, err := json.Marshal(engineevents.Subscribe{Request: engineRequest("subscribe"), After: r.engineEvents.After()})
	if err != nil {
		return err
	}
	purpose := sfcp.Purpose(sfcp.EngineEvents)
	if err := st.WriteFrame(sfcp.Frame{Purpose: purpose, Kind: 1, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: body}}}); err != nil {
		return err
	}
	answer, err := st.ReadFrame(sfcp.MaxBody)
	if err != nil {
		return err
	}
	if answer.Purpose != purpose || answer.Kind != 2 || len(answer.Fields) == 0 {
		return fmt.Errorf("engine events: unexpected answer kind %d", answer.Kind)
	}
	subscribed, err := schema.Decode[engineevents.Subscribed](answer.Fields[0].Value)
	if err != nil {
		return fmt.Errorf("engine events: subscribe answer: %w", err)
	}
	if err := r.engineEvents.Subscribed(ctx, subscribed); err != nil {
		return err
	}
	for {
		f, err := st.ReadFrame(sfcp.MaxBody)
		if err != nil {
			return err
		}
		if f.Purpose != purpose || f.Kind != 16 || len(f.Fields) == 0 {
			return fmt.Errorf("engine events: unexpected frame kind %d", f.Kind)
		}
		var batch engineevents.Batch
		if err := json.Unmarshal(f.Fields[0].Value, &batch); err != nil {
			return fmt.Errorf("engine events: batch: %w", err)
		}
		if err := r.engineEvents.Apply(ctx, batch); err != nil {
			return err
		}
	}
}

// engineChunkWriter cuts a stream into kind 4 chunks on the engine socket's
// own codec (sfcp.ChunkWriter frames with the mesh codec, which refuses
// engine purposes). Offsets count from 0 within the stream.
type engineChunkWriter struct {
	st     sfcp.EngineStream
	p      sfcp.Purpose
	header [32]byte
	offset uint64
}

func (w *engineChunkWriter) Write(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		take := min(len(b), sfcp.ChunkSize)
		var off [8]byte
		binary.LittleEndian.PutUint64(off[:], w.offset)
		if err := w.st.WriteFrame(sfcp.Frame{Purpose: w.p, Kind: 4, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: off[:]}, {Tag: 2, Required: true, Value: b[:take]}, {Tag: 3, Required: true, Value: w.header[:]}}}); err != nil {
			return n, err
		}
		w.offset += uint64(take)
		b, n = b[take:], n+take
	}
	return n, nil
}
