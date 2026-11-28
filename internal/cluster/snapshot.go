// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/jay94ks/seafield/internal/cluster/recovery"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"io"

	"github.com/hashicorp/raft"
)

// State size is not a fixed database or snapshot limit. Configuration has its
// own receive bound; state is streamed through a native snapshot file.
const snapshotHeaderSize = 140
const maxConfiguration = 1 << 20

type fsmSnapshot struct {
	state         state.State
	cluster       string
	position      uint64
	meta          recovery.Metadata
	configuration []byte
}
type countedWriter struct {
	io.Writer
	n int64
}

func (w *countedWriter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	w.n += int64(n)
	return n, err
}

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	if f.failed != nil {
		err := f.failed
		f.mu.RUnlock()
		return nil, err
	}
	if !f.ready {
		f.mu.RUnlock()
		return nil, ErrRecovering
	}
	if f.work.Index() == 0 {
		f.mu.RUnlock()
		return nil, raft.ErrNothingNewToSnapshot
	}
	s := &fsmSnapshot{state: f.work, cluster: f.cluster, position: f.position, configuration: append([]byte(nil), f.configuration...)}
	if f.configurationTracking(f.work) {
		if f.configurationIndex == 0 || f.configurationIndex > f.position {
			f.mu.RUnlock()
			return nil, ErrRecovering
		}
		packed := make([]byte, 12, len(s.configuration)+12)
		copy(packed, "MDC1")
		binary.LittleEndian.PutUint64(packed[4:], f.configurationIndex)
		s.configuration = append(packed, s.configuration...)
	}
	term := f.term
	f.mu.RUnlock()
	hash := sha256.New()
	count := &countedWriter{Writer: hash}
	if err := state.EncodeTo(count, s.state); err != nil {
		return nil, err
	}
	s.meta = recovery.Metadata{Schema: 1, Index: s.state.Index(), Term: term, Size: int(count.n), Configuration: sha256.Sum256(s.configuration)}
	copy(s.meta.Digest[:], hash.Sum(nil))
	return s, nil
}
func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) (err error) {
	defer func() {
		if err != nil {
			_ = sink.Cancel()
		}
	}()
	cluster, e := hex.DecodeString(s.cluster)
	if e != nil || len(cluster) != 32 || len(s.configuration) > maxConfiguration {
		return errors.New("invalid snapshot binding/configuration")
	}
	header := make([]byte, snapshotHeaderSize)
	copy(header, "MDS1")
	binary.LittleEndian.PutUint32(header[4:8], 1)
	copy(header[8:40], cluster)
	binary.LittleEndian.PutUint64(header[40:48], s.position)
	binary.LittleEndian.PutUint64(header[48:56], s.meta.Term)
	binary.LittleEndian.PutUint64(header[56:64], s.meta.Index)
	binary.LittleEndian.PutUint32(header[64:68], uint32(len(s.configuration)))
	binary.LittleEndian.PutUint64(header[68:76], uint64(s.meta.Size))
	copy(header[76:108], s.meta.Configuration[:])
	copy(header[108:140], s.meta.Digest[:])
	if _, err = io.Copy(sink, bytes.NewReader(header)); err != nil {
		return err
	}
	if _, err = io.Copy(sink, bytes.NewReader(s.configuration)); err != nil {
		return err
	}
	if err = state.EncodeTo(sink, s.state); err != nil {
		return err
	}
	return sink.Close()
}
func (s *fsmSnapshot) Release() { s.state = state.State{}; s.configuration = nil }

func (f *fsm) Restore(source io.ReadCloser) error {
	defer source.Close()
	header := make([]byte, snapshotHeaderSize)
	if _, err := io.ReadFull(source, header); err != nil {
		return err
	}
	position := binary.LittleEndian.Uint64(header[40:48])
	configSize := binary.LittleEndian.Uint32(header[64:68])
	dataSize := binary.LittleEndian.Uint64(header[68:76])
	if string(header[:4]) != "MDS1" || binary.LittleEndian.Uint32(header[4:8]) != 1 || hex.EncodeToString(header[8:40]) != f.cluster || position == 0 || configSize == 0 || configSize > maxConfiguration || dataSize == 0 || dataSize > uint64(^uint(0)>>1) {
		return errors.New("invalid snapshot binding/length")
	}
	configuration := make([]byte, configSize)
	if _, err := io.ReadFull(source, configuration); err != nil {
		return err
	}
	meta := recovery.Metadata{Schema: 1, Index: binary.LittleEndian.Uint64(header[56:64]), Term: binary.LittleEndian.Uint64(header[48:56]), Size: int(dataSize)}
	copy(meta.Configuration[:], header[76:108])
	copy(meta.Digest[:], header[108:140])
	if meta.Configuration != sha256.Sum256(configuration) {
		return errors.New("snapshot configuration checksum mismatch")
	}
	var configurationIndex uint64
	indexed := len(configuration) >= 12 && string(configuration[:4]) == "MDC1"
	if indexed {
		configurationIndex = binary.LittleEndian.Uint64(configuration[4:12])
		configuration = configuration[12:]
		if configurationIndex == 0 || configurationIndex > position || len(configuration) == 0 {
			return errors.New("invalid snapshot configuration index")
		}
	}
	verified, err := recovery.Verify(meta, source)
	if err != nil {
		return err
	}
	if indexed != f.configurationTracking(verified.State()) {
		return errors.New("snapshot configuration tracking mode mismatch")
	}
	if f.validate != nil {
		if err = f.validate(verified.State(), verified.State(), state.Command{}); err != nil {
			return err
		}
	}
	if err = haveStateFeatures(verified.State()); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed != nil {
		return f.failed
	}
	// The library owns log retention and the Raft position. Restore validates the
	// reusable state core; it does not run a second suffix/consensus algorithm.
	// Rewrite every row the old stored state or the snapshot has.
	f.dirty.AddAll(f.published)
	f.dirty.AddAll(f.work)
	f.work = verified.State()
	f.dirty.AddAll(f.work)
	f.position = position
	f.term = meta.Term
	f.configuration = configuration
	f.configurationIndex = configurationIndex
	f.ready = false
	if position > f.durable.RaftIndex {
		f.projectionRestore = position
	}
	return f.publish()
}
