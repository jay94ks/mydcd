// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"github.com/jay94ks/seafield/internal/cluster/recovery"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// SnapshotPoint is where an exported snapshot stands: its Raft position and
// term, the state's own command ordinal and digest, and the size and SHA-256
// of the whole MDS1 snapshot.
type SnapshotPoint struct {
	RaftIndex, Term uint64
	Index           uint64
	StateDigest     [32]byte
	Size            uint64
	Digest          [32]byte
}

// ErrSnapshotBehind means the local FSM has not reached the requested Raft
// floor yet.
var ErrSnapshotBehind = errors.New("local FSM behind the backup floor")

type writerSink struct {
	io.Writer
}

func (writerSink) ID() string    { return "backup" }
func (writerSink) Cancel() error { return nil }
func (writerSink) Close() error  { return nil }

// SnapshotExport is one FSM state held for export. The state is immutable,
// so it can be written more than once with the same bytes.
type SnapshotExport struct {
	snap  *fsmSnapshot
	Point SnapshotPoint
}

// ExportSnapshot holds the current FSM once it covers Raft position floor,
// as one MDS1 snapshot: the same bytes a Raft snapshot holds. It is a read;
// it neither takes a Raft snapshot nor trims the log. The caller releases it.
func (e *Engine) ExportSnapshot(floor uint64) (*SnapshotExport, error) {
	if e == nil || floor == 0 {
		return nil, errors.New("snapshot export needs an engine and a floor")
	}
	snap, err := e.fsm.Snapshot()
	if err != nil {
		return nil, err
	}
	s := snap.(*fsmSnapshot)
	if s.position < floor {
		s.Release()
		return nil, ErrSnapshotBehind
	}
	x := &SnapshotExport{snap: s, Point: SnapshotPoint{RaftIndex: s.position, Term: s.meta.Term, Index: s.meta.Index, StateDigest: s.meta.Digest}}
	h := sha256.New()
	count := &countedWriter{Writer: h}
	if _, err := x.WriteTo(count); err != nil {
		s.Release()
		return nil, err
	}
	x.Point.Size = uint64(count.n)
	copy(x.Point.Digest[:], h.Sum(nil))
	return x, nil
}

// WriteTo writes the MDS1 snapshot.
func (x *SnapshotExport) WriteTo(w io.Writer) (int64, error) {
	count := &countedWriter{Writer: w}
	err := x.snap.Persist(writerSink{count})
	return count.n, err
}

// Release drops the held state.
func (x *SnapshotExport) Release() { x.snap.Release() }

// ReadSnapshot checks one MDS1 snapshot of cluster and decodes its state
// strictly, as Restore would before installing it.
func ReadSnapshot(cluster [32]byte, source io.Reader) (SnapshotPoint, state.State, error) {
	header := make([]byte, snapshotHeaderSize)
	if _, err := io.ReadFull(source, header); err != nil {
		return SnapshotPoint{}, state.State{}, err
	}
	position := binary.LittleEndian.Uint64(header[40:48])
	configSize := binary.LittleEndian.Uint32(header[64:68])
	dataSize := binary.LittleEndian.Uint64(header[68:76])
	if string(header[:4]) != "MDS1" || binary.LittleEndian.Uint32(header[4:8]) != 1 || hex.EncodeToString(header[8:40]) != hex.EncodeToString(cluster[:]) || position == 0 || configSize == 0 || configSize > maxConfiguration || dataSize == 0 || dataSize > uint64(^uint(0)>>1) {
		return SnapshotPoint{}, state.State{}, errors.New("invalid snapshot binding/length")
	}
	configuration := make([]byte, configSize)
	if _, err := io.ReadFull(source, configuration); err != nil {
		return SnapshotPoint{}, state.State{}, err
	}
	meta := recovery.Metadata{Schema: 1, Index: binary.LittleEndian.Uint64(header[56:64]), Term: binary.LittleEndian.Uint64(header[48:56]), Size: int(dataSize)}
	copy(meta.Configuration[:], header[76:108])
	copy(meta.Digest[:], header[108:140])
	if meta.Configuration != sha256Sum(configuration) {
		return SnapshotPoint{}, state.State{}, errors.New("snapshot configuration checksum mismatch")
	}
	if len(configuration) >= 12 && string(configuration[:4]) == "MDC1" {
		index := binary.LittleEndian.Uint64(configuration[4:12])
		if index == 0 || index > position || len(configuration) == 12 {
			return SnapshotPoint{}, state.State{}, errors.New("invalid snapshot configuration index")
		}
	}
	verified, err := recovery.Verify(meta, source)
	if err != nil {
		return SnapshotPoint{}, state.State{}, err
	}
	if err = haveStateFeatures(verified.State()); err != nil {
		return SnapshotPoint{}, state.State{}, err
	}
	return SnapshotPoint{RaftIndex: position, Term: meta.Term, Index: meta.Index, StateDigest: meta.Digest}, verified.State(), nil
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
