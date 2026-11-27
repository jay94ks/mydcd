// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"io"

	"github.com/jay94ks/seafield/pkg/sfcp/wire"
)

// The codec lives in pkg/sfcp/wire (dependency-free, shared with the
// Seafield engine); this package supplies the rule table (purposes.go).
const HeaderSize = wire.HeaderSize
const MaxBody = wire.MaxBody

var (
	ErrFrame     = wire.ErrFrame
	ErrBudget    = wire.ErrBudget
	ErrTruncated = wire.ErrTruncated
)

type (
	Purpose = wire.Purpose
	Field   = wire.Field
	Frame   = wire.Frame
	Decoder = wire.Decoder
)

const (
	Handshake Purpose = iota + 1
	Management
	Raft
	Snapshot
	Observation
	Packet
	PathControl
	User
	Membership
	SecretInput
	SecretFetch
	VolumeTransfer
	CheckerArtifact
	CheckerProbe
	ContainerSession
	ImageContent
	CertificateMaterial
	VolumeFile Purpose = 18
	NodeShell  Purpose = 19
	// ClusterBackup streams one cluster backup from a voter to the CLI.
	ClusterBackup Purpose = 20
	VaultValue    Purpose = 21
	// ChangeWatch streams committed cluster changes (record references)
	// to one authenticated user session until it closes or expires.
	ChangeWatch Purpose = 22
	// VolumeFS carries file operations of a shared Volume from a consuming
	// server to the Volume's home (23 is reserved).
	VolumeFS Purpose = 24
)

// Numbers reserved for transit sessions (devel/design/sfcp-transit.md,
// 0.1.1). No build before then defines them, so a frame using them is an
// ordinary unknown-purpose/kind refusal; nothing else may take them.
const (
	reservedTransitPurpose Purpose = 25
	reservedTransitLoad    uint8   = KindOwn + 5 // Observation: transit load report
)

// codec checks frames against the purpose table.
var codec = wire.Rules(func(p Purpose, kind uint8) (wire.Rule, bool) {
	k, ok := kindOf(p, kind)
	if !ok {
		return wire.Rule{}, false
	}
	return wire.Rule{Fields: k.fields, Budget: k.budget, NoRequest: p == Packet}, true
})

func Encode(f Frame) ([]byte, error)                  { return codec.Encode(f) }
func NewDecoder(limit int) (*Decoder, error)          { return codec.NewDecoder(limit) }
func ReadFrame(r io.Reader, limit int) (Frame, error) { return codec.ReadFrame(r, limit) }
func WriteFrame(w io.Writer, f Frame) error           { return codec.WriteFrame(w, f) }
