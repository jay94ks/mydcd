// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"sync"

	"github.com/jay94ks/seafield/internal/buildinfo"
)

// Shape is how a purpose's stream is used. It documents the purpose and
// lets later common helpers pick the right exchange; admission does not
// depend on it.
type Shape uint8

const (
	ShapeHandshake Shape = iota + 1
	ShapeUnary           // one request frame, one response frame
	ShapeSensitive       // unary whose bodies may carry private bytes
	ShapeBulk            // request, then ordered chunks, end and receipts
	ShapeDuplex          // long-lived ordered records both ways
	ShapeReport          // report and receipt
	ShapeDatagram        // QUIC DATAGRAM, never a stream
)

// kindSpec is what one purpose/kind frame may carry and who may send it.
type kindSpec struct {
	// fields are the required tags 1..n in order: an exact length, or -1
	// for any non-empty length.
	fields []int
	// budget bounds the whole body, optional extensions included.
	budget int
	// allow reports whether the sender's current policy may send this
	// kind. Handshake kinds have none: they are allowed only before
	// authentication.
	allow func(Policy) bool
}

// purposeSpec is everything the transport knows about one purpose. Adding a
// purpose means adding its constant and one entry in purposes; frame
// parsing, admission, stream limits, handler lifetime and Unix access all
// read this table.
type purposeSpec struct {
	name  string
	shape Shape
	kinds map[uint8]kindSpec
	// limit bounds the streams of this purpose served at once on this
	// node; perPeer bounds them for one authenticated key, so one slow peer
	// cannot use up the whole limit. Zero perPeer means limit.
	limit, perPeer int
	// local admits the purpose on the management Unix socket too.
	local bool
	// longLived handlers get the transport's lifetime instead of the 30s
	// parse deadline; they bind their own plan deadline and idle budget.
	// On Unix a long-lived exchange also owns its connection.
	longLived bool
	// needs are the features every kind of this purpose requires; a peer
	// that did not announce them in its handshake is never sent the purpose
	// and its frames of it are refused (devel/design/sfcp-transit.md 12).
	needs buildinfo.Features
	// kindNeeds adds features one kind needs beyond the purpose's own (a
	// kind added to an existing purpose later in the major).
	kindNeeds map[uint8]buildinfo.Features
}

func allowAny(bits ...func(Policy) bool) func(Policy) bool {
	return func(p Policy) bool {
		for _, b := range bits {
			if b(p) {
				return true
			}
		}
		return false
	}
}

var (
	byManage   = func(p Policy) bool { return p.Manage }
	byRead     = func(p Policy) bool { return p.Read }
	byRespond  = func(p Policy) bool { return p.Respond }
	byMember   = func(p Policy) bool { return p.Member }
	byReport   = func(p Policy) bool { return p.Report }
	byTunnel   = func(p Policy) bool { return p.Tunnel }
	byUser     = func(p Policy) bool { return p.UserAuth }
	byReplica  = allowAny(byMember, func(p Policy) bool { return p.Replicate })
	bySnapshot = func(p Policy) bool { return byReplica(p) && p.Snapshot }
	byPath     = func(p Policy) bool { return p.Member && p.Tunnel }
	byJoinResp = func(p Policy) bool { return byReplica(p) && p.Respond }
	byAnyEnd   = allowAny(byUser, byMember, byRespond)
)

const (
	envelopeBudget = 128 << 10
	chunkBudget    = ChunkSize + 64
)

func envelope(budget int, allow func(Policy) bool) kindSpec {
	return kindSpec{[]int{-1, 32}, budget, allow}
}
func chunk(allow func(Policy) bool) kindSpec {
	return kindSpec{[]int{8, -1, 32}, chunkBudget, allow}
}
func report() kindSpec { return kindSpec{[]int{-1}, 64 << 10, byReport} }
func receipt(allow func(Policy) bool) kindSpec {
	return kindSpec{[]int{32, 32}, 128, allow}
}

// userTransfer is the kind set of user-started finite transfers.
func userTransfer() map[uint8]kindSpec {
	return map[uint8]kindSpec{
		KindRequest:  envelope(envelopeBudget, byUser),
		KindResponse: envelope(envelopeBudget, byRespond),
		KindRelay:    envelope(envelopeBudget, byMember),
		KindChunk:    chunk(byAnyEnd),
	}
}

// userKinds: User purpose. Its chunks are user upload input, so a
// responder never sends them.
func userKinds() map[uint8]kindSpec {
	k := userTransfer()
	k[KindChunk] = chunk(allowAny(byUser, byMember))
	return k
}

// userSession is the kind set of user-started duplex sessions.
func userSession() map[uint8]kindSpec {
	return map[uint8]kindSpec{
		KindRequest:  envelope(envelopeBudget, byUser),
		KindResponse: envelope(envelopeBudget, byRespond),
		KindRelay:    envelope(envelopeBudget, byMember),
		KindRecord:   envelope(envelopeBudget, byAnyEnd),
	}
}

// sensitive is the kind set of member-only private request/response.
func sensitive(budget int) map[uint8]kindSpec {
	return map[uint8]kindSpec{KindRequest: envelope(budget, byMember), KindResponse: envelope(budget, byMember)}
}

var purposes = map[Purpose]purposeSpec{
	Handshake: {name: "handshake", shape: ShapeHandshake, kinds: map[uint8]kindSpec{
		1: {fields: []int{32, 32, 32}, budget: 4096},
		2: {fields: []int{32, 32, 32, 64}, budget: 4096},
		3: {fields: []int{32}, budget: 4096},
		4: {fields: []int{32, 32, 32, -1, 64}, budget: 4096},
	}},
	// Request is a submit, Relay a member relay of an original signed
	// request (relay permission never authorizes the original command).
	Management: {name: "management", shape: ShapeUnary, kinds: map[uint8]kindSpec{
		KindRequest:        envelope(envelopeBudget, byManage),
		KindResponse:       envelope(envelopeBudget, byRespond),
		KindRelay:          envelope(envelopeBudget, byMember),
		KindManagementRead: envelope(envelopeBudget, byRead),
	}, limit: 16, perPeer: 8},
	// Non-voters also exchange replication RPCs; the Raft library alone
	// decides voting and leadership.
	Raft: {name: "raft", shape: ShapeUnary, kinds: map[uint8]kindSpec{
		KindRequest:  {fields: []int{-1}, budget: MaxBody, allow: byReplica},
		KindResponse: {fields: []int{-1}, budget: MaxBody, allow: byReplica},
	}, limit: 32, perPeer: 16},
	// Request is the metadata, Done the installed ACK.
	Snapshot: {name: "snapshot", shape: ShapeBulk, kinds: map[uint8]kindSpec{
		KindRequest: envelope(4096, bySnapshot),
		KindChunk:   {fields: []int{8, -1, 32}, budget: 128<<10 + 64, allow: bySnapshot},
		KindDone:    {fields: []int{8, 8, 32}, budget: 128, allow: bySnapshot},
	}, limit: 2},
	Observation: {name: "observation", shape: ShapeReport, kinds: map[uint8]kindSpec{
		KindResponse:        {fields: []int{32}, budget: 2048, allow: byRespond}, // + optional refused-item bitmap
		KindWorkloadReport:  report(),
		KindNodeObservation: report(),
		KindEventBatch:      report(),
		KindAppRenewal:      report(),
		KindAlarm:           report(),
	}, limit: 8, perPeer: 4},
	Packet: {name: "packet", shape: ShapeDatagram, kinds: map[uint8]kindSpec{
		1: {fields: []int{32, 16, 16, -1}, budget: 65535 + 128, allow: byTunnel},
		2: {fields: []int{32, 16, 16, -1}, budget: 65535 + 128, allow: byTunnel},
	}},
	PathControl: {name: "path-control", shape: ShapeUnary, kinds: map[uint8]kindSpec{
		KindRequest:  envelope(4096, byPath),
		KindResponse: envelope(4096, byPath),
	}, limit: 8},
	User: {name: "user", shape: ShapeUnary, kinds: userKinds(), limit: 16, local: true}, // no per-peer share: the web daemon and relaying members carry many users on one key
	Membership: {name: "membership", shape: ShapeUnary, kinds: map[uint8]kindSpec{
		KindRequest:  envelope(envelopeBudget, byReplica),
		KindResponse: envelope(envelopeBudget, byJoinResp),
	}, limit: 8},
	SecretInput: {name: "secret-input", shape: ShapeUnary, kinds: map[uint8]kindSpec{
		KindRequest:  envelope(64<<10, byUser),
		KindResponse: envelope(64<<10, byRespond),
	}, limit: 8, local: true},
	SecretFetch: {name: "secret-fetch", shape: ShapeSensitive, kinds: sensitive(envelopeBudget), limit: 4},
	// Stored is the per-chunk ACK, Done the verified ACK.
	VolumeTransfer: {name: "volume-transfer", shape: ShapeBulk, kinds: map[uint8]kindSpec{
		KindRequest: envelope(32<<10, byMember),
		KindChunk:   {fields: []int{8, -1, 32}, budget: (128 << 10) + 64, allow: byMember},
		KindEnd:     {fields: []int{8, 32, 32}, budget: 128, allow: byMember},
		KindStored:  {fields: []int{8, 32}, budget: 64, allow: byMember},
		KindDone:    {fields: []int{8, 32, 32}, budget: 128, allow: byMember},
	}, limit: 1, longLived: true},
	// Response is the metadata. Both sides send End: the puller after its
	// request, the source after its last chunk.
	CheckerArtifact: {name: "checker-artifact", shape: ShapeBulk, kinds: map[uint8]kindSpec{
		KindRequest:  envelope(32<<10, byMember),
		KindResponse: envelope(24<<10, byMember),
		KindChunk:    chunk(byMember),
		KindEnd:      receipt(byMember),
		KindStored:   receipt(byMember),
		KindDone:     receipt(byMember),
	}, limit: 2, longLived: true},
	// Both sides send Chunk and End: the caller its payload, the prober its
	// result after the Response header.
	CheckerProbe: {name: "checker-probe", shape: ShapeBulk, kinds: map[uint8]kindSpec{
		KindRequest:  envelope(envelopeBudget, byMember),
		KindResponse: envelope(2048, byMember),
		KindChunk:    chunk(byMember),
		KindEnd:      receipt(byMember),
		KindStored:   receipt(byMember),
		KindDone:     receipt(byMember),
	}, limit: 2, longLived: true},
	ContainerSession:    {name: "container-session", shape: ShapeDuplex, kinds: userSession(), limit: 8, local: true, longLived: true},
	ImageContent:        {name: "image-content", shape: ShapeBulk, kinds: imageContentKinds(), limit: 2, local: true, longLived: true},
	CertificateMaterial: {name: "certificate-material", shape: ShapeSensitive, kinds: sensitive(64 << 10), limit: 2},
	VolumeFile:          {name: "volume-file", shape: ShapeBulk, kinds: userTransfer(), limit: 2, local: true, longLived: true},
	NodeShell:           {name: "node-shell", shape: ShapeDuplex, kinds: userSession(), limit: 64, local: true, longLived: true},
	ClusterBackup:       {name: "cluster-backup", shape: ShapeBulk, kinds: userTransfer(), limit: 1, local: true, longLived: true},
	// Request is the watch (user), Response the change frames.
	ChangeWatch: {name: "change-watch", shape: ShapeDuplex, kinds: map[uint8]kindSpec{
		KindRequest:  envelope(envelopeBudget, byUser),
		KindResponse: envelope(envelopeBudget, byRespond),
	}, limit: 32, local: true, longLived: true},
	// Voter-to-voter sealed builtin Secret values; the handler still checks
	// committed voter membership and holdings.
	VaultValue: {name: "vault-value", shape: ShapeSensitive, kinds: sensitive(192 << 10), limit: 4},
	// One file operation per stream: kind 1 asks (tag 1 header JSON, tag 2
	// its SHA-256, optional extension tag 128 write data), kind 2 answers (tag 1 reply
	// JSON, tag 2 the request digest, optional tag 128 read data). Data is at
	// most VolumeFSData, so a FUSE request is one frame. The home checks the
	// committed share binding of the caller on every operation.
	VolumeFS: {name: "volume-fs", shape: ShapeUnary, kinds: map[uint8]kindSpec{
		1: {fields: []int{-1, 32}, budget: VolumeFSData + 8<<10, allow: byMember},
		2: {fields: []int{-1, 32}, budget: VolumeFSData + 8<<10, allow: byMember},
	}, limit: 64, perPeer: 16},
}

// imageContentKinds: the user transfer kinds with data chunks only from the
// responder, plus the member-started reads: an accepted build's source and
// content for the local engine.
func imageContentKinds() map[uint8]kindSpec {
	k := userTransfer()
	k[KindChunk] = chunk(byRespond)
	k[KindImageSourceRead] = envelope(envelopeBudget, byMember)
	k[KindImageEngineRead] = envelope(envelopeBudget, byMember)
	return k
}

func specOf(p Purpose) (purposeSpec, bool) {
	s, ok := purposes[p]
	return s, ok
}

// needsOf is the features a purpose/kind frame requires of both ends.
func needsOf(p Purpose, kind uint8) buildinfo.Features {
	s, ok := purposes[p]
	if !ok {
		return 0
	}
	return s.needs | s.kindNeeds[kind]
}

func kindOf(p Purpose, kind uint8) (kindSpec, bool) {
	s, ok := purposes[p]
	if !ok {
		return kindSpec{}, false
	}
	k, ok := s.kinds[kind]
	return k, ok
}

// fieldRule returns the required tag lengths and body budget of a frame, or
// a zero budget for an unknown purpose/kind.
func fieldRule(p Purpose, kind uint8) ([]int, int) {
	k, ok := kindOf(p, kind)
	if !ok {
		return nil, 0
	}
	return k.fields, k.budget
}

func localPurpose(p Purpose) bool {
	s, ok := specOf(p)
	return ok && s.local
}

func longLivedPurpose(p Purpose) bool {
	s, ok := specOf(p)
	return ok && s.longLived
}

// streamLimits is the stream budget of one transport: a global channel per
// purpose (its capacity is the purpose limit) and a count per peer.
type streamLimits struct {
	mu      sync.Mutex
	perPeer map[peerPurpose]int
}
type peerPurpose struct {
	key     Identity
	purpose Purpose
}

func newPurposeLimits() map[Purpose]chan struct{} {
	limits := map[Purpose]chan struct{}{}
	for p, s := range purposes {
		if s.limit > 0 {
			limits[p] = make(chan struct{}, s.limit)
		}
	}
	return limits
}

// acquire takes one stream of purpose p for key, or reports false when the
// purpose or that peer's share is full. release undoes a true acquire.
func (t *Transport) acquire(key Identity, p Purpose) (release func(), ok bool) {
	global := t.limits[p]
	if global == nil {
		return nil, false
	}
	select {
	case global <- struct{}{}:
	default:
		return nil, false
	}
	share := purposes[p].perPeer
	if share <= 0 {
		return func() { <-global }, true
	}
	k := peerPurpose{key, p}
	t.streams.mu.Lock()
	if t.streams.perPeer == nil {
		t.streams.perPeer = map[peerPurpose]int{}
	}
	if t.streams.perPeer[k] >= share {
		t.streams.mu.Unlock()
		<-global
		return nil, false
	}
	t.streams.perPeer[k]++
	t.streams.mu.Unlock()
	return func() {
		t.streams.mu.Lock()
		if t.streams.perPeer[k]--; t.streams.perPeer[k] <= 0 {
			delete(t.streams.perPeer, k)
		}
		t.streams.mu.Unlock()
		<-global
	}, true
}
