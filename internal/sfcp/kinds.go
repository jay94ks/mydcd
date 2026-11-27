// SPDX-License-Identifier: Apache-2.0

package sfcp

// Every purpose gives the same frame kind the same meaning (design 4.2).
// Purpose-specific kinds start at KindOwn. Handshake and Packet keep their
// own numbering: the handshake is not a request/response conversation and a
// packet datagram has no request.
const (
	KindRequest  uint8 = 1 // opens a conversation
	KindResponse uint8 = 2 // answers it
	KindRelay    uint8 = 3 // a member forwards the unchanged original request
	KindChunk    uint8 = 4 // a data chunk
	KindRecord   uint8 = 5 // an ordered duplex record
	KindEnd      uint8 = 6 // end of data: total length and digest
	KindStored   uint8 = 7 // the receiver durably stored data up to an offset
	KindDone     uint8 = 8 // the receiver verified the whole transfer
	KindOwn      uint8 = 16
)

// Purpose-specific kinds.
const (
	// KindManagementRead is a Management read; KindRequest is a submit.
	KindManagementRead uint8 = KindOwn
	// KindImageSourceRead is a member reading an accepted build's source
	// content from its owner node.
	KindImageSourceRead uint8 = KindOwn
	// KindImageEngineRead is a member fetching repository@digest content
	// from offset for its local engine (design 4.9); no user session.
	KindImageEngineRead uint8 = KindOwn + 1

	// Observation report kinds name what a report carries; the receiver
	// never peeks into the body to find out (design 4.6).
	KindWorkloadReport  uint8 = KindOwn     // a node's workload report
	KindNodeObservation uint8 = KindOwn + 1 // a stored node observation
	KindEventBatch      uint8 = KindOwn + 2 // a batch of diagnostic events
	KindAppRenewal      uint8 = KindOwn + 3 // an unchanged app observation's renewal, to the leader
	KindAlarm           uint8 = KindOwn + 4 // an alarm/<name> event for the receiver's bus
)

// ReportKind reports whether kind is an Observation report kind.
func ReportKind(kind uint8) bool { return kind >= KindWorkloadReport && kind <= KindAlarm }
