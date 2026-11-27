// SPDX-License-Identifier: Apache-2.0

package cluster

// ReportClass is the R14 row a node report method belongs to
// (docs/architecture/raft-and-sfcp.md). Every report method is a Raft write,
// so a new one must say why it belongs in Raft at all.
type ReportClass uint8

const (
	// ReportCommand is a user or operator command: desired state or
	// membership itself.
	ReportCommand ReportClass = iota + 1
	// ReportWork records work that must happen once: begin, complete,
	// uncertain and closure proofs another server can take over from. It
	// carries no intermediate progress.
	ReportWork
	// ReportFact is an owner observation. It is sent only when the fact
	// changes; an unchanged fact is renewed over SFCP.
	ReportFact
	// ReportProgress moves a deployment stage. It carries result facts
	// (native ID, applied, exit) and is CAS-bound to that stage.
	ReportProgress
)
