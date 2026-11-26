// SPDX-License-Identifier: Apache-2.0

package cluster

// ReportClass is the R14 row a node report method belongs to
// (docs/architecture/raft-and-mydcp.md). Every report method is a Raft write,
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
	// changes; an unchanged fact is renewed over MyDCP.
	ReportFact
	// ReportProgress moves a deployment stage. It carries result facts
	// (native ID, applied, exit) and is CAS-bound to that stage.
	ReportProgress
)

// reportMethods is the one list of node methods that write to Raft. The
// management handler and the leader's local call both admit exactly these.
var reportMethods = map[string]ReportClass{
	"app-command":           ReportCommand,
	"vault-approve-command": ReportCommand,
	"member-report":         ReportCommand,

	"node-shell-report":                  ReportWork,
	"standalone-policy-report":           ReportWork,
	"image-build-cache-automatic-report": ReportWork,
	"image-build-automatic-git-report":   ReportWork,
	"image-build-cache-prune-report":     ReportWork,
	"image-build-job-report":             ReportWork,
	"image-build-owner-report":           ReportWork,
	"registry-maintenance-report":        ReportWork,
	"image-cache-report":                 ReportWork,
	"tunnel-reconnect-report":            ReportWork,
	"compact-report":                     ReportWork,
	"task-restart-report":                ReportWork,
	"tenant-retirement-report":           ReportWork,
	"route-retirement":                   ReportWork,
	"route-dispatch":                     ReportWork,
	"volume-backup-report":               ReportWork,
	"volume-restore-report":              ReportWork,
	"volume-delete-report":               ReportWork,
	"volume-file-report":                 ReportWork,
	"volume-create-report":               ReportWork,
	"volume-move-report":                 ReportWork,
	"checker-build-report":               ReportWork,
	"external-registry-closed":           ReportWork,

	"certificate-expiry-report":          ReportFact,
	"image-build-git-observation-report": ReportFact,
	"network-dns-progress":               ReportFact,
	"node-storage-report":                ReportFact,
	"registry-report":                    ReportFact,

	"app-progress":          ReportProgress,
	"app-delivery-progress": ReportProgress,
}

// ReportMethod reports whether method is a node report that writes to Raft,
// and its R14 class.
func ReportMethod(method string) (ReportClass, bool) {
	class, ok := reportMethods[method]
	return class, ok
}
