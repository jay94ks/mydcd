// SPDX-License-Identifier: Apache-2.0

package cluster

// nodeMethodKind is how the management handler serves a node method.
type nodeMethodKind uint8

const (
	// nodeReport writes to Raft: the leader turns the input into a command
	// (commandModule) and submits it. Its R14 class says why it is in Raft.
	nodeReport nodeMethodKind = iota + 1
	// nodeLeaderRead is a fresh read on the leader (ReadIndex): permits,
	// work lists and leader-memory state such as observation renewals.
	nodeLeaderRead
	// nodeOwnerRead is node-local readback on the native owner. It is not an
	// authority read: that owner obtains fresh quorum permits itself.
	nodeOwnerRead
	// nodeVolumePermit is the fresh member volume activation read.
	nodeVolumePermit
)

// nodeMethod is everything the management handler knows about one method a
// member node calls on another. Adding a node method means adding one entry
// here and its handler in the module that owns it.
type nodeMethod struct {
	kind   nodeMethodKind
	report ReportClass
	// fail is the reply message when the module refuses or cannot answer.
	fail string
}

func report(class ReportClass) nodeMethod { return nodeMethod{kind: nodeReport, report: class} }
func leaderRead() nodeMethod {
	return nodeMethod{kind: nodeLeaderRead, fail: "current app read denied"}
}
func ownerRead(fail string) nodeMethod { return nodeMethod{kind: nodeOwnerRead, fail: fail} }

// nodeMethods is the one list of node methods served over Management. The
// built-in methods (status, get, result, observe, plan, submit) are not in it.
var nodeMethods = map[string]nodeMethod{
	"app-command":           report(ReportCommand),
	"vault-approve-command": report(ReportCommand),
	"member-report":         report(ReportCommand),

	"node-shell-report":                  report(ReportWork),
	"standalone-policy-report":           report(ReportWork),
	"image-build-cache-automatic-report": report(ReportWork),
	"image-build-automatic-git-report":   report(ReportWork),
	"image-build-cache-prune-report":     report(ReportWork),
	"image-build-job-report":             report(ReportWork),
	"image-build-owner-report":           report(ReportWork),
	"registry-maintenance-report":        report(ReportWork),
	"image-cache-report":                 report(ReportWork),
	"tunnel-reconnect-report":            report(ReportWork),
	"compact-report":                     report(ReportWork),
	"task-restart-report":                report(ReportWork),
	"tenant-retirement-report":           report(ReportWork),
	"route-retirement":                   report(ReportWork),
	"route-dispatch":                     report(ReportWork),
	"volume-backup-report":               report(ReportWork),
	"volume-archive-report":              report(ReportWork),
	"volume-archive-key-report":          report(ReportWork),
	"volume-restore-report":              report(ReportWork),
	"volume-delete-report":               report(ReportWork),
	"volume-remote-fence-report":         report(ReportWork),
	"volume-file-report":                 report(ReportWork),
	"volume-create-report":               report(ReportWork),
	"volume-move-report":                 report(ReportWork),
	"checker-build-report":               report(ReportWork),
	"external-registry-closed":           report(ReportWork),
	"system-network-report":              report(ReportWork),
	"network-leave-report":               report(ReportWork),
	"virtual-bridge-closed":              report(ReportWork),
	"credential-store-report":            report(ReportWork),
	"vault-holder-report":                report(ReportWork),
	"vps-report":                         report(ReportWork),
	"owned-vps-report":                   report(ReportWork),

	"certificate-expiry-report":          report(ReportFact),
	"image-build-git-observation-report": report(ReportFact),
	"network-dns-progress":               report(ReportFact),
	"node-storage-report":                report(ReportFact),
	"registry-report":                    report(ReportFact),

	"app-progress":          report(ReportProgress),
	"app-delivery-progress": report(ReportProgress),

	"node-shell-owner-view":           leaderRead(),
	"node-shell-permit":               leaderRead(),
	"node-identity-activation":        leaderRead(),
	"node-diagnostics-permit":         leaderRead(),
	"lifecycle-source-version-permit": leaderRead(),
	"service-call-permit":             leaderRead(),
	"image-build-base-work":           leaderRead(),
	"image-build-registry-permit":     leaderRead(),
	"image-build-secret-inputs":       leaderRead(),
	"image-build-cache-prune-work":    leaderRead(),
	"image-build-job-work":            leaderRead(),
	"image-build-artifact-work":       leaderRead(),
	"image-build-io-permit":           leaderRead(),
	"image-build-part-permit":         leaderRead(),
	"registry-maintenance-work":       leaderRead(),
	"image-cache-plan-permit":         leaderRead(),
	"image-cache-work":                leaderRead(),
	"tunnel-reconnect-work":           leaderRead(),
	"compact-work":                    leaderRead(),
	"task-restart-permit":             leaderRead(),
	"container-session-plan":          leaderRead(),
	"container-session-permit":        leaderRead(),
	"container-read-permit":           leaderRead(),
	"tenant-retirement-work":          leaderRead(),
	"node-runtime-work":               leaderRead(),
	"route-native-permit":             leaderRead(),
	"route-work":                      leaderRead(),
	"registry-image-permit":           leaderRead(),
	"registry-work":                   leaderRead(),
	"external-registry-work":          leaderRead(),
	"checker-cache-gc-fence":          leaderRead(),
	"checker-probe-permit":            leaderRead(),
	"checker-shutdown-permit":         leaderRead(),
	"checker-build-permit":            leaderRead(),
	"checker-source-permit":           leaderRead(),
	"checker-artifact-permit":         leaderRead(),
	"app-native-permit":               leaderRead(),
	"app-binding-permit":              leaderRead(),
	"app-input-read-permit":           leaderRead(),
	"app-delivery-permit":             leaderRead(),
	"app-delivery-sync-work":          leaderRead(),
	"app-result":                      leaderRead(),
	"vault-write-permit":              leaderRead(),
	"vault-approval-permit":           leaderRead(),
	"vault-approval-result":           leaderRead(),
	"volume-file-work":                leaderRead(),
	"volume-usage-permit":             leaderRead(),
	"volume-backup-permit":            leaderRead(),
	"volume-archive-permit":           leaderRead(),
	"volume-archive-unseal":           leaderRead(),
	"volume-restore-permit":           leaderRead(),
	"volume-delete-permit":            leaderRead(),
	"volume-retained-delete-permit":   leaderRead(),
	"volume-create-permit":            leaderRead(),
	"volume-move-permit":              leaderRead(),
	"node-storage-permit":             leaderRead(),
	"node-disk-permit":                leaderRead(),
	"node-firewall-permit":            leaderRead(),
	"vps-status":                      leaderRead(),
	"owned-vps-status":                leaderRead(),
	"owned-vps-instances":             leaderRead(),
	"vps-traffic":                     leaderRead(),
	"vps-traffic-history":             leaderRead(),

	"node-diagnostics-owner":         ownerRead("volume observation unavailable"),
	"node-logs-owner":                ownerRead("node logs unavailable"),
	"node-disk-owner":                ownerRead("node disk operation unavailable"),
	"node-firewall-owner":            ownerRead("node firewall unavailable"),
	"lifecycle-source-version-owner": ownerRead("volume observation unavailable"),
	"ingress-observe":                ownerRead("volume observation unavailable"),
	"image-build-base-tls-owner":     ownerRead("image build registry trust unavailable"),
	"image-build-registry-tls-owner": ownerRead("image build registry trust unavailable"),
	"image-build-base-token-owner":   ownerRead("image build base authentication unavailable"),
	"image-build-base-owner":         ownerRead("image build base resolution unavailable"),
	"image-build-caches-owner":       ownerRead("image build cache observation unavailable"),
	"image-build-cache-owner":        ownerRead("image build cache observation unavailable"),
	"image-build-logs-owner":         ownerRead("image build logs unavailable"),
	"image-build-publication-owner":  ownerRead("image build publication observation unavailable"),
	"image-build-git-owner":          ownerRead("volume observation unavailable"),
	"image-build-draft-owner":        ownerRead("volume observation unavailable"),
	"image-build-content-owner":      ownerRead("volume observation unavailable"),
	"image-build-source-owner":       ownerRead("volume observation unavailable"),
	"image-build-owner":              ownerRead("volume observation unavailable"),
	"registry-prune-owner":           ownerRead("volume observation unavailable"),
	"registry-catalog-owner":         ownerRead("volume observation unavailable"),
	"event-receipt":                  ownerRead("volume observation unavailable"),
	"image-cache-native-plan":        ownerRead("volume observation unavailable"),
	"external-registry-probe":        ownerRead("volume observation unavailable"),
	"image-resolve-owner":            ownerRead("volume observation unavailable"),
	"container-observe":              ownerRead("volume observation unavailable"),
	"logs-clear-node":                ownerRead("log clear unavailable"),
	"stored-logs-node":               ownerRead("stored logs unavailable"),
	"route-flow-observe":             ownerRead("route flow observation unavailable"),
	"checker-cache-observe":          ownerRead("checker cache observation unavailable"),
	"volume-usage-observe":           ownerRead("volume observation unavailable"),
	"volume-backup-source-observe":   ownerRead("volume observation unavailable"),
	"volume-move-recipe-observe":     ownerRead("volume observation unavailable"),
	"volume-move-inputs-observe":     ownerRead("volume observation unavailable"),
	"node-storage-space-observe":     ownerRead("volume observation unavailable"),
	"login-records-observe":          ownerRead("volume observation unavailable"),

	"volume-permit": {kind: nodeVolumePermit, fail: "current volume activation denied"},
}

// ReportMethod reports whether method is a node report that writes to Raft,
// and its R14 class.
func ReportMethod(method string) (ReportClass, bool) {
	m, ok := nodeMethods[method]
	return m.report, ok && m.kind == nodeReport
}

// NodeReadMethods lists the node methods a member serves with its read
// module, so the module can check it serves exactly these.
func NodeReadMethods() []string {
	var out []string
	for name, m := range nodeMethods {
		if m.kind != nodeReport {
			out = append(out, name)
		}
	}
	return out
}
