// SPDX-License-Identifier: Apache-2.0

package userauth

import "github.com/jay94ks/mydcd/internal/cluster/control"

type RaftCompactNode struct {
	Operation, User, State, Code          string
	At                                    uint64
	SnapshotIndex, SnapshotBytes          uint64
	LogEntriesBefore, LogEntriesAfter     uint64
	LogFileBytesBefore, LogFileBytesAfter uint64
	LogUsedBytesBefore, LogUsedBytesAfter uint64
	LogKnown, LogFileKnown, LogUsedKnown  bool
	DurationMillis                        uint64
	ConfigRestored, TargetMet             bool
}

func lastNodeCompaction(jobs control.Compactions, node string) *RaftCompactNode {
	for i := len(jobs.Records) - 1; i >= 0; i-- {
		record := jobs.Records[i]
		n, ok := record.Job.Node(node)
		if !ok {
			continue
		}
		out := &RaftCompactNode{Operation: record.Job.Operation, User: record.Origin.Session.User, State: n.State, Code: n.Code, At: record.At}
		if r := n.Result; r != nil {
			out.SnapshotIndex = r.After.SnapshotIndex
			out.SnapshotBytes = r.After.SnapshotBytes
			out.LogEntriesBefore = r.Dispatch.Before.LogEntries
			out.LogEntriesAfter = r.After.LogEntries
			out.LogFileBytesBefore = r.Dispatch.Before.LogFileBytes
			out.LogFileBytesAfter = r.After.LogFileBytes
			out.LogUsedBytesBefore = r.Dispatch.Before.LogUsedBytes
			out.LogUsedBytesAfter = r.After.LogUsedBytes
			out.LogKnown = r.Dispatch.Before.LogKnown && r.After.LogKnown
			out.LogFileKnown = r.Dispatch.Before.LogFileKnown && r.After.LogFileKnown
			out.LogUsedKnown = r.Dispatch.Before.LogUsedKnown && r.After.LogUsedKnown
			out.DurationMillis = r.DurationMillis
			out.ConfigRestored = r.ConfigRestored
			out.TargetMet = r.TargetMet
		}
		return out
	}
	return nil
}
