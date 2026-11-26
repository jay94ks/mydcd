// SPDX-License-Identifier: Apache-2.0

package deployment

// expired marks every stage observation of e Expired, as the leader does in
// Raft once owners stop renewing them (devel/refactor/14-raft-liveness.md).
func expired(e Execution) Execution {
	n, err := e.cloneAt(e.d.Revision)
	if err != nil {
		panic(err)
	}
	for i := range n.d.Stages {
		if o := n.d.Stages[i].Observation; o != nil {
			c := *o
			c.Expired = true
			n.d.Stages[i].Observation = &c
		}
	}
	return n
}
