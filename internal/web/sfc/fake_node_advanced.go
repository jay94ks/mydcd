// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// REQ-51 in the fake. Reachability is the node summary Status
// ("unreachable"); the fixture's node-d is unreachable. Drain moves the
// task rows at once (the app document is not rewritten).

func (w *world) summaryStatus(node string) string {
	for _, s := range w.summaries {
		if s.Node == node {
			return s.Status
		}
	}
	return ""
}

func quorumOf(voters int) (quorum, tolerates int) {
	if voters == 0 {
		return 0, 0
	}
	q := voters/2 + 1
	return q, voters - q
}

// voterPlan: the voter set without node.
func (w *world) voterPlan(node string, needVoter bool) voterPlanView {
	p := voterPlanView{Node: node}
	i := w.memberIndex(node)
	if i < 0 {
		p.Code = NodeUnknown
		return p
	}
	voters, reachable := 0, 0
	for _, m := range w.members {
		if m.Voter && m.ID != node {
			voters++
			if w.summaryStatus(m.ID) != "unreachable" {
				reachable++
			}
		}
	}
	p.VotersAfter = voters
	p.Quorum, p.Tolerates = quorumOf(voters)
	switch {
	case needVoter && !w.members[i].Voter:
		p.Code = NodeNotVoter
	case w.members[i].Voter && voters == 0:
		p.Code = NodeLastVoter
	case w.members[i].Voter && reachable < p.Quorum:
		p.Code = NodeQuorumLoss
	}
	p.Plan = fakeDigest("node-voter", node, p.Code, fmt.Sprint(voters, reachable, w.members[i].Revision))
	return p
}

func (w *world) serviceVolumes(a *fakeApp, service string) []string {
	src, ok := a.running()
	if !ok {
		return nil
	}
	var d struct {
		Services map[string]struct {
			Volumes []any `yaml:"volumes"`
		} `yaml:"services"`
	}
	if yaml.Unmarshal(src.Document, &d) != nil {
		return nil
	}
	var out []string
	for _, m := range parseMounts(d.Services[service].Volumes) {
		out = append(out, m.Volume)
	}
	return out
}

func (w *world) drainPlan(node string) drainPlanView {
	p := drainPlanView{Node: node, Tasks: []drainTask{}}
	var lines []string
	for _, k := range sortedKeys(w.apps) {
		a := w.apps[k]
		for _, t := range a.tasks {
			if t.Node != node {
				continue
			}
			dt := drainTask{Tenant: t.Tenant, App: t.App, Service: t.Service, Instance: t.Instance}
			for _, v := range w.serviceVolumes(a, t.Service) {
				if i := w.volumeRow(t.Tenant, v); i >= 0 && w.volumes[i].Kind == "fixed" && w.volumes[i].Node == node {
					dt.Blocked = NodeFixedVolume
				}
			}
			if dt.Blocked == "" {
				for _, n := range w.tenantNodes[t.Tenant] {
					j := w.memberIndex(n)
					if n != node && j >= 0 && w.members[j].AdmitsWork && !w.members[j].Cordoned && w.summaryStatus(n) != "unreachable" {
						dt.To = n
						break
					}
				}
				if dt.To == "" {
					dt.Blocked = NodeNoTarget
				}
			}
			p.Tasks = append(p.Tasks, dt)
			lines = append(lines, taskKey(t)+">"+dt.To+dt.Blocked)
		}
	}
	rev := uint64(0)
	if i := w.memberIndex(node); i >= 0 {
		rev = w.members[i].Revision
	}
	p.Plan = fakeDigest("node-drain", node, fmt.Sprint(rev), strings.Join(lines, "\n"))
	return p
}

func (c *fakeConn) adminRead(ctx context.Context, m, node string) error {
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return err
	}
	if !c.f.w.admin(user) {
		c.unlock()
		return fail(m, CodeDenied, "")
	}
	if c.f.w.memberIndex(node) < 0 {
		c.unlock()
		return fail(m, CodeMissing, "")
	}
	return nil
}

// SetNodeStatus sets a server's summary Status (ready / degraded /
// unreachable / isolated) for REQ-51 reachability.
func (f *Fake) SetNodeStatus(node, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.w.summaries {
		if f.w.summaries[i].Node == node {
			f.w.summaries[i].Status = status
		}
	}
}
