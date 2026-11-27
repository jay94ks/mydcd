// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Service `ports` host publishing (docs/architecture/app-and-cluster-spec.md
// '서비스의 호스트 포트 직접 공개'), for apps and standalone containers alike.
// The fake models only sfcd's plan check: a fixed published port on the
// same server as another accepted task's fixed port, with the same protocol
// and an overlapping address (an empty or wildcard host_ip overlaps every
// address), is HOST_PORT_CONFLICT. Dynamic ports (no published, 0, or a
// range) are left to Docker and never conflict here.

const InputHostPortConflict = "HOST_PORT_CONFLICT"

type hostPort struct {
	IP, Proto string
	Port      int
}

func (p hostPort) String() string {
	if p.IP == "" {
		return fmt.Sprintf("%d/%s", p.Port, p.Proto)
	}
	return fmt.Sprintf("%s:%d/%s", p.IP, p.Port, p.Proto)
}

func (p hostPort) overlaps(q hostPort) bool {
	wild := func(ip string) bool { return ip == "" || ip == "0.0.0.0" || ip == "::" }
	return p.Port == q.Port && p.Proto == q.Proto && (p.IP == q.IP || wild(p.IP) || wild(q.IP))
}

// composePort is one entry of a compose `ports` list (short
// "[ip:][published:]target[/proto]" or long {target, published, host_ip,
// protocol}). Published is "" when omitted.
type composePort struct {
	Target               int
	Proto, IP, Published string
}

func parseComposePort(x any) (composePort, bool) {
	var p composePort
	switch v := x.(type) {
	case map[string]any:
		p.Target, _ = strconv.Atoi(fmt.Sprint(v["target"]))
		if v["published"] != nil {
			p.Published = fmt.Sprint(v["published"])
		}
		p.IP, _ = v["host_ip"].(string)
		p.Proto, _ = v["protocol"].(string)
	default:
		s := fmt.Sprint(v)
		if i := strings.LastIndex(s, "/"); i >= 0 {
			s, p.Proto = s[:i], s[i+1:]
		}
		if strings.HasPrefix(s, "[") { // IPv6 host_ip: "[::1]:published:target"
			end := strings.Index(s, "]:")
			if end < 0 {
				return p, false
			}
			p.IP, s = s[1:end], s[end+2:]
			published, target, ok := strings.Cut(s, ":")
			if !ok {
				return p, false
			}
			p.Published = published
			p.Target, _ = strconv.Atoi(target)
			break
		}
		parts := strings.Split(s, ":")
		switch len(parts) {
		case 2:
			p.Published = parts[0]
		case 3:
			p.IP, p.Published = strings.Trim(parts[0], "[]"), parts[1]
		}
		p.Target, _ = strconv.Atoi(parts[len(parts)-1])
	}
	if p.Proto == "" {
		p.Proto = "tcp"
	}
	return p, p.Target > 0 && p.Target <= 65535
}

// fixed: the published host port when it is one number (not omitted, 0 or
// a range, which Docker chooses).
func (p composePort) fixed() (int, bool) {
	n, err := strconv.Atoi(p.Published)
	return n, err == nil && n > 0 && n <= 65535
}

// parseHostPorts reads the fixed published ports of a compose `ports` list.
func parseHostPorts(raw []any) []hostPort {
	var out []hostPort
	for _, x := range raw {
		p, ok := parseComposePort(x)
		if !ok {
			continue
		}
		if n, ok := p.fixed(); ok {
			out = append(out, hostPort{IP: p.IP, Proto: p.Proto, Port: n})
		}
	}
	return out
}

// hostPortCheck: ports on node against every other owner's fixed ports
// there. owner is "app:tenant/app" or "standalone:tenant/name".
func (w *world) hostPortCheck(node, owner, service string, ports []hostPort) *inputError {
	for _, p := range ports {
		if other, ok := w.hostPortHolder(node, owner, p); ok {
			return &inputError{code: InputHostPortConflict, detail: fmt.Sprintf("%s %s on %s is used by %s", service, p, node, other)}
		}
	}
	return nil
}

func (w *world) hostPortHolder(node, owner string, p hostPort) (string, bool) {
	for k, a := range w.apps {
		if "app:"+k == owner || a.view.Retiring {
			continue
		}
		src, ok := a.running()
		if !ok {
			continue
		}
		d, err := parseApp(src.Document)
		if err != nil {
			continue
		}
		for svc, s := range d.Services {
			for _, t := range a.tasks {
				if t.Service != svc || t.Node != node {
					continue
				}
				for _, q := range parseHostPorts(s.Ports) {
					if q.overlaps(p) {
						return k + "/" + svc, true
					}
				}
			}
		}
	}
	for k, e := range w.standalones {
		if "standalone:"+k == owner || e.removed() || e.view.Node != node {
			continue
		}
		var d standaloneDef
		if yaml.Unmarshal(e.view.Document, &d) != nil {
			continue
		}
		for _, q := range parseHostPorts(d.Ports) {
			if q.overlaps(p) {
				return k, true
			}
		}
	}
	return "", false
}

// appHostPortCheck: a planned app against other owners, and its own
// services and replicas on one server against each other.
func (w *world) appHostPortCheck(tenant string, d appDoc) error {
	owner := "app:" + tenant + "/" + d.Name
	mine := map[string][]hostPort{} // node → ports already planned in this app
	for _, svc := range sortedKeys(d.Services) {
		s := d.Services[svc]
		ports := parseHostPorts(s.Ports)
		for _, n := range s.XSfc.Nodes {
			if err := w.hostPortCheck(n, owner, svc, ports); err != nil {
				return err
			}
			for _, p := range ports {
				for _, q := range mine[n] {
					if q.overlaps(p) {
						return &inputError{code: InputHostPortConflict, detail: fmt.Sprintf("%s %s on %s is used twice in the app", svc, p, n)}
					}
				}
			}
			mine[n] = append(mine[n], ports...)
		}
	}
	return nil
}
