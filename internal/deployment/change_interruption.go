// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"strings"
)

// Interruption codes say, for the deploy preview only, why replacing a Task
// stops its service for a while (devel/design/zero-downtime-apply.md). A
// replaced Task without one keeps serving through other replicas.
const (
	InterruptSingleInstance = "SINGLE_INSTANCE" // no replica on another server serves meanwhile
	InterruptVolumeWriter   = "VOLUME_WRITER"   // a writable Volume: two writers are never allowed
	InterruptHostPort       = "HOST_PORT"       // `ports` opens the server's own port
	InterruptStaticAddress  = "STATIC_ADDRESS"  // a fixed ipv4_address/ipv6_address
	InterruptVolumeMove     = "VOLUME_MOVE"     // the Volume moves to another server
)

// InterruptionCodes lists every Change.Interruption.
var InterruptionCodes = []string{InterruptSingleInstance, InterruptVolumeWriter, InterruptHostPort, InterruptStaticAddress, InterruptVolumeMove}

// annotateInterruptions marks each replaced Task whose service stops while
// it is replaced. The cause that can never be lifted is named first:
// a writable Volume, then a server port, then a fixed address, and last a
// service with no replica elsewhere (which a same-server surge will lift).
// A fixed address is one the app declares (input); a planned Task always
// carries the address it was given.
func annotateInterruptions(steps []Step, input Compose, out []Change) {
	byKey := map[string]Step{}
	nodes := map[string]map[string]bool{} // service -> servers its Tasks run on
	for _, s := range steps {
		byKey[s.Key] = s
		if service, ok := taskService(s, input); ok {
			if nodes[service.name] == nil {
				nodes[service.name] = map[string]bool{}
			}
			nodes[service.name][s.Node] = true
		}
	}
	for i := range out {
		switch out[i].Action {
		case "MoveRequired":
			if byKey[out[i].Key].Kind == "volume" {
				out[i].Interruption = InterruptVolumeMove
			}
			continue
		case "Replace":
		default:
			continue
		}
		step, ok := byKey[out[i].Key]
		service, isTask := taskService(step, input)
		if !ok || !isTask {
			continue
		}
		switch {
		case service.writer:
			out[i].Interruption = InterruptVolumeWriter
		case service.hostPort:
			out[i].Interruption = InterruptHostPort
		case service.static:
			out[i].Interruption = InterruptStaticAddress
		case len(nodes[service.name]) < 2:
			out[i].Interruption = InterruptSingleInstance
		}
	}
}

type taskShape struct {
	name                     string
	writer, hostPort, static bool
}

func taskService(s Step, input Compose) (taskShape, bool) {
	if s.Kind != "task" {
		return taskShape{}, false
	}
	var service ComposeService
	if json.Unmarshal(s.Goal, &service) != nil {
		return taskShape{}, false
	}
	shape := taskShape{name: s.Key}
	if service.Sfc.Instance != nil {
		shape.name = service.Sfc.Instance.Service
	}
	declared, known := input.Services[taskServiceName(s.Key, service)]
	for _, m := range service.Volumes {
		if m.Type == "volume" && !m.ReadOnly {
			shape.writer = true
		}
	}
	for _, p := range service.Ports {
		if p.Published != "" {
			shape.hostPort = true
		}
	}
	for _, a := range declared.Networks {
		if known && (a.IPv4 != "" || a.IPv6 != "") {
			shape.static = true
		}
	}
	return shape, true
}

// taskServiceName is the app.yaml service a Task key comes from: a replica
// names it, otherwise it is the first segment of the resource id
// (workload/task/<tenant>/<app>/<id>).
func taskServiceName(key string, service ComposeService) string {
	if service.Sfc.Instance != nil {
		return service.Sfc.Instance.Service
	}
	parts := strings.SplitN(key, "/", 5)
	if len(parts) < 5 {
		return ""
	}
	name, _, _ := strings.Cut(parts[4], "/")
	return name
}
