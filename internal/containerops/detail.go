// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"encoding/json"
	"time"
)

// Image-inherited argv may legitimately exceed one app frame even when the
// original accepted app artifact fits its own 4MiB budget.
const MaxDetailWindowBytes = 16 << 20

// DetailDeclaration contains only the accepted app's public fields. Runtime
// values are never expanded into it, including image-default environment.
type DetailDeclaration struct {
	Environment    map[string]string
	NetworkAliases map[string][]string
	Ingress        []DetailIngress
}

type DetailIngress struct {
	Host, Node  string
	Listeners   []string
	BackendPort uint16
	State       string // declared association, not proof of a remote gateway's health
}

type DetailEnvironment struct {
	Name, Source    string  // literal, image, secret, or native-only
	Value           *string `json:",omitempty"`
	SecretReference string  `json:",omitempty"`
	Drift, Present  bool
}

type DetailMount struct {
	Kind, Name, Target string
	ReadOnly           bool
	UID, GID, Mode     *uint32 `json:",omitempty"`
}

type DetailNetwork struct {
	Name, NativeID, IPv4, IPv6 string
	Aliases                    []string
}

type DetailPort struct {
	Port                       uint16
	Protocol, HostIP, HostPort string
}

type DetailCheck struct {
	Generation, Revision   uint64
	Checker, Phase, Status string
	At                     time.Time
	DurationMS             int64
	Message                string
	ConsecutiveFailures    *uint32 `json:",omitempty"`
	RunID, NativeID        string  `json:",omitempty"`
}

type DetailHistory struct {
	ID, Kind, Reason, NativeID string
	At                         time.Time
	ExitCode                   *int `json:",omitempty"`
	Generation, Revision       uint64
}

// ContainerDetail is an allowlisted snapshot, never a native InspectResponse.
// Host bind sources, env values, logger credentials and raw health output are
// excluded. A separately authorized update is required to change anything.
type ContainerDetail struct {
	NetworksOmitted                                         int
	ChecksTruncated                                         bool
	Name, ImageReference, NativeImage, ImageID              string
	Command, Entrypoint                                     []string
	WorkingDir, User                                        string
	ReadOnlyRootFS, Privileged                              bool
	CapabilitiesAdded, CapabilitiesDropped, SecurityOptions []string
	MemoryBytes, NanoCPUs                                   int64
	StopSignal                                              string
	StopGraceSeconds                                        int
	LogDriver                                               string
	LogOptions                                              map[string]string
	Environment                                             []DetailEnvironment
	Mounts                                                  []DetailMount
	Networks                                                []DetailNetwork
	DeclaredNetworkAliases                                  map[string][]string
	DNS, DNSSearch                                          []string
	Ports                                                   []DetailPort
	DeclaredIngress                                         []DetailIngress
	Running, Paused, Restarting, OOMKilled                  bool
	ExitCode                                                int
	StartedAt, FinishedAt                                   string
	Drift                                                   []string
	Checks                                                  []DetailCheck
	History                                                 []DetailHistory
	HistoryIncomplete                                       bool `json:",omitempty"`
}

func (d ContainerDetail) Valid(maxBytes int) bool {
	if len(d.Environment) > 384 || len(d.Command) > 128 || len(d.Entrypoint) > 128 || len(d.Mounts) > 384 || len(d.Networks) > 16 || len(d.Ports) > 256 || len(d.Drift) > 64 || len(d.Checks) > 100 || len(d.History) > 100 {
		return false
	}
	for _, env := range d.Environment {
		if env.Name == "" || env.Source != "literal" && env.Source != "image" && env.Source != "secret" && env.Source != "native-only" || env.Value != nil && env.Source != "literal" || env.Source == "secret" && (env.SecretReference == "" || env.Value != nil) || env.Source != "secret" && env.SecretReference != "" {
			return false
		}
	}
	raw, err := json.Marshal(d)
	return err == nil && len(raw) <= maxBytes
}
