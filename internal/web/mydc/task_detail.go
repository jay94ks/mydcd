// SPDX-License-Identifier: Apache-2.0

package mydc

// REQ-20 (mock) what container-observe does not give yet: the applied run
// settings with drift, exit/restart history, health check records, logs
// paged by cursor with secret values masked, kept stats samples, and a
// restart of one task. Names follow REQUEST.md REQ-20 and may change.

const ActionRestartTask = "restart-task"

// TaskDetail: `task-detail` (tenant Read), the server's snapshot. No secret
// value appears: an environment key fed by the vault shows Secret only.
type TaskDetail struct {
	Selection   ContainerSelection
	Node        string
	Name        string // Docker name
	NativeID    string
	Image       string
	Digest      string
	Command     []string `json:",omitempty"`
	Entrypoint  []string `json:",omitempty"`
	WorkingDir  string   `json:",omitempty"`
	User        string   `json:",omitempty"`
	ReadOnly    bool     // read-only root
	CapAdd      []string `json:",omitempty"`
	Privileged  bool
	CPUs        float64 `json:",omitempty"`
	MemoryBytes uint64  `json:",omitempty"`
	LogDriver   string
	LogOptions  map[string]string `json:",omitempty"` // no backend credentials
	Env         []TaskEnv
	Mounts      []TaskMount
	Networks    []TaskNetwork
	Ports       []TaskPort `json:",omitempty"`
	StopSignal  string
	StopGrace   int // seconds
	Generation  uint64
	// Drift: app.yaml fields whose applied value differs from the target
	// (paths like "services.web.image").
	Drift      []string `json:",omitempty"`
	ObservedAt int64
}

// TaskEnv: Value only for a plain app.yaml value; Secret = "secret:<object>/<key>".
type TaskEnv struct {
	Key    string
	Value  string `json:",omitempty"`
	Secret string `json:",omitempty"`
}

// TaskMount kinds: volume / secret (a file) / tmpfs.
type TaskMount struct {
	Kind     string
	Source   string `json:",omitempty"` // volume name or secret:<object>/<key>
	Target   string
	ReadOnly bool
	Mode     string `json:",omitempty"` // secret files
}

type TaskNetwork struct {
	Name    string
	IP      string
	Aliases []string `json:",omitempty"`
	DNS     []string `json:",omitempty"`
}

type TaskPort struct {
	Port     int
	Protocol string
	Ingress  string `json:",omitempty"` // host served by the ingress, if any
	// Published: the actual host bindings of this container port (service
	// `ports`), grouped by Port and Protocol. The real adapter fills it from
	// container-detail Detail.Ports (containerops.DetailPort{Port, Protocol,
	// HostIP, HostPort}).
	Published []TaskPortBinding `json:",omitempty"`
}

// TaskPortBinding is one host binding; HostIP "" = Docker's default address.
// HostPort is a string as in containerops.DetailPort.
type TaskPortBinding struct {
	HostIP   string `json:"hostIp,omitempty"`
	HostPort string
}

// Exit reasons (REQ-10 event kinds).
const (
	ExitReasonExit        = "exit"
	ExitReasonOOM         = "oom"
	ExitReasonHealth      = "health"
	ExitReasonNodeRestart = "node-restart"
	ExitReasonUser        = "user"
	ExitReasonLogClear    = "log-clear"
)

type TaskExit struct {
	At         int64
	Reason     string
	ExitCode   int
	Generation uint64
	NativeID   string
}

type TaskCheckResult struct {
	At         int64
	OK         bool
	DurationMs int
	Message    string `json:",omitempty"`
}

type TaskCheckHistory struct {
	Checker             string
	ConsecutiveFailures int
	Results             []TaskCheckResult // newest first
}

// TaskHistory: `task-history` (tenant Read), newest first; Limit 0 = 20.
type TaskHistory struct {
	Selection ContainerSelection
	Exits     []TaskExit
	Checks    []TaskCheckHistory
}

// TaskLogQuery: `task-logs`. Lines before Cursor ("" = the newest), at most
// Limit lines and 24 KiB; the reply's Cursor continues further back ("" =
// nothing older).
type TaskLogQuery struct {
	Selection ContainerSelection
	Cursor    string `json:",omitempty"`
	Limit     int
}

type TaskLogPage struct {
	Lines  []TaskLogLine // oldest first
	Cursor string        `json:",omitempty"`
	// Masked: how many lines had a supplied secret value replaced by
	// «가림: object/key».
	Masked int
}

type TaskLogLine struct {
	Seq uint64 // unique per task, increasing
	LogLine
}

// TaskStatsSample: one kept stats sample (30 s apart, the last hour).
type TaskStatsSample struct {
	At int64
	ContainerStats
}
