// SPDX-License-Identifier: Apache-2.0

// Package lifecycle is the schema-1 checker SDK shared by interpreted and
// compiled scripts. It carries no cluster credentials or host-native handles.
package lifecycle

import "context"

const Schema uint8 = 1

type Phase string

const (
	Startup   Phase = "startup"
	Readiness Phase = "readiness"
	Liveness  Phase = "liveness"
	Shutdown  Phase = "shutdown"
)

type Status string

const (
	Pass    Status = "pass"
	Fail    Status = "fail"
	Unknown Status = "unknown"
)

type Target struct {
	Service, TaskKey, NativeID, Owner, OwnerBoot string
	Generation, Revision                         uint64
	StartedAt                                    string `json:",omitempty"` // Docker instance stamp; not a process/exit proof
}

type Request struct {
	Schema                                             uint8
	RunID, Cluster, Tenant, App, Checker, SourceDigest string
	Phase                                              Phase
	Targets                                            []Target
	Parameters                                         map[string]string
	DeadlineUnixMilli                                  int64
}

type Result struct {
	Schema uint8
	Status Status
	Reason string
}

type HTTPProbe struct {
	Service, Path, Method string
	Port                  uint16
	TLS                   bool
	ExpectedStatus        []int
	MaxBytes              int
}
type HTTPResult struct {
	StatusCode int
	Match      bool
}

// TCPProbe customizes a single bounded connection check. Service identifies
// an accepted container target; callers cannot supply a host or node address.
// ReadBytes is the exact response-prefix length, or zero for connect/send only.
type TCPProbe struct {
	Service   string
	Port      uint16
	Request   []byte
	ReadBytes int
}

type TCPResult struct {
	Connected bool
	Data      []byte // private probe data, never a public lifecycle Result/log
}
type ExecProbe struct {
	Service  string
	Argv     []string
	MaxBytes int
}
type ExecResult struct {
	Exited   bool
	ExitCode int
	// Private bounded probe input, never included in a public Result/log.
	Stdout    []byte
	Truncated bool
}
type FileProbe struct {
	Service, Path, Kind string
	ContentDigest       string `json:",omitempty"`
	MaxBytes            int    `json:",omitempty"`
}
type FileResult struct {
	Exists, Match bool
	Kind          string
	Mode          uint32
}
type DependencyProbe struct{ Service, Condition string }
type DependencyResult struct {
	Status               Status
	Generation, Revision uint64
}

type Probe interface {
	Healthz(context.Context, HTTPProbe) (HTTPResult, error)
	Connect(context.Context, TCPProbe) (TCPResult, error)
	Exec(context.Context, ExecProbe) (ExecResult, error)
	File(context.Context, FileProbe) (FileResult, error)
	Dependency(context.Context, DependencyProbe) (DependencyResult, error)
}

type Checker func(context.Context, Request, Probe) (Result, error)
