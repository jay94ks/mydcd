// SPDX-License-Identifier: Apache-2.0

package containerops

import "strings"

// TaskFact is public process metadata from an exact owner inspection. It is
// signed inside the existing deployment Observation; it grants no control,
// replacement, cleanup, native Gone or Volume fence permission.
type TaskFact struct {
	Name            string
	Image           string `json:",omitempty"`
	State           string
	RestartCount    uint64
	LastCheck       *TaskCheck `json:",omitempty"`
	EndpointPresent *bool      `json:",omitempty"`
}

type TaskCheck struct {
	Checker string
	Status  string
	At      uint64
}

func (f TaskFact) Valid(at uint64) bool {
	if len(f.Name) > 256 || strings.ContainsAny(f.Name, "\x00\r\n") || len(f.Image) > 2048 || strings.ContainsAny(f.Image, "\x00\r\n") {
		return false
	}
	switch f.State {
	case "running", "exited", "restarting", "missing", "unknown":
	default:
		return false
	}
	if f.State == "missing" && f.EndpointPresent != nil && *f.EndpointPresent {
		return false
	}
	if f.LastCheck == nil {
		return true
	}
	c := f.LastCheck
	return c.Checker != "" && len(c.Checker) <= 128 && !strings.ContainsAny(c.Checker, "\x00\r\n") &&
		(c.Status == "pass" || c.Status == "fail" || c.Status == "unknown") && c.At > 0 && c.At <= at
}

func (f TaskFact) Clone() TaskFact {
	if f.EndpointPresent != nil {
		present := *f.EndpointPresent
		f.EndpointPresent = &present
	}
	if f.LastCheck != nil {
		c := *f.LastCheck
		f.LastCheck = &c
	}
	return f
}
