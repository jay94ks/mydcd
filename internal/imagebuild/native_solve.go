// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
)

// NativeSolve is the original SDK dispatch/result, separate from the finite
// daemon's process exit. Sent without Returned never permits a second Solve.
type NativeSolve struct {
	Sent, Returned, Stopping bool
	Code                     string
	Directory                NativeDirectory
	TLS                      bool      `json:",omitempty"`
	Trust                    *[32]byte `json:",omitempty"`
	SourceContent            bool      `json:",omitempty"`
}

func (s NativeSolve) valid(r NativeRecord) bool {
	if s.Sent && (!r.StartSent || !r.ControlsDone || r.NativeID == "" || !s.Directory.valid()) || s.Returned && !s.Sent || (s.Code != "") != s.Returned || s.Directory != (NativeDirectory{}) && !s.Directory.valid() {
		return false
	}
	if s.Trust != nil && (!s.TLS || *s.Trust == ([32]byte{})) || s.TLS && r.ControlsSent && s.Trust == nil || s.SourceContent && !s.TLS {
		return false
	}
	switch s.Code {
	case "", "OK", "BUILD_FAILED", "SOURCE_FETCH", "STORAGE_UNAVAILABLE", "TIMEOUT", "CANCELLED":
		return true
	}
	return false
}

func nativeOutputSucceeded(r NativeRecord) bool {
	if !r.Exited || !r.Waited || !r.Removed {
		return false
	}
	if r.Solve != nil {
		return r.Solve.Returned && r.Solve.Code == "OK"
	}
	return r.ExitCode == 0
}

func (n *NativeJobs) UseSDK(ctx context.Context, spec JobSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	if r.Solve != nil {
		return nil
	}
	if _, err := n.current(ctx, &r, false); err != nil {
		return err
	}
	if r.CreateSent || r.Cancel || r.Completion != nil {
		return ErrConflict
	}
	r.Solve = &NativeSolve{TLS: true, SourceContent: true}
	return n.save(r)
}

// StopSDK is owner cleanup, not a user cancel and not an SDK success. It does
// not require quorum and does not authorize publication or release references.
func (n *NativeJobs) StopSDK(ctx context.Context, spec JobSpec) error {
	n.mu.Lock()
	r, err := n.load(spec)
	if err == nil {
		if r.Solve == nil || n.solving[spec.Digest()] {
			err = ErrUsed
		} else {
			r.Solve.Stopping = true
			err = n.save(r)
		}
	}
	n.mu.Unlock()
	if err != nil {
		return err
	}
	return n.ObserveExit(ctx, spec, false)
}
