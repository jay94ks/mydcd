// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"errors"
	"time"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Even formatting a native context/probe must not expose a daemon adapter's
// fields or context values. Only method closures cross into checker code.
type checkerContext struct {
	deadline func() (time.Time, bool)
	done     func() <-chan struct{}
	err      func() error
}

func (c checkerContext) Deadline() (time.Time, bool) { return c.deadline() }
func (c checkerContext) Done() <-chan struct{}       { return c.done() }
func (c checkerContext) Err() error                  { return c.err() }
func (c checkerContext) Value(any) any               { return nil }

type opaqueCheckerProbe struct {
	healthz    func(context.Context, contract.HTTPProbe) (contract.HTTPResult, error)
	connect    func(context.Context, contract.TCPProbe) (contract.TCPResult, error)
	exec       func(context.Context, contract.ExecProbe) (contract.ExecResult, error)
	file       func(context.Context, contract.FileProbe) (contract.FileResult, error)
	dependency func(context.Context, contract.DependencyProbe) (contract.DependencyResult, error)
}

func privateProbeError(err error) error {
	if err != nil {
		return errors.New("checker probe failed")
	}
	return nil
}
func (p opaqueCheckerProbe) Healthz(ctx context.Context, in contract.HTTPProbe) (contract.HTTPResult, error) {
	r, err := p.healthz(ctx, in)
	return r, privateProbeError(err)
}
func (p opaqueCheckerProbe) Connect(ctx context.Context, in contract.TCPProbe) (contract.TCPResult, error) {
	if p.connect == nil {
		return contract.TCPResult{}, privateProbeError(ErrContract)
	}
	r, err := p.connect(ctx, in)
	return r, privateProbeError(err)
}
func (p opaqueCheckerProbe) Exec(ctx context.Context, in contract.ExecProbe) (contract.ExecResult, error) {
	r, err := p.exec(ctx, in)
	return r, privateProbeError(err)
}
func (p opaqueCheckerProbe) File(ctx context.Context, in contract.FileProbe) (contract.FileResult, error) {
	r, err := p.file(ctx, in)
	return r, privateProbeError(err)
}
func (p opaqueCheckerProbe) Dependency(ctx context.Context, in contract.DependencyProbe) (contract.DependencyResult, error) {
	r, err := p.dependency(ctx, in)
	return r, privateProbeError(err)
}
