// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	"io"
	"sync/atomic"
)

func (r *Runtime) runStandaloneAttach(ctx context.Context, cancel context.CancelCauseFunc, intent containerops.SessionIntent, channel *userauth.ContainerChannel, permit func(context.Context) error) error {
	// Connection ownership is runtime-local; signed owner samples persist zero
	// and the last disconnect time in the original workload metadata.
	r.standaloneConnection(intent.Target.Instance, 1)
	defer r.standaloneConnection(intent.Target.Instance, -1)
	attached, err := r.workload.AttachContainer(ctx, intent, permit)
	if err != nil {
		return channel.Send(containerops.SessionRecord{Kind: "error", Code: containerSessionError(err)})
	}
	defer attached.Close()
	done := make(chan struct{})
	var stopping atomic.Bool
	go func() {
		defer close(done)
		for {
			record, err := channel.Receive()
			if err != nil {
				if !stopping.Load() {
					cancel(err)
				}
				return
			}
			switch record.Kind {
			case "stdin":
				for len(record.Data) > 0 {
					n, e := attached.Write(record.Data)
					err = e
					if n == 0 && err == nil {
						err = io.ErrNoProgress
					}
					if err != nil {
						break
					}
					record.Data = record.Data[n:]
				}
			case "stdin-eof":
				err = attached.CloseWrite()
			case "resize":
				err = attached.Resize(ctx, record.Rows, record.Cols)
			case "cancel":
				cancel(context.Canceled)
				return
			}
			if err != nil {
				cancel(err)
				return
			}
		}
	}()
	err = workload.StreamContainerExecOutput(attached, intent.Spec.Exec.TTY, channel.Send)
	stopping.Store(true)
	channel.StopReceive()
	attached.Close()
	<-done
	if err != nil || ctx.Err() != nil {
		return channel.Send(containerops.SessionRecord{Kind: "error", Code: containerSessionError(err)})
	}
	if err = channel.Send(containerops.SessionRecord{Kind: "output-eof"}); err != nil {
		return err
	}
	return channel.Send(containerops.SessionRecord{Kind: "end"})
}
