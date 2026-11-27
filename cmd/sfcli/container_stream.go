// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

type containerSetupBudgetKey struct{}

func containerSetupBudget(ctx context.Context) time.Duration {
	if d, ok := ctx.Value(containerSetupBudgetKey{}).(time.Duration); ok && d > 0 {
		return min(d, time.Minute)
	}
	return 10 * time.Second
}

func runContainerStream(ctx context.Context, o composeOptions, tenant string, c userauth.Client, peer sfcp.Peer, stored userauth.Stored, home string, out, diagnostic io.Writer) int {
	journalApp := o.project.value
	if o.standalone != nil && (o.method == "exec" || o.method == "exec-status") {
		reply, e := c.StandalonePage(ctx, peer, stored.Session, tenant, o.standalone.Name, "")
		if e != nil {
			return userFailure(diagnostic, e)
		}
		if len(reply.Standalones) != 1 {
			return failure(diagnostic, containerops.ErrTarget, 3)
		}
		journalApp = reply.Standalones[0].Metadata.Scope
	}
	if o.method == "exec-status" || o.method == "exec" {
		old, err := userauth.LoadContainerExec(home, c, stored.Session, tenant, journalApp, o.operation.value)
		if err == nil {
			if o.method == "exec" {
				s := old.Intent.Spec.Exec
				if (o.standalone == nil && old.Intent.Target.Service != o.container.service || o.standalone != nil && (old.Intent.Target.Standalone == "" || old.Intent.Target.App != journalApp)) || o.container.instance.set && old.Intent.Target.Instance != o.container.instance.value || s.Stdin != o.container.interactive.value || s.TTY != o.container.tty.value || !slices.Equal(s.Argv, o.container.argv) {
					return failure(diagnostic, errors.New("exec ID belongs to another original command/target"), 2)
				}
			}
			read, cancel := context.WithTimeout(ctx, containerSetupBudget(ctx))
			defer cancel()
			status, err := c.ContainerExecStatus(read, peer, stored.Session, old.Intent)
			if err != nil {
				return userFailure(diagnostic, err)
			}
			return userOutput(out, diagnostic, status)
		}
		if o.method == "exec-status" || !errors.Is(err, userauth.ErrOperationMissing) {
			return failure(diagnostic, err, 2)
		}
	}
	spec := containerops.SessionSpec{Kind: o.method}
	selection := containerops.Selection{App: o.project.value, Service: o.container.service, Instance: o.container.instance.value}
	if o.standalone != nil {
		selection = containerops.Selection{Standalone: o.standalone.Name, Instance: o.container.instance.value}
	}
	if o.method == "exec" || o.method == "attach" {
		exec := o.container.execSpec()
		if exec.TTY {
			exec.Rows, exec.Cols = containerTerminalSize(os.Stdin)
		}
		spec.Exec = &exec
	} else {
		query := o.container.query
		spec.Query = &query
		if o.container.watch.value {
			var err error
			spec.Interval, err = o.container.watchInterval()
			if err != nil {
				return failure(diagnostic, err, 2)
			}
		}
	}
	if spec.Validate() != nil {
		return failure(diagnostic, containerops.ErrSession, 2)
	}
	setup, finish := context.WithTimeout(ctx, containerSetupBudget(ctx))
	target, err := c.ResolveContainerSession(setup, peer, stored.Session, tenant, selection, spec)
	finish()
	if err != nil {
		return userFailure(diagnostic, err)
	}
	id := o.operation.value
	if spec.Kind != "exec" && spec.Kind != "attach" {
		var nonce [12]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return failure(diagnostic, err, 1)
		}
		id = "observe-" + hex.EncodeToString(nonce[:])
	}
	intent := containerops.SessionIntent{Schema: 1, Request: id, User: stored.Session.User, Session: access.ExactSessionDigest(stored.Session), At: time.Now().Unix(), Target: target, Spec: spec}
	intent.Signature = ed25519.Sign(c.Self.Private, containerops.SessionIntentBytes(intent))
	if intent.Verify(stored.Session.Key) != nil {
		return failure(diagnostic, containerops.ErrSession, 2)
	}
	if spec.Kind == "exec" {
		if _, err = userauth.StageContainerExec(home, c, stored.Session, intent); err != nil {
			return failure(diagnostic, err, 2)
		}
		fmt.Fprintf(diagnostic, "exec operation=%s app=%s service=%s node=%s; after disconnection run the same exec with --id %s to see its result\n", id, target.App, target.Service, target.Node, id)
	}
	restore := func() {}
	if spec.Exec != nil && spec.Exec.TTY && spec.Exec.Stdin {
		restore, err = makeContainerTerminalRaw(os.Stdin)
		if err != nil {
			return failure(diagnostic, err, 2)
		}
	}
	defer restore()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	channel, err := c.OpenContainerSession(ctx, peer, stored.Session, intent, containerSetupBudget(ctx))
	if err != nil {
		return userFailure(diagnostic, err)
	}
	var inputDone, windowDone <-chan error
	if spec.Exec != nil && spec.Exec.Stdin {
		inputDone = containerInput(ctx, os.Stdin, channel)
	}
	if spec.Exec != nil && spec.Exec.TTY {
		windowDone = containerWindow(ctx, os.Stdin, channel)
	}
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if channel.Send(containerops.SessionRecord{Kind: "ping"}) != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		cancel()
		_ = channel.Close()
		if inputDone != nil {
			<-inputDone
		}
		if windowDone != nil {
			<-windowDone
		}
		<-pingDone
	}()
	output := containerOutput{ctx: ctx, writer: out}
	errorsOut := containerOutput{ctx: ctx, writer: diagnostic}
	var receipt *containerops.ExecReceipt
	for {
		record, err := channel.Receive()
		if err != nil {
			return failure(diagnostic, errors.New("container session disconnected; original exec is preserved for exec-status"), 4)
		}
		switch record.Kind {
		case "stdout":
			if o.container.json {
				err = writeContainerJSON(output, record)
			} else {
				_, err = output.Write(record.Data)
			}
		case "stderr":
			if o.container.json {
				err = writeContainerJSON(output, record)
			} else {
				_, err = errorsOut.Write(record.Data)
			}
		case "sample":
			if o.container.json {
				err = writeContainerJSON(output, *record.Sample)
			} else if o.method != "logs" {
				err = writeContainerObservation(output, errorsOut, *record.Sample)
			}
		case "receipt":
			receipt = record.Receipt
		case "error":
			return failure(diagnostic, errors.New("container session: "+record.Code+"; native process termination is not implied"), 4)
		case "end":
			if spec.Kind == "exec" {
				if receipt == nil || receipt.Phase != containerops.ExecFinished || receipt.ExitCode == nil {
					return failure(diagnostic, errors.New("container I/O ended; original process is running or its exit is unknown; use exec-status"), 4)
				}
				return *receipt.ExitCode
			}
			return 0
		}
		if err != nil {
			return failure(diagnostic, err, 1)
		}
	}
}

func containerStreamContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return context.WithValue(ctx, containerSetupBudgetKey{}, timeout), cancel
}

func writeContainerJSON(w io.Writer, value any) error { return json.NewEncoder(w).Encode(value) }
