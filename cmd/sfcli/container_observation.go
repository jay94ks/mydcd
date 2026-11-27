// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

type containerCLIOptions struct {
	service                                                string
	instance, tail, since, until, maximum, cursor, history onceString
	timestamps, stdout, stderr, json                       bool
	query                                                  containerops.Query
	follow, watch, interactive, tty                        checkerRetryFlag
	interval                                               onceString
	argv                                                   []string
}

func containerReadMethod(method string) bool {
	return method == "logs" || method == "top" || method == "stats" || method == "inspect"
}
func addContainerReadFlags(f *flag.FlagSet) *containerCLIOptions {
	o := new(containerCLIOptions)
	f.Var(&o.instance, "instance", "exact logical Task instance (not Docker ID)")
	f.Var(&o.tail, "tail", "recent log lines (default 200, maximum 10000)")
	f.Var(&o.since, "since", "RFC3339 log start timestamp")
	f.Var(&o.until, "until", "RFC3339 log end timestamp")
	f.Var(&o.cursor, "cursor", "continue an original redacted log window")
	f.Var(&o.history, "history", "inspect recent lifecycle history count (default 20, maximum 100)")
	f.Var(&o.maximum, "max-bytes", "maximum output payload (default 16384, maximum 24576)")
	f.BoolVar(&o.timestamps, "timestamps", false, "include log timestamps")
	f.BoolVar(&o.stdout, "stdout", false, "select stdout (default both streams)")
	f.BoolVar(&o.stderr, "stderr", false, "select stderr (default both streams)")
	f.BoolVar(&o.json, "json", false, "structured observation including target and truncation")
	f.Var(&o.follow, "follow", "follow this exact container's new logs")
	f.Var(&o.watch, "watch", "watch this exact container's top/stats")
	f.Var(&o.interval, "interval", "watch sample interval (default 2s, 1s..1m)")
	f.Var(&o.interactive, "i", "attach stdin to exec")
	f.Var(&o.interactive, "interactive", "attach stdin to exec")
	f.Var(&o.tty, "t", "allocate an exec TTY")
	f.Var(&o.tty, "tty", "allocate an exec TTY")
	return o
}
func (o *containerCLIOptions) finish(method, project string) error {
	q := containerops.Query{Schema: 1, Selection: containerops.Selection{App: project, Service: o.service, Instance: o.instance.value}, Kind: method, MaxBytes: 16 << 10}
	if method == "inspect" {
		q.MaxBytes = containerops.MaxOutput
		if o.history.set {
			n, err := strconv.Atoi(o.history.value)
			if err != nil || n < 1 || n > 100 {
				return containerops.ErrQuery
			}
			q.HistoryLimit = n
		}
	} else if o.history.set {
		return containerops.ErrQuery
	}
	if o.maximum.set {
		n, e := strconv.Atoi(o.maximum.value)
		if e != nil {
			return containerops.ErrQuery
		}
		q.MaxBytes = n
	}
	if method == "logs" {
		q.Tail = 200
		if o.tail.set {
			n, e := strconv.Atoi(o.tail.value)
			if e != nil {
				return containerops.ErrQuery
			}
			q.Tail = n
		}
		q.Since, q.Until, q.Timestamps = o.since.value, o.until.value, o.timestamps
		q.Cursor = o.cursor.value
		q.Stdout, q.Stderr = o.stdout, o.stderr
		if !q.Stdout && !q.Stderr {
			q.Stdout, q.Stderr = true, true
		}
	} else if o.tail.set || o.since.set || o.until.set || o.cursor.set || o.timestamps || o.stdout || o.stderr {
		return errors.New("log options require compose logs")
	}
	if err := q.Validate(); err != nil {
		return err
	}
	if o.follow.set && method != "logs" || o.watch.set && method != "top" && method != "stats" || o.interval.set && !o.watch.value || o.follow.value && (o.until.set || o.cursor.set) || o.interactive.set || o.tty.set {
		return errors.New("invalid container stream options")
	}
	if o.watch.value {
		if _, err := o.watchInterval(); err != nil {
			return err
		}
	}
	o.query = q
	return nil
}
func containerReadFlag(name string) bool {
	switch name {
	case "instance", "tail", "since", "until", "cursor", "history", "max-bytes", "timestamps", "stdout", "stderr", "json", "follow", "watch", "interval", "i", "interactive", "t", "tty":
		return true
	}
	return false
}

func (o *containerCLIOptions) watchInterval() (time.Duration, error) {
	d := 2 * time.Second
	if o.interval.set {
		var err error
		d, err = time.ParseDuration(o.interval.value)
		if err != nil {
			return 0, err
		}
	}
	if d < time.Second || d > time.Minute {
		return 0, containerops.ErrSession
	}
	return d, nil
}
func runContainerRead(ctx context.Context, o composeOptions, tenant string, c userauth.Client, peer sfcp.Peer, stored userauth.Stored, out, diagnostic io.Writer) int {
	var reply userauth.Reply
	var err error
	if o.method == "inspect" {
		reply, err = c.InspectContainer(ctx, peer, stored.Session, tenant, o.container.query)
	} else {
		reply, err = c.ObserveContainer(ctx, peer, stored.Session, tenant, o.container.query)
	}
	if err != nil {
		return userFailure(diagnostic, err)
	}
	result := *reply.Container
	if o.container.json || o.method == "inspect" {
		return userOutput(out, diagnostic, result)
	}
	if err = writeContainerObservation(out, diagnostic, result); err != nil {
		return failure(diagnostic, err, 1)
	}
	return 0
}
func writeContainerObservation(out, diagnostic io.Writer, result containerops.Result) error {
	var err error
	if result.Truncated {
		fmt.Fprintln(diagnostic, "container output truncated at the requested limit")
		if result.NextCursor != "" {
			fmt.Fprintln(diagnostic, "continue with the same log options and --cursor", result.NextCursor)
		}
	}
	switch result.Kind {
	case "logs":
		if _, err = out.Write(result.Stdout); err == nil {
			_, err = diagnostic.Write(result.Stderr)
		}
	case "top":
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, err = fmt.Fprintln(w, strings.Join(result.Titles, "\t"))
		for _, row := range result.Processes {
			if err != nil {
				break
			}
			_, err = fmt.Fprintln(w, strings.Join(row, "\t"))
		}
		err = errors.Join(err, w.Flush())
	case "stats":
		s := result.Stats
		cpu := "N/A (" + s.CPUStatus + ")"
		if s.CPUPercent != nil {
			cpu = fmt.Sprintf("%.2f%%", *s.CPUPercent)
		}
		_, err = fmt.Fprintf(out, "SERVICE\tCPU\tMEMORY BYTES / LIMIT\tWORKING SET BYTES\tNET RX / TX BYTES\tBLOCK READ / WRITE BYTES\tPIDS\n%s\t%s\t%s / %s\t%s\t%s / %s\t%s / %s\t%s\n", result.Target.Service, cpu, observationNumber(s.MemoryBytes), observationNumber(s.MemoryLimitBytes), observationNumber(s.MemoryWorkingSetBytes), observationNumber(s.NetworkRXBytes), observationNumber(s.NetworkTXBytes), observationNumber(s.BlockReadBytes), observationNumber(s.BlockWriteBytes), observationNumber(s.PIDs))
	}
	if err != nil {
		return err
	}
	return nil
}
func observationNumber(v *uint64) string {
	if v == nil {
		return "N/A"
	}
	return strconv.FormatUint(*v, 10)
}
