// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/config"
)

// runUpgradeDryRun is `sfcd --config NODE.yaml upgrade-dry-run`: run the
// new binary before installing it to see whether it would start on this
// server's stored control state. It works on a copy and changes nothing on
// the server, which may keep running (devel/design/upgrades.md 4).
func runUpgradeDryRun(args []string, file string, out, diagnostic io.Writer) int {
	f := flag.NewFlagSet("upgrade-dry-run", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	scratch := f.String("scratch", "", "directory for the temporary copy (default: the system temporary directory); needs room for control/raft.db and control/fsm.db")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return fail(diagnostic, err, 2)
	}
	if f.NArg() != 0 {
		return fail(diagnostic, errors.New("usage: sfcd --config NODE.yaml upgrade-dry-run [--scratch DIR]"), 2)
	}
	if file == "" {
		return fail(diagnostic, errors.New("--config is required"), 2)
	}
	c, err := config.LoadNode(file)
	if err != nil {
		return fail(diagnostic, err, 2)
	}
	dir, err := os.MkdirTemp(*scratch, "sfcd-upgrade-dry-run-")
	if err != nil {
		return fail(diagnostic, err, 1)
	}
	defer os.RemoveAll(dir)
	r, err := app.DryRun(c, dir)
	if err != nil {
		fmt.Fprintf(diagnostic, "%s would not start on %s's stored state: %v\n", buildinfo.Line("sfcd"), c.Node.ID, err)
		fmt.Fprintln(diagnostic, "The copy was taken while sfcd ran; a write during the copy can also fail it. To be sure, stop sfcd on this server and run the dry run again.")
		return 1
	}
	fmt.Fprintf(out, "%s can start on %s's stored state (dry run, nothing on this server was changed).\n", buildinfo.Line("sfcd"), c.Node.ID)
	if r.Replayed {
		fmt.Fprintf(out, "- replayed the whole Raft log (1–%d) to the stored checkpoint and got the same state\n", r.Checkpoint)
	} else {
		fmt.Fprintf(out, "- read and checked the stored checkpoint at Raft index %d (the log before %d is in a snapshot, so it was not replayed)\n", r.Checkpoint, r.FirstLog)
	}
	fmt.Fprintf(out, "- applied the %d Raft entries after the checkpoint\n", r.Tail)
	return 0
}
