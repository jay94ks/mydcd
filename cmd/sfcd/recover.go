// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/config"
)

// runRecover is `sfcd recover` (design B2): on a surviving voter, with sfcd
// stopped, force a voting configuration of only the listed voters after the
// cluster lost its voter majority for good. Run it on every surviving voter
// with the same --voters list, then start sfcd on each.
func runRecover(args []string, globalConfig string, in io.Reader, out, diagnostic io.Writer) int {
	f := flag.NewFlagSet("sfcd recover", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	file := onceString{value: globalConfig, set: globalConfig != ""}
	var voters, request onceString
	var confirm uint64
	f.Var(&file, "config", "managed node YAML file")
	f.Var(&voters, "voters", "surviving voters, separated by commas; must include this server")
	f.Var(&request, "request-id", "recovery operation ID, recorded in the cluster")
	f.Uint64Var(&confirm, "confirm-index", 0, "the last Raft index shown by the preview (needed without a terminal)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return fail(diagnostic, err, 2)
	}
	if f.NArg() != 0 || file.value == "" || voters.value == "" || request.value == "" {
		return fail(diagnostic, errors.New("recover requires --config, --voters and --request-id"), 2)
	}
	list := strings.Split(voters.value, ",")
	for i := range list {
		list[i] = strings.TrimSpace(list[i])
	}
	c, err := config.LoadNode(file.value)
	if err != nil {
		return fail(diagnostic, err, 2)
	}
	p, err := app.PreviewRecovery(c, list)
	if err != nil {
		return fail(diagnostic, err, 1)
	}
	fmt.Fprintf(diagnostic, "Cluster %x, this server %s\n", p.Cluster[:4], p.Node)
	fmt.Fprintf(diagnostic, "Local Raft configuration (index %d), last log index %d, term %d:\n", p.ConfigurationIndex, p.LastIndex, p.Term)
	for _, s := range p.Servers {
		fmt.Fprintf(diagnostic, "  %s %s %s\n", s.ID, s.Suffrage, s.Address)
	}
	fmt.Fprintf(diagnostic, "Voters after recovery: %s\n", strings.Join(p.Voters, ", "))
	fmt.Fprintf(diagnostic, "Lost (retired, refused if they come back): %s\n", strings.Join(p.Lost, ", "))
	fmt.Fprintln(diagnostic, "Run this on EVERY surviving voter with the SAME --voters list. A different list splits the cluster.")
	if confirm == 0 {
		if nonInteractive() {
			return fail(diagnostic, errors.New("without a terminal give --confirm-index with the last log index shown above"), 2)
		}
		fmt.Fprintf(diagnostic, "Type the last log index (%d) to confirm: ", p.LastIndex)
		line, _ := bufio.NewReader(in).ReadString('\n')
		if confirm, err = strconv.ParseUint(strings.TrimSpace(line), 10, 64); err != nil {
			return fail(diagnostic, errors.New("not confirmed"), 1)
		}
	}
	if confirm != p.LastIndex {
		return fail(diagnostic, fmt.Errorf("not confirmed: the last log index is %d", p.LastIndex), 1)
	}
	plan, err := app.PlanRecovery(c, list, request.value, confirm, time.Now())
	if err != nil {
		return fail(diagnostic, err, 1)
	}
	fmt.Fprintf(out, "Recovery %s planned at index %d. Start sfcd to carry it out.\n", plan.RequestID, plan.Index())
	return 0
}

// nonInteractive: SFC_NONINTERACTIVE=1 (or true/yes), or stdin is not a terminal.
func nonInteractive() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SFC_NONINTERACTIVE"))) {
	case "1", "true", "yes":
		return true
	}
	info, err := os.Stdin.Stat()
	return err != nil || info.Mode()&os.ModeCharDevice == 0
}
