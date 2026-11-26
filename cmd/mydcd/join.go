// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/jay94ks/mydcd/internal/app"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
)

func runJoin(args []string, globalConfig string, out, diagnostic io.Writer) int {
	f := flag.NewFlagSet("mydcd join", flag.ContinueOnError)
	f.SetOutput(diagnostic)
	file := onceString{value: globalConfig, set: globalConfig != ""}
	var cluster, source, invitation onceString
	var timeout time.Duration
	f.Var(&file, "config", "managed node YAML; identity must already exist")
	f.Var(&cluster, "cluster", "explicit pinned target cluster ID")
	f.Var(&source, "source-public-key", "explicit pinned control public key that signed the invitation")
	f.Var(&invitation, "invitation", "original signed invitation file; retain it for resume")
	f.DurationVar(&timeout, "timeout", 30*time.Second, "join/synchronization deadline; uncertainty preserves the original intent")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if f.NArg() != 0 || file.value == "" || cluster.value == "" || source.value == "" || invitation.value == "" || timeout <= 0 || timeout > 5*time.Minute {
		return fail(diagnostic, errors.New("join requires --config, --cluster, --source-public-key and --invitation; timeout in (0,5m]"), 2)
	}
	clusterID, err := config.ClusterKey(cluster.value)
	if err != nil || hex.EncodeToString(clusterID[:]) != cluster.value {
		return fail(diagnostic, errors.New("cluster must be canonical lowercase ID"), 2)
	}
	key, err := identity.ParseKey(source.value)
	if err != nil || hex.EncodeToString(key[:]) != source.value {
		return fail(diagnostic, errors.New("source-public-key must be canonical lowercase key"), 2)
	}
	input, err := os.Open(invitation.value)
	if err != nil {
		return fail(diagnostic, err, 2)
	}
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = input.Close()
		return fail(diagnostic, errors.New("invitation must be a regular file"), 2)
	}
	raw, err := io.ReadAll(io.LimitReader(input, (16<<10)+1))
	closeErr := input.Close()
	if err != nil || closeErr != nil {
		return fail(diagnostic, errors.Join(err, closeErr), 2)
	}
	inv, err := membership.DecodeInvitation(raw)
	if err != nil || inv.Verify(clusterID, key) != nil {
		return fail(diagnostic, errors.New("invitation does not match explicit cluster/control pins"), 2)
	}
	c, err := config.LoadNode(file.value)
	if err != nil {
		return fail(diagnostic, err, 2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	runtime, record, err := app.Join(ctx, c, inv, clusterID, key)
	if err != nil {
		return fail(diagnostic, err, 4)
	}
	if err = runtime.Close(); err != nil {
		return fail(diagnostic, err, 1)
	}
	self, _ := record.Root.Installed.Member(c.Node.ID)
	return printInit(out, diagnostic, map[string]any{"schema": 1, "status": "Joined", "node": c.Node.ID, "cluster": cluster.value, "join_id": record.Root.Operation, "voter": self.Voter, "voters": record.Root.Installed.Voters(), "quorum": record.Root.Installed.Quorum(), "configuration_index": record.Root.Installed.Index, "applied_index": record.Root.AppliedIndex})
}
