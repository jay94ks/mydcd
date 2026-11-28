// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagecache"
)

func init() { followKind("node-images", followImages) }

// nodeImagesCommand is `sfcli node images NODE` and `node images delete`.
func nodeImagesCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "images",
		Args:  "NODE",
		Short: "List the container images cached on a server (system administrator)",
		Long:  "Lists the images on NODE with the containers and deployments that still use them.",
		Run: func(c *cli.Context, args []string) error {
			node, err := nodeArg(args, "images")
			if err != nil {
				return err
			}
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			images := []imagecache.Image{}
			q := imagecache.Query{Node: node}
			for pages := 0; ; pages++ {
				if pages == 256 {
					return errors.New("too many image pages")
				}
				plan, err := s.Client.PlanImageCache(ctx, s.Target, s.Stored.Session, q)
				if err != nil {
					return err
				}
				images = append(images, plan.Images...)
				if q.After = plan.Next; q.After == "" {
					break
				}
			}
			return cli.Print(c.Out, g.output.Format(), images, func() cli.Rows {
				t := cli.Rows{Header: []string{"id", "names", "size", "containers", "used by"}}
				for _, i := range images {
					t.Add(i.ID, strings.Join(i.Aliases, ","), cli.Size(max(0, i.Bytes)), i.Containers, i.References)
				}
				return t
			})
		},
		Sub: []*cli.Command{nodeImagesDeleteCommand(g)},
	}
}

func nodeImagesDeleteCommand(g *globals) *cli.Command {
	var f changeFlags
	return &cli.Command{
		Name:  "delete",
		Args:  "NODE ID...",
		Short: "Delete unused cached images from a server (system administrator)",
		Long:  "Deletes 1 to 8 images by their full sha256 ID. An image any container or deployment still uses is refused.",
		Flags: func(fs *flag.FlagSet) { f.register(fs, true, true) },
		Run: func(c *cli.Context, args []string) error {
			if len(args) < 2 {
				return cli.Usagef("delete needs NODE and 1 to 8 image IDs")
			}
			node, err := nodeArg(args[:1], "delete")
			if err != nil {
				return err
			}
			ids := slices.Clone(args[1:])
			slices.Sort(ids)
			if !imagecache.ValidSelection(ids, true) {
				return cli.Usagef("give 1 to 8 different full sha256:... image IDs")
			}
			id := f.id.Get()
			s, err := g.open(c)
			if err != nil {
				return err
			}
			defer s.Close()
			ctx, cancel := g.Deadline(c)
			defer cancel()
			plan, err := s.Client.PlanImageCache(ctx, s.Target, s.Stored.Session, imagecache.Query{Node: node, Images: ids})
			if err != nil {
				return err
			}
			for _, i := range plan.Images {
				fmt.Fprintf(c.Err, "%s  %s  %d containers, used by %d\n", i.ID, cli.Size(max(0, i.Bytes)), i.Containers, i.References)
			}
			if !plan.DeleteReady() {
				return cli.ExitError{Code: 3, Err: errors.New("an image is still in use; nothing was sent")}
			}
			if f.dryRun {
				return nil
			}
			if err := g.Prompter(c).Confirm(fmt.Sprintf("Delete %d images from %s?", len(ids), node)); err != nil {
				return err
			}
			return g.apply(c, s, change{Kind: "node-images", Async: true, Summary: fmt.Sprintf("node images delete %s (%d images)", node, len(ids)), ID: id,
				Action: "prune-node-images", Payload: imagecache.Change{Operation: id, Plan: plan}}, f.noWait)
		},
	}
}

func followImages(ctx context.Context, s *session, op control.UserOperation) (cli.State, string, error) {
	operation, err := operationOf(op)
	if err != nil {
		return "", "", err
	}
	status, err := s.Client.ImageCacheStatus(ctx, s.Target, s.Stored.Session, operation)
	if err != nil {
		return "", "", err
	}
	return jobState(status.State), "image delete " + status.State, nil
}
