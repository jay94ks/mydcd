// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"flag"
	"fmt"
	"time"
)

// Handler settles operations of one kind with the server. Both functions
// use the operation's original ID; neither may send a new request ID.
type Handler struct {
	// Show asks the server what became of the operation and returns the
	// state and one result line to record.
	Show func(c *Context, op Op) (State, string, error)
	// Resume sends the same saved original again and follows it, for an
	// operation whose outcome is unknown or that stopped part way.
	Resume func(c *Context, op Op) (State, string, error)
}

// OpCommand builds `op list|show|resume|prune`. open opens the index; kinds
// maps each Op.Kind to its handler.
func OpCommand(open func() (*Ops, error), format *FormatFlag, kinds map[string]Handler) *Command {
	withOps := func(run func(*Context, *Ops, []string) error) func(*Context, []string) error {
		return func(c *Context, args []string) error {
			x, err := open()
			if err != nil {
				return err
			}
			defer x.Close()
			return run(c, x, args)
		}
	}
	settle := func(c *Context, x *Ops, id string, resume bool) error {
		op, err := x.Get(id)
		if err != nil {
			return err
		}
		h, ok := kinds[op.Kind]
		call := h.Show
		if resume {
			call = h.Resume
		}
		if !ok || call == nil {
			if resume {
				return fmt.Errorf("operation %s (%s) cannot be resumed by this version of sfcli", op.ID, op.Kind)
			}
		} else if !(op.State.Final() && !resume) {
			state, detail, err := call(c, op)
			if err != nil {
				return err
			}
			if err = x.Update(op.ID, state, detail); err != nil {
				return err
			}
			if op, err = x.Get(op.ID); err != nil {
				return err
			}
		}
		return Print(c.Out, format.Format(), op, nil)
	}
	return &Command{
		Name:  "op",
		Short: "Check and resume changes sent from this computer",
		Long: `Every change gets an operation ID before it is sent. If a command is
interrupted or its reply is lost, 'sfcli op show ID' asks the server what
happened with that same ID, and 'sfcli op resume ID' sends the same saved
request again. A new command is never needed to finish an old one.`,
		Sub: []*Command{
			{
				Name:  "list",
				Short: "List operations sent from this computer, newest first",
				Run: withOps(func(c *Context, x *Ops, args []string) error {
					if len(args) != 0 {
						return Usagef("list takes no arguments")
					}
					ops, err := x.List()
					if err != nil {
						return err
					}
					return Print(c.Out, format.Format(), ops, func() Rows {
						t := Rows{Header: []string{"id", "state", "created", "context", "command"}}
						for _, op := range ops {
							t.Add(op.ID, op.State, op.Created.Local().Format("2006-01-02 15:04"), op.Context, op.Summary)
						}
						return t
					})
				}),
			},
			{
				Name:  "show",
				Args:  "ID",
				Short: "Ask the server what became of an operation",
				Run: withOps(func(c *Context, x *Ops, args []string) error {
					if len(args) != 1 {
						return Usagef("show needs one operation ID")
					}
					return settle(c, x, args[0], false)
				}),
			},
			{
				Name:  "resume",
				Args:  "ID",
				Short: "Send the same saved request again and follow it",
				Run: withOps(func(c *Context, x *Ops, args []string) error {
					if len(args) != 1 {
						return Usagef("resume needs one operation ID")
					}
					return settle(c, x, args[0], true)
				}),
			},
			pruneCommand(withOps, format),
		},
	}
}

func pruneCommand(withOps func(func(*Context, *Ops, []string) error) func(*Context, []string) error, format *FormatFlag) *Command {
	var olderThan time.Duration
	var dryRun bool
	return &Command{
		Name:  "prune",
		Short: "Forget finished operations",
		Long:  "Removes finished (done or failed) operations from this computer's list. Operations still sending or running are kept.",
		Flags: func(fs *flag.FlagSet) {
			fs.DurationVar(&olderThan, "older-than", 0, "only operations finished at least this long ago, such as 168h")
			fs.BoolVar(&dryRun, "dry-run", false, "only print what would be removed")
		},
		Run: withOps(func(c *Context, x *Ops, args []string) error {
			if len(args) != 0 {
				return Usagef("prune takes no arguments")
			}
			ops, err := x.List()
			if err != nil {
				return err
			}
			removed := []Op{}
			for _, op := range ops {
				if !op.State.Final() || time.Since(op.Updated) < olderThan {
					continue
				}
				if !dryRun {
					if err := x.Remove(op.ID); err != nil && !errors.Is(err, ErrOpNotFound) {
						return err
					}
				}
				removed = append(removed, op)
			}
			return Print(c.Out, format.Format(), removed, func() Rows {
				t := Rows{Header: []string{"id", "state", "command"}}
				for _, op := range removed {
					t.Add(op.ID, op.State, op.Summary)
				}
				return t
			})
		}),
	}
}
