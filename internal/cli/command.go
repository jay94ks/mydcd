// SPDX-License-Identifier: Apache-2.0

// Package cli is the command frame shared by the sfcli commands: a tree of
// resource/verb commands with generated help, output formats, confirmation,
// request IDs, revision (CAS) selection and the local operation index behind
// `sfcli op`. Design: devel/design/cli-and-formats.md.
//
// The frame holds no product rules. Server rules (original operations, CAS,
// authorization) stay in sfcd and the client packages; a command only uses
// this package to present them.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Command is one node of the command tree. A group has Sub and no Run; a
// leaf has Run. Flags registers the command's own options; options of every
// ancestor are also accepted after the command name.
type Command struct {
	Name  string // one word, lower case
	Args  string // usage after the name, such as "APP [SERVICE]"
	Short string // one line, shown in the parent's command list
	Long  string // optional paragraph for the command's own help
	Flags func(*flag.FlagSet)
	Run   func(c *Context, args []string) error
	Sub   []*Command
}

// Context is what a running command gets.
type Context struct {
	Ctx   context.Context // cancelled on interrupt
	In    io.Reader
	Out   io.Writer
	Err   io.Writer
	Path  []string // command words from the root, such as sfcli app deploy
	Flags *flag.FlagSet
	Rest  []string // words after a bare "--", or nil
}

// Set reports whether the named option was given on the command line.
func (c *Context) Set(name string) bool {
	set := false
	c.Flags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// UsageError is a wrong command line. Execute prints it with a hint and
// exits with code 2.
type UsageError struct{ Message string }

func (e UsageError) Error() string { return e.Message }

// Usagef returns a UsageError.
func Usagef(format string, args ...any) error {
	return UsageError{Message: fmt.Sprintf(format, args...)}
}

// ExitError carries an explicit exit code. A nil Err exits silently.
type ExitError struct {
	Code int
	Err  error
}

func (e ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}
func (e ExitError) Unwrap() error { return e.Err }

// Env is the process environment Execute runs in.
type Env struct {
	Context context.Context
	In      io.Reader
	Out     io.Writer
	Err     io.Writer
}

// Find returns the direct subcommand with the given name.
func (c *Command) Find(name string) *Command {
	for _, s := range c.Sub {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// Execute runs the command line args (without the program name) against
// root and returns the process exit code: 0 success, 1 failure, 2 usage.
func Execute(root *Command, args []string, env Env) int {
	if env.Context == nil {
		env.Context = context.Background()
	}
	// Everything after a bare "--" is passed to the command untouched
	// (sfcli app exec shop web -- ls -l).
	var passthrough []string
	for i, a := range args {
		if a == "--" {
			args, passthrough = args[:i], append([]string{}, args[i+1:]...)
			break
		}
	}
	path := []*Command{root}
	fs := newFlagSet(path, nil)
	for {
		cmd := path[len(path)-1]
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				writeHelp(env.Out, path, fs)
				return 0
			}
			fmt.Fprintf(env.Err, "%s: %v\n", strings.Join(names(path), " "), err)
			fmt.Fprintf(env.Err, "Run '%s --help' for usage.\n", strings.Join(names(path), " "))
			return 2
		}
		args = fs.Args()
		if len(cmd.Sub) == 0 || len(args) == 0 {
			break
		}
		next := cmd.Find(args[0])
		if next == nil {
			if cmd.Run != nil {
				break
			}
			fmt.Fprintf(env.Err, "%s: unknown command %q\n", strings.Join(names(path), " "), args[0])
			fmt.Fprintf(env.Err, "Run '%s --help' for the list of commands.\n", strings.Join(names(path), " "))
			return 2
		}
		path = append(path, next)
		args = args[1:]
		fs = newFlagSet(path, fs)
	}
	cmd := path[len(path)-1]
	if cmd.Run == nil {
		writeHelp(env.Err, path, fs)
		return 2
	}
	// A leaf accepts options after its arguments too (sfcli app logs web -f).
	var positional []string
	for len(args) > 0 {
		positional = append(positional, args[0])
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				writeHelp(env.Out, path, fs)
				return 0
			}
			fmt.Fprintf(env.Err, "%s: %v\n", strings.Join(names(path), " "), err)
			fmt.Fprintf(env.Err, "Run '%s --help' for usage.\n", strings.Join(names(path), " "))
			return 2
		}
		args = fs.Args()
	}
	args = positional
	c := &Context{Ctx: env.Context, In: env.In, Out: env.Out, Err: env.Err, Path: names(path), Flags: fs, Rest: passthrough}
	err := cmd.Run(c, args)
	if err == nil {
		return 0
	}
	var usage UsageError
	if errors.As(err, &usage) {
		fmt.Fprintf(env.Err, "%s: %s\n", strings.Join(c.Path, " "), usage.Message)
		fmt.Fprintf(env.Err, "Run '%s --help' for usage.\n", strings.Join(c.Path, " "))
		return 2
	}
	var exit ExitError
	if errors.As(err, &exit) {
		if exit.Err != nil {
			fmt.Fprintf(env.Err, "%s: %v\n", c.Path[0], exit.Err)
		}
		return exit.Code
	}
	fmt.Fprintf(env.Err, "%s: %v\n", c.Path[0], err)
	return 1
}

// newFlagSet makes the option set of the last command in path. Options
// already registered by ancestors are carried over with their current
// values, so a global option may come before or after the command words.
func newFlagSet(path []*Command, parent *flag.FlagSet) *flag.FlagSet {
	fs := flag.NewFlagSet(strings.Join(names(path), " "), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if parent != nil {
		parent.VisitAll(func(f *flag.Flag) { fs.Var(f.Value, f.Name, f.Usage) })
	}
	if cmd := path[len(path)-1]; cmd.Flags != nil {
		cmd.Flags(fs)
	}
	return fs
}

func names(path []*Command) []string {
	out := make([]string, len(path))
	for i, c := range path {
		out[i] = c.Name
	}
	return out
}

func writeHelp(w io.Writer, path []*Command, fs *flag.FlagSet) {
	cmd := path[len(path)-1]
	usage := strings.Join(names(path), " ")
	switch {
	case cmd.Run == nil && len(cmd.Sub) > 0:
		usage += " COMMAND"
	case cmd.Args != "":
		usage += " " + cmd.Args
	}
	fmt.Fprintf(w, "Usage: %s [options]\n", usage)
	text := cmd.Long
	if text == "" {
		text = cmd.Short
	}
	if text != "" {
		fmt.Fprintf(w, "\n%s\n", strings.TrimSpace(text))
	}
	if len(cmd.Sub) > 0 {
		fmt.Fprintln(w, "\nCommands:")
		width := 0
		for _, s := range cmd.Sub {
			width = max(width, len(s.Name))
		}
		for _, s := range cmd.Sub {
			fmt.Fprintf(w, "  %-*s  %s\n", width, s.Name, s.Short)
		}
	}
	own := map[string]bool{}
	if cmd.Flags != nil {
		probe := flag.NewFlagSet("", flag.ContinueOnError)
		cmd.Flags(probe)
		probe.VisitAll(func(f *flag.Flag) { own[f.Name] = true })
	}
	var local, inherited []*flag.Flag
	fs.VisitAll(func(f *flag.Flag) {
		if own[f.Name] {
			local = append(local, f)
		} else {
			inherited = append(inherited, f)
		}
	})
	writeFlags(w, "Options:", local)
	if len(path) > 1 {
		writeFlags(w, "Global options:", inherited)
	}
	if len(cmd.Sub) > 0 {
		fmt.Fprintf(w, "\nRun '%s COMMAND --help' for more about a command.\n", strings.Join(names(path), " "))
	}
}

func writeFlags(w io.Writer, title string, flags []*flag.Flag) {
	if len(flags) == 0 {
		return
	}
	sort.Slice(flags, func(i, j int) bool { return flags[i].Name < flags[j].Name })
	fmt.Fprintf(w, "\n%s\n", title)
	rows := make([][2]string, len(flags))
	width := 0
	for i, f := range flags {
		dash := "--"
		if len(f.Name) == 1 {
			dash = "-"
		}
		name, usage := flag.UnquoteUsage(f)
		left := dash + f.Name
		if name != "" {
			left += " " + name
		}
		if d := f.DefValue; d != "" && d != "false" && d != "0" && d != "0s" && d != "[]" {
			usage += " (default " + d + ")"
		}
		rows[i] = [2]string{left, usage}
		width = max(width, len(left))
	}
	for _, r := range rows {
		fmt.Fprintf(w, "  %-*s  %s\n", width, r[0], r[1])
	}
}
