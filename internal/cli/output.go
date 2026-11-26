// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// Format is the -o output format. Table is for people; json and yaml are
// for scripts and keep every field.
type Format string

const (
	Table Format = "table"
	JSON  Format = "json"
	YAML  Format = "yaml"
)

// FormatFlag is the -o option value. The zero value means table.
type FormatFlag struct{ F Format }

func (f *FormatFlag) String() string {
	if f.F == "" {
		return string(Table)
	}
	return string(f.F)
}

func (f *FormatFlag) Set(s string) error {
	switch Format(s) {
	case Table, JSON, YAML:
		f.F = Format(s)
		return nil
	}
	return fmt.Errorf("output must be table, json or yaml")
}

// Format returns the chosen format, table when unset.
func (f *FormatFlag) Format() Format {
	if f.F == "" {
		return Table
	}
	return f.F
}

// Rows is a table for people: a header and string cells.
type Rows struct {
	Header []string
	Rows   [][]string
}

// Add appends one row; values are printed with %v and empty cells as "-".
func (r *Rows) Add(values ...any) {
	row := make([]string, len(values))
	for i, v := range values {
		row[i] = fmt.Sprint(v)
		if row[i] == "" {
			row[i] = "-"
		}
	}
	r.Rows = append(r.Rows, row)
}

// Print writes value in the format. For table it prints rows; when rows is
// nil the value is shown as yaml, which reads well for a single record.
func Print(w io.Writer, f Format, value any, rows func() Rows) error {
	switch f {
	case JSON:
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		return e.Encode(value)
	case YAML:
		return writeYAML(w, value)
	}
	if rows == nil {
		return writeYAML(w, value)
	}
	t := rows()
	if len(t.Rows) == 0 {
		_, err := fmt.Fprintln(w, "(none)")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.ToUpper(strings.Join(t.Header, "\t")))
	for _, row := range t.Rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

// writeYAML goes through JSON so yaml output uses the same field names and
// omissions as -o json.
func writeYAML(w io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var generic any
	if err = yaml.Unmarshal(raw, &generic); err != nil {
		return err
	}
	e := yaml.NewEncoder(w)
	e.SetIndent(2)
	if err = e.Encode(generic); err != nil {
		return err
	}
	return e.Close()
}
