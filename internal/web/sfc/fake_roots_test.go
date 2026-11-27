// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

// Every key control.CommandKey can return, and the key of every Action*
// constant here, must be in rootKeys: otherwise Whoami.Roots lacks it,
// RootFor falls back to the catalog root and a strict submit refuses it (as
// happened when sfcd added control/certificates and ingress-management).
func TestRootKeysCoverActions(t *testing.T) {
	check := func(where, action string) {
		if key := control.CommandKey(action); !slices.Contains(rootKeys, key) {
			t.Errorf("%s (%s): key %s missing from rootKeys", where, action, key)
		}
	}
	fs := token.NewFileSet()
	members, err := parser.ParseFile(fs, filepath.Join("..", "..", "cluster", "control", "members.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	cases := 0
	for _, d := range members.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "CommandKey" {
			ast.Inspect(fn, func(n ast.Node) bool {
				if cc, ok := n.(*ast.CaseClause); ok {
					for _, e := range cc.List {
						if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							action, _ := strconv.Unquote(lit.Value)
							check("CommandKey", action)
							cases++
						}
					}
				}
				return true
			})
		}
	}
	if cases == 0 {
		t.Fatal("no CommandKey cases found")
	}
	for _, k := range []string{control.ImageBuildCachePruneAction, control.RegistryPruneAction} {
		check("CommandKey", k)
	}
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fs, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, id := range vs.Names {
				if !strings.HasPrefix(id.Name, "Action") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				action, _ := strconv.Unquote(lit.Value)
				check(id.Name, action)
			}
			return true
		})
	}
}
