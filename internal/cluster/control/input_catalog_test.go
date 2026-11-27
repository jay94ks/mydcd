// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"slices"
	"strconv"
	"testing"
)

// Every action the InputChange switch accepts is in inputPayloads, and no
// other.
func TestInputPayloadsMatchInputChange(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "input.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var cases []string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "InputChange" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			if sel, ok := sw.Tag.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Action" {
				return true
			}
			for _, s := range sw.Body.List {
				for _, e := range s.(*ast.CaseClause).List {
					switch v := e.(type) {
					case *ast.BasicLit:
						name, _ := strconv.Unquote(v.Value)
						cases = append(cases, name)
					case *ast.Ident:
						cases = append(cases, constants[v.Name])
					}
				}
			}
			return false
		})
		return false
	})
	if len(cases) < 100 {
		t.Fatalf("parsed %d cases", len(cases))
	}
	for _, c := range cases {
		if _, ok := inputPayloads[c]; !ok || c == "" {
			t.Errorf("InputChange accepts %q, inputPayloads lacks it", c)
		}
	}
	for a := range inputPayloads {
		if !slices.Contains(cases, a) {
			t.Errorf("inputPayloads has %q, InputChange does not accept it", a)
		}
	}
}

var constants = map[string]string{"ImageBuildCachePruneAction": ImageBuildCachePruneAction, "RegistryPruneAction": RegistryPruneAction}

// The described fields are the JSON keys the payload type has.
func TestInputActionsDescribePayloads(t *testing.T) {
	actions := InputActions()
	if len(actions) != len(inputPayloads) || !slices.IsSortedFunc(actions, func(a, b InputAction) int {
		if a.Action < b.Action {
			return -1
		}
		return 1
	}) {
		t.Fatalf("%d actions", len(actions))
	}
	for _, a := range actions {
		typ := inputPayloads[a.Action]
		if typ.Kind() != reflect.Struct {
			continue
		}
		raw, err := json.Marshal(reflect.New(typ).Interface())
		if err != nil {
			continue
		}
		var keys map[string]json.RawMessage
		if json.Unmarshal(raw, &keys) != nil {
			continue
		}
		for _, f := range a.Fields {
			if _, ok := keys[f.Name]; !ok && !omitEmpty(typ, f.Name) {
				t.Errorf("%s: field %s is not a JSON key of %s", a.Action, f.Name, typ)
			}
		}
	}
	byName := map[string]InputAction{}
	for _, a := range actions {
		byName[a.Action] = a
	}
	field := func(action, name string) InputField {
		for _, f := range byName[action].Fields {
			if f.Name == name {
				return f
			}
		}
		t.Fatalf("%s has no %s: %+v", action, name, byName[action])
		return InputField{}
	}
	if f := field("set-nodes", "Add"); f.Type != "list" || f.Items.Type != "string" || f.Replace {
		t.Fatalf("set-nodes Add: %+v", f)
	}
	if f := field("set-membership", "Enabled"); f.Type != "boolean" || f.Replace {
		t.Fatalf("set-membership Enabled: %+v", f)
	}
	if a := byName["set-membership"]; a.Key != "access" {
		t.Fatalf("set-membership key: %q", a.Key)
	}
	if a := byName["create-tun-network"]; a.Key != "resources" {
		t.Fatalf("create-tun-network key: %q", a.Key)
	}
}

func omitEmpty(t reflect.Type, name string) bool {
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if n, opts, _ := cutTag(tag); (n == name || n == "" && t.Field(i).Name == name) && opts {
			return true
		}
		if t.Field(i).Anonymous {
			return true
		}
	}
	return false
}

func cutTag(tag string) (string, bool, bool) {
	for i := 0; i < len(tag); i++ {
		if tag[i] == ',' {
			return tag[:i], len(tag) > i+1, true
		}
	}
	return tag, false, false
}
