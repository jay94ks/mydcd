// SPDX-License-Identifier: Apache-2.0

package control

import (
	"fmt"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/eventlog"
)

// Book is everything control knows about one Raft book: its root key, the
// actions that write it, how it reduces, who may write it and which node
// reports it admits. A book declares itself once (one value in its own file)
// and is listed once in books (books.go); dispatch reads only that list.
// See devel/refactor/18-sfcd-structure.md.
//
// A book owns Key and every state key under Key+"/" (R17 checkpoint rule).
type Book struct {
	Key string

	// Actions are the user/operator action names that CommandKey maps to Key.
	Actions []string

	// Reduce applies every command whose Key is this book, whatever its kind.
	// A book that only accepts some kinds refuses the rest itself.
	Reduce func(p Policy, s state.State, cmd state.Command) (map[string][]byte, state.Code)

	// Authorize decides a signed user operation for one of Actions. When
	// OwnScope is false it runs after the account's action scope
	// (Catalog.OperationAllowed); when true it replaces that check and must
	// apply it itself where needed. Nil keeps the shared fallback.
	Authorize func(p Policy, s state.State, c access.Catalog, op UserOperation) error
	OwnScope  bool

	// AdmitReport checks a node ("node/" actor) command for this book before
	// it is proposed. With ReportOnly it applies only to ModuleReport commands;
	// other node commands fall through to the shared admission.
	AdmitReport func(p Policy, s state.State, cmd state.Command) error
	ReportOnly  bool

	// Events projects the event log rows a committed command on this book
	// produced. It runs only when the book's root object changed.
	Events func(p Policy, before, after state.State, emit eventEmitter) error
}

// eventEmitter appends one projected event (see ProjectEvents).
type eventEmitter func(kind, scope string, target eventlog.Target, detail eventlog.Detail)

var (
	bookByKey    map[string]*Book
	bookByAction map[string]*Book
	bookRoots    []string
)

func init() {
	if err := indexBooks(books); err != nil {
		panic(err)
	}
}

// indexBooks builds the lookup tables and refuses a list a new book would
// break: an empty or duplicate key, one key under another, or an action name
// two books claim.
func indexBooks(list []Book) error {
	byKey := map[string]*Book{}
	byAction := map[string]*Book{}
	roots := make([]string, 0, len(list))
	for i := range list {
		b := &list[i]
		if !strings.HasPrefix(b.Key, "control/") || b.Reduce == nil {
			return fmt.Errorf("control book %q: key or reducer missing", b.Key)
		}
		for _, other := range roots {
			if other == b.Key || strings.HasPrefix(b.Key, other+"/") || strings.HasPrefix(other, b.Key+"/") {
				return fmt.Errorf("control book %q overlaps %q", b.Key, other)
			}
		}
		if b.OwnScope && b.Authorize == nil {
			return fmt.Errorf("control book %q: OwnScope without Authorize", b.Key)
		}
		if b.ReportOnly && b.AdmitReport == nil {
			return fmt.Errorf("control book %q: ReportOnly without AdmitReport", b.Key)
		}
		for _, action := range b.Actions {
			if action == "" {
				return fmt.Errorf("control book %q: empty action", b.Key)
			}
			if prior, dup := byAction[action]; dup {
				return fmt.Errorf("control action %q in both %q and %q", action, prior.Key, b.Key)
			}
			byAction[action] = b
		}
		byKey[b.Key] = b
		roots = append(roots, b.Key)
	}
	bookByKey, bookByAction, bookRoots = byKey, byAction, roots
	return nil
}

// bookFor returns the book whose root is key.
func bookFor(key string) (*Book, bool) {
	b, ok := bookByKey[key]
	return b, ok
}

// actionBook returns the book that owns action.
func actionBook(action string) (*Book, bool) {
	b, ok := bookByAction[action]
	return b, ok
}

// authorizeCluster is the Authorize of an action any cluster manager may run.
func authorizeCluster(p Policy, _ state.State, c access.Catalog, op UserOperation) error {
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
}
