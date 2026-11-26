// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/storage"
)

func TestSourceTypeMetadataHasNoToolchainAndCoversCompleteWhitelist(t *testing.T) {
	t.Setenv("GOROOT", filepath.Join(t.TempDir(), "missing-go"))
	t.Setenv("GOPATH", t.TempDir())
	t.Setenv("YAEGI_NO_RUN", "false")
	importer := newNativeTypeImporter()
	for _, pkg := range []string{"bytes", "context", "encoding/base64", "encoding/hex", "encoding/json", "errors", "fmt", "math", "math/bits", "net/url", "path", "sort", "strconv", "strings", "time", "unicode", "unicode/utf8", checkerSDK} {
		p, err := importer.Import(pkg)
		if err != nil || p == nil || !p.Complete() || len(p.Scope().Names()) == 0 {
			t.Fatal("compiled-in type surface missing", pkg, err)
		}
	}
	if _, err := importer.Import("os"); err == nil {
		t.Fatal("non-whitelist native package admitted")
	}
}
func TestSourceEditorDiagnosticsDoNotRunRootOrModuleInitialization(t *testing.T) {
	archive := moduleArchive(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte("package safe\nvar Initialization=func()int{panic(\"must not execute module init\")}()\nconst Ready=true\n")})
	root := append(scriptSource(`"example.invalid/safe";`, `if !safe.Ready { return lifecycle.Result{}, nil }; `+passBody), []byte("\nvar initialization = func() int { panic(\"must not execute source init\") }()\n")...)
	p, d, target := resolverInput(root, []ModuleArchive{archive}, "example.invalid/safe")
	resolved, err := ResolveSource(context.Background(), p, d, root, []ModuleArchive{archive}, target)
	if err != nil {
		t.Fatal(err)
	}
	diagnostics, err := CheckSourceTypes(context.Background(), resolved)
	if err != nil || len(diagnostics) != 0 {
		t.Fatal("valid graph rejected or initialized", diagnostics, err)
	}
	for _, mode := range []string{"syntax", "import", "signature", "shadowed-error", "missing-check", "type"} {
		t.Run(mode, func(t *testing.T) {
			source := scriptSource("", passBody)
			switch mode {
			case "syntax":
				source = scriptSource("", `return {`)
			case "import":
				source = scriptSource(`"os";`, passBody)
			case "signature":
				source = []byte("package checker\nfunc Check() {}\n")
			case "shadowed-error":
				source = append(scriptSource("", `return lifecycle.Result{}, 0`), []byte("\ntype error = int\n")...)
			case "missing-check":
				source = []byte("package checker\nconst Other=1\n")
			case "type":
				source = scriptSource("", `return lifecycle.Result{Schema: "wrong"}, nil`)
			}
			policy, descriptor, target := resolverInput(source, nil)
			resolved, cause := ResolveSource(context.Background(), policy, descriptor, source, nil, target)
			var list []SourceDiagnostic
			if cause != nil {
				list = sourceDiagnostics(cause)
			} else {
				list, cause = CheckSourceTypes(context.Background(), resolved)
			}
			if len(list) == 0 {
				t.Fatal("missing diagnostics", cause)
			}
			for _, d := range list {
				if !d.Valid() || d.Line < 1 || d.Column < 1 || strings.Contains(d.Message, "/tmp/") {
					t.Fatal("unbounded/private/location-free diagnostic", d)
				}
			}
		})
	}
}

func TestSourceEditorTypesPreserveNativeMethodsConstantsAndModuleAliases(t *testing.T) {
	archive := moduleArchive(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte(`package safe
import lifecycle "github.com/jay94ks/mydcd/lifecycle/v1"
type Request = lifecycle.Request
type Link struct { Next *Link }
func (link *Link) Ready() bool { return link == nil || link.Next == nil }
`)})
	root := scriptSource(`"bytes";"encoding/base64";"encoding/hex";"encoding/json";"errors";"fmt";"math";"math/bits";"net/url";"path";"sort";"strconv";"strings";"time";"unicode";"unicode/utf8";"example.invalid/safe";`, `
var native fmt.Stringer = time.Duration(time.Second)
var reader interface{ Read([]byte) (int,error) } = bytes.NewReader(nil)
var alias safe.Request = in
var link safe.Link
var _ [utf8.UTFMax]byte
const layout = time.RFC3339
if !link.Ready() { return lifecycle.Result{}, errors.New("link") }
when := time.Date(2026,time.January,1,0,0,0,0,time.UTC)
text := native.String()+when.Format(layout)+alias.Tenant
address,err := url.Parse("/ready")
if err != nil { return lifecycle.Result{},err }
text += path.Clean(address.String())+strconv.Itoa(bits.Len(1))
text += hex.EncodeToString([]byte(text))+base64.StdEncoding.EncodeToString(nil)
text += strings.TrimSpace(fmt.Sprint(math.Sqrt(4),unicode.IsLetter(utf8.RuneError)))
values := []string{text}
sort.Slice(values,func(i,j int)bool{return values[i]<values[j]})
if err := json.NewDecoder(reader).Decode(&values); err != nil { return lifecycle.Result{},err }
return lifecycle.Result{Schema:lifecycle.Schema,Status:lifecycle.Pass},nil
`)
	allow := []string{"bytes", "encoding/base64", "encoding/hex", "encoding/json", "errors", "fmt", "math", "math/bits", "net/url", "path", "sort", "strconv", "strings", "time", "unicode", "unicode/utf8", "example.invalid/safe"}
	p, d, target := resolverInput(root, []ModuleArchive{archive}, allow...)
	resolved, err := ResolveSource(context.Background(), p, d, root, []ModuleArchive{archive}, target)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics, err := CheckSourceTypes(context.Background(), resolved); err != nil || len(diagnostics) != 0 {
		t.Fatal("native methods/constants or source aliases changed identity", diagnostics, err)
	}
}

func TestSourceValidationNeverPublishesAndOriginalPagesVerifyEveryByte(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{133}, 32))
	defer clear(key)
	store, err := OpenSources(db, [32]byte{134}, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root := append(scriptSource("", passBody), []byte(strings.Repeat("// UTF-8 원본\n", 7000))...)
	p, d, _ := resolverInput(root, nil)
	diagnostics, err := store.ValidateSource(context.Background(), d, root, p)
	if err != nil || len(diagnostics) > 0 || len(store.entries) != 0 {
		t.Fatal("validation published a source fact", diagnostics, err)
	}
	fact, err := store.Stage(context.Background(), d, root, p)
	if err != nil {
		t.Fatal(err)
	}
	var received []byte
	for offset := uint64(0); ; {
		page, err := NewSourcePage(d.Tenant, "editor", 7, offset, fact.Descriptor(), root)
		if err != nil || !page.Valid() {
			t.Fatal(page, err)
		}
		received = append(received, page.Data...)
		if page.Next == 0 {
			break
		}
		offset = page.Next
	}
	if !bytes.Equal(received, root) || sha256.Sum256(received) != fact.Digest {
		t.Fatal("source page changed original bytes")
	}
	for _, offset := range []uint64{1, uint64(len(root)), uint64(len(root)) + 1} {
		if _, err := NewSourcePage(d.Tenant, "editor", 7, offset, d, root); err == nil {
			t.Fatal("foreign/EOF offset", offset)
		}
	}
	corrupt := bytes.Clone(root)
	corrupt[0] ^= 1
	if _, err := NewSourcePage(d.Tenant, "editor", 7, 0, d, corrupt); err == nil {
		t.Fatal("corrupt source accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = store.ValidateSource(canceled, d, root, p); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
