// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/certstore"
	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// mydc certificate: the cluster's TLS certificate store (system
// administrators). Usage: docs/cli/certificate.md.

func certificateCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "certificate",
		Short: "Manage the cluster's TLS certificates for ingress",
		Long: `Certificates are stored once for the whole cluster, with no name: the ID
is the SHA-256 of the leaf certificate. Each host of a certificate inside a
registered domain (mydc domain) is linked to the certificate that expires
last, one per key family (ECDSA, RSA). Ingress and the registry pick
certificates by host. Only system administrators can change the store. The
private key is sealed by the server; mydc never stores it.`,
		Sub: []*cli.Command{
			certificateListCommand(g),
			certificateShowCommand(g),
			certificatePutCommand(g),
			certificateSelectCommand(g, "delete", "Delete an unlinked or pending-destroy certificate"),
			certificateSelectCommand(g, "disable", "Drop every link of a certificate at once (a leaked key)"),
		},
	}
}

func shortID(id certstore.ID) string { return id.String()[:12] }

func algorithmLabel(algorithm string) string {
	if certstore.Discouraged(algorithm) {
		return algorithm + " (not recommended)"
	}
	return algorithm
}

func stateLabel(e certstore.PublicEntry) string {
	if e.DisabledAt != 0 {
		return e.State + " (disabled)"
	}
	return e.State
}

func certificateListCommand(g *globals) *cli.Command {
	var host string
	var pending, unlinked bool
	return &cli.Command{
		Name:  "list",
		Short: "List certificates",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&host, "host", "", "only certificates whose names cover this `host`")
			fs.BoolVar(&pending, "pending", false, "only pending-destroy certificates")
			fs.BoolVar(&unlinked, "unlinked", false, "only unlinked certificates")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			all, _, err := certificateEntries(c, g, s)
			if err != nil {
				return err
			}
			entries := []certstore.PublicEntry{}
			for _, e := range all {
				if host != "" && !e.Metadata.Covers(host) || pending && e.State != certstore.StatePendingDestroy || unlinked && e.State != certstore.StateUnlinked || pending && unlinked {
					continue
				}
				entries = append(entries, e)
			}
			return cli.Print(c.Out, g.output.Format(), entries, func() cli.Rows {
				t := cli.Rows{Header: []string{"id", "hosts", "algorithm", "issuer", "expires", "state", "links"}}
				for _, e := range entries {
					m := e.Metadata
					t.Add(shortID(m.ID), hostsLabel(m.Hosts), algorithmLabel(m.Algorithm), m.Issuer, expiresLabel(m.NotAfter), stateLabel(e), len(e.Links))
				}
				return t
			})
		}),
	}
}

func hostsLabel(hosts []string) string {
	if len(hosts) == 0 {
		return ""
	}
	if len(hosts) == 1 {
		return hosts[0]
	}
	return fmt.Sprintf("%s +%d", hosts[0], len(hosts)-1)
}

func expiresLabel(notAfter int64) string {
	days := int(time.Until(time.Unix(notAfter, 0)).Hours() / 24)
	return fmt.Sprintf("%s (%dd)", time.Unix(notAfter, 0).Local().Format("2006-01-02"), days)
}

// certificateEntries reads every page of the store at one revision.
func certificateEntries(c *cli.Context, g *globals, s *session) ([]certstore.PublicEntry, uint64, error) {
	var all []certstore.PublicEntry
	var revision uint64
	after := ""
	for {
		ctx, cancel := g.Deadline(c)
		page, err := s.Client.QueryCertificates(ctx, s.Target, s.Stored.Session, control.CertificateQuery{After: after})
		cancel()
		if err != nil {
			return nil, 0, err
		}
		if after != "" && page.Revision != revision {
			return nil, 0, errors.New("the certificate list changed while it was read; run the command again")
		}
		revision = page.Revision
		all = append(all, page.Certificates...)
		if page.Next == "" || page.Next == after {
			break
		}
		after = page.Next
	}
	if all == nil {
		all = []certstore.PublicEntry{}
	}
	return all, revision, nil
}

// findCertificateID resolves a full ID or a prefix of 12 or more characters.
func findCertificateID(entries []certstore.PublicEntry, prefix string) (certstore.PublicEntry, error) {
	prefix = strings.ToLower(prefix)
	if len(prefix) < 12 {
		return certstore.PublicEntry{}, cli.Usagef("give at least 12 characters of the certificate ID")
	}
	var found []certstore.PublicEntry
	for _, e := range entries {
		if strings.HasPrefix(e.Metadata.ID.String(), prefix) {
			found = append(found, e)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return certstore.PublicEntry{}, fmt.Errorf("no certificate has ID %s", prefix)
	}
	return certstore.PublicEntry{}, fmt.Errorf("%d certificates start with %s; give more of the ID", len(found), prefix)
}

func isIDPrefix(arg string) bool {
	if len(arg) < 12 || len(arg) > 64 {
		return false
	}
	_, err := hex.DecodeString(arg + strings.Repeat("0", len(arg)%2))
	return err == nil
}

type certificateView struct {
	certstore.PublicEntry
	Chain []string `json:"chain"`
}

func certificateShowCommand(g *globals) *cli.Command {
	var issuer, serial string
	return &cli.Command{
		Name:  "show",
		Args:  "ID|HOST",
		Short: "Show a certificate by ID, host, or issuer and serial",
		Long: `Shows one certificate. The argument is an ID (12 or more characters) or a
host; a host shows the certificate linked to it for each key family (the
exact host first, then a one-level wildcard). With --issuer and --serial and
no argument, the certificate with that issuer DN (or CN, when only one
matches) and serial number.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&issuer, "issuer", "", "issuer `DN` or CN")
			fs.StringVar(&serial, "serial", "", "serial `number` in hex (colons allowed)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if (issuer == "") != (serial == "") || issuer != "" && len(args) != 0 || issuer == "" && len(args) != 1 {
				return cli.Usagef("show needs an ID or host, or --issuer and --serial")
			}
			entries, _, err := certificateEntries(c, g, s)
			if err != nil {
				return err
			}
			var picked []certstore.PublicEntry
			switch {
			case issuer != "":
				var catalog certstore.Catalog
				for _, e := range entries {
					catalog.Certificates = append(catalog.Certificates, certstore.Entry{Certificate: certstore.Certificate{Metadata: e.Metadata}})
				}
				e, ok := catalog.Find("", issuer, serial)
				if !ok {
					return errors.New("no single certificate has that issuer and serial")
				}
				one, _ := findCertificateID(entries, e.Certificate.Metadata.ID.String())
				picked = append(picked, one)
			case isIDPrefix(args[0]):
				e, err := findCertificateID(entries, args[0])
				if err != nil {
					return err
				}
				picked = append(picked, e)
			default:
				picked = certstore.LookupPublic(entries, args[0])
				if len(picked) == 0 {
					return fmt.Errorf("no certificate is linked to %s", args[0])
				}
			}
			views := []certificateView{}
			for _, e := range picked {
				ctx, cancel := g.Deadline(c)
				page, err := s.Client.QueryCertificates(ctx, s.Target, s.Stored.Session, control.CertificateQuery{ID: e.Metadata.ID.String()})
				cancel()
				if err != nil {
					return err
				}
				view := certificateView{PublicEntry: e, Chain: []string{}}
				if in, err := certstore.Inspect(page.Chain, time.Now().Unix()); err == nil {
					view.Chain = in.Subjects
				}
				views = append(views, view)
			}
			if g.output.Format() != cli.Table {
				if len(views) == 1 {
					return cli.Print(c.Out, g.output.Format(), views[0], nil)
				}
				return cli.Print(c.Out, g.output.Format(), views, nil)
			}
			for i, v := range views {
				if i > 0 {
					fmt.Fprintln(c.Out)
				}
				printCertificate(c.Out, v)
			}
			return nil
		}),
	}
}

func printCertificate(w io.Writer, v certificateView) {
	m := v.Metadata
	fmt.Fprintf(w, "ID:         %s\n", m.ID)
	fmt.Fprintf(w, "Hosts:      %s\n", strings.Join(m.Hosts, ", "))
	fmt.Fprintf(w, "Algorithm:  %s\n", algorithmLabel(m.Algorithm))
	fmt.Fprintf(w, "Issuer:     %s\n", m.Issuer)
	fmt.Fprintf(w, "Serial:     %s\n", m.Serial)
	fmt.Fprintf(w, "Valid:      %s to %s\n", time.Unix(m.NotBefore, 0).Local().Format(time.DateTime), time.Unix(m.NotAfter, 0).Local().Format(time.DateTime))
	fmt.Fprintf(w, "Uploaded:   %s by %s\n", time.Unix(m.UploadedAt, 0).Local().Format(time.DateTime), m.UploadedBy)
	fmt.Fprintf(w, "State:      %s\n", stateLabel(v.PublicEntry))
	for i, subject := range v.Chain {
		label := "Chain:"
		if i > 0 {
			label = ""
		}
		fmt.Fprintf(w, "%-11s %s\n", label, subject)
	}
	for i, l := range v.Links {
		label := "Links:"
		if i > 0 {
			label = ""
		}
		fmt.Fprintf(w, "%-11s %s (%s)\n", label, l.Host, l.Family)
	}
}

// readInputFile reads a whole file, or standard input for "-", up to limit
// bytes.
func readInputFile(c *cli.Context, path string, limit int) ([]byte, error) {
	var r io.Reader = c.In
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		clear(raw)
		return nil, err
	}
	if len(raw) == 0 || len(raw) > limit {
		clear(raw)
		return nil, fmt.Errorf("%s must hold 1 to %d bytes", path, limit)
	}
	return raw, nil
}

func certificatePutCommand(g *globals) *cli.Command {
	var chain, key string
	var id cli.IDFlag
	return &cli.Command{
		Name:  "put",
		Short: "Upload a certificate",
		Long: `Uploads a PEM certificate chain and its private key. The store reads the
hosts from the leaf (DNS and IP names, or the subject CN when there are
none) and links them. The key is read once and sent through the protected
input path; it is never saved on this computer. Use --key - to read the key
from standard input. A certificate already in the store is reported, not
uploaded again.`,
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&chain, "chain", "", "PEM certificate chain `file`, leaf first")
			fs.StringVar(&key, "key", "", "PEM private key `file`, or - for standard input")
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("put takes no arguments; certificates have no name")
			}
			if chain == "" || key == "" || chain == "-" {
				return cli.Usagef("put needs --chain FILE and --key FILE (or --key -)")
			}
			opID := id.Get()
			// An upload whose key already went out continues from the
			// saved intent; the files are not read again.
			if intent, err := userauth.LoadCertificateIntent(s.Home, s.Client, s.Stored.Session, opID); err == nil && (intent.Dispatched || intent.Fact != nil) {
				fmt.Fprintf(c.Err, "Operation %s\n", opID)
				result, err := certificatePut(c, g, s, opID, nil, nil)
				if err != nil {
					return err
				}
				return printApplied(c, g, opID, result)
			}
			chainPEM, err := readInputFile(c, chain, certstore.MaxChainBytes)
			if err != nil {
				return err
			}
			defer clear(chainPEM)
			in, err := certstore.Inspect(chainPEM, time.Now().Unix())
			if err != nil {
				return errors.New("the chain is not a PEM certificate chain, leaf first")
			}
			if msg := invalidMessage(in.Invalid); msg != "" {
				return errors.New(msg)
			}
			entries, _, err := certificateEntries(c, g, s)
			if err != nil {
				return err
			}
			if e, err := findCertificateID(entries, in.Metadata.ID.String()); err == nil {
				fmt.Fprintf(c.Err, "Certificate %s is already in the store (%s).\n", shortID(e.Metadata.ID), stateLabel(e))
				return cli.Print(c.Out, g.output.Format(), e, func() cli.Rows {
					t := cli.Rows{Header: []string{"id", "state", "links"}}
					t.Add(shortID(e.Metadata.ID), stateLabel(e), len(e.Links))
					return t
				})
			}
			keyPEM, err := readInputFile(c, key, certstore.MaxKeyBytes)
			if err != nil {
				return err
			}
			defer clear(keyPEM)
			m := in.Metadata
			fmt.Fprintf(c.Err, "Upload certificate %s for %s (%s, expires %s).\n", shortID(m.ID), strings.Join(m.Hosts, ", "), algorithmLabel(m.Algorithm), expiresLabel(m.NotAfter))
			if certstore.Discouraged(m.Algorithm) {
				fmt.Fprintln(c.Err, "RSA is accepted but not recommended; ingress serves it only to clients without ECDSA.")
			}
			if err := g.Prompter(c).Confirm("Go ahead?"); err != nil {
				return err
			}
			if err := g.Record(s, "certificate-put", "certificate put "+shortID(m.ID), opID); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Operation %s\n", opID)
			result, err := certificatePut(c, g, s, opID, chainPEM, keyPEM)
			if err != nil {
				return err
			}
			return printApplied(c, g, opID, result)
		}),
	}
}

func invalidMessage(code string) string {
	switch code {
	case certstore.InvalidExpired:
		return "the certificate has expired"
	case certstore.InvalidNotYetValid:
		return "the certificate is not valid yet"
	case certstore.InvalidKey:
		return "the key algorithm is not supported (ECDSA P-256/P-384 or RSA 2048 bits or more)"
	case certstore.InvalidNoNames:
		return "the certificate has no DNS or IP name and no subject CN"
	}
	return ""
}

// certificatePut runs (or continues) the two steps of an upload with one
// operation ID: the protected key input that the server seals into a
// receipt, then the put-certificate change that publishes that receipt. With
// nil chain and key it only continues: an upload whose key was already sent
// is recovered from the server without reading the key again.
func certificatePut(c *cli.Context, g *globals, s *session, id string, chain, key []byte) (*state.Result, error) {
	home, client, session := s.Home, s.Client, s.Stored.Session
	intent, err := userauth.LoadCertificateIntent(home, client, session, id)
	if errors.Is(err, userauth.ErrOperationMissing) {
		if chain == nil {
			return nil, fmt.Errorf("operation %s never sent its key; run 'mydc certificate put' again with --id %s", id, id)
		}
		intent, err = userauth.StageCertificateIntent(home, client, session, userauth.CertificateIntent{ID: id, Owner: [32]byte(s.Target.Key)})
	}
	if err != nil {
		return nil, err
	}
	owner := s.Target
	if [32]byte(owner.Key) != intent.Owner {
		found := false
		for _, p := range client.Peers {
			if [32]byte(p.Key) == intent.Owner {
				owner, found = p, true
			}
		}
		if !found {
			return nil, errors.New("the server that sealed this upload is no longer in the context")
		}
	}
	if intent.Fact == nil {
		q := userauth.CertificateInput{Request: id, Recover: intent.Dispatched}
		if !q.Recover {
			if chain == nil {
				return nil, fmt.Errorf("operation %s never sent its key; run 'mydc certificate put' again with --id %s", id, id)
			}
			q.Chain, q.Key = chain, key
			if err = userauth.UpdateCertificateIntent(home, client, session, id, nil); err != nil {
				return nil, err
			}
		}
		ctx, cancel := g.Deadline(c)
		v, err := client.WriteCertificate(ctx, owner, session, q)
		cancel()
		if err != nil {
			return nil, errOutcomeUnknown{id: id, err: err}
		}
		if err = userauth.UpdateCertificateIntent(home, client, session, id, &v); err != nil {
			return nil, err
		}
		intent.Fact = &v
	}
	return g.send(c, s, change{Kind: "certificate-put", Summary: "certificate put " + shortID(intent.Fact.Metadata.ID), ID: id, Action: "put-certificate", Payload: control.CertificatePut{Certificate: *intent.Fact}})
}

func certificateSelectCommand(g *globals, verb, short string) *cli.Command {
	var id cli.IDFlag
	return &cli.Command{
		Name:  verb,
		Args:  "ID",
		Short: short,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
		},
		Run: g.withSession(func(c *cli.Context, s *session, args []string) error {
			if len(args) != 1 {
				return cli.Usagef("%s needs one certificate ID", verb)
			}
			entries, _, err := certificateEntries(c, g, s)
			if err != nil {
				return err
			}
			e, err := findCertificateID(entries, args[0])
			if err != nil {
				return err
			}
			short := shortID(e.Metadata.ID)
			var impact string
			switch {
			case verb == "delete" && e.State == certstore.StateLinked:
				hosts := []string{}
				for _, l := range e.Links {
					hosts = append(hosts, l.Host+" ("+l.Family+")")
				}
				return fmt.Errorf("certificate %s is linked to %s; disable it first", short, strings.Join(hosts, ", "))
			case verb == "delete" && e.DisabledAt != 0:
				impact = fmt.Sprintf("Delete certificate %s. It was disabled; uploading the same certificate again after this gives it links again.", short)
			case verb == "delete":
				impact = fmt.Sprintf("Delete certificate %s (%s).", short, e.State)
			case e.DisabledAt != 0:
				return fmt.Errorf("certificate %s is already disabled", short)
			default:
				impact = fmt.Sprintf("Disable certificate %s. Its %d links move to the next best certificate, or the hosts have none.", short, len(e.Links))
			}
			return g.sendAndPrint(c, s, impact, change{ID: id.Get(), Summary: "certificate " + verb + " " + short, Action: verb + "-certificate", Payload: control.CertificateSelection{ID: e.Metadata.ID}})
		}),
	}
}

// certificatePutHandler settles a certificate upload with its original ID.
// Resume never reads the key again: an upload whose key was sent is
// recovered from the server's sealed receipt.
func certificatePutHandler(g *globals) cli.Handler {
	published := changeHandler(g, nil, false)
	settle := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
		s, err := g.opSession(c, op)
		if err != nil {
			return "", "", err
		}
		defer s.Close()
		if _, err := userauth.LoadOperation(s.Home, s.Client, s.Stored.Session, op.ID); err == nil && !resume {
			return published.Show(c, op)
		}
		intent, err := userauth.LoadCertificateIntent(s.Home, s.Client, s.Stored.Session, op.ID)
		if errors.Is(err, userauth.ErrOperationMissing) {
			return cli.Failed, "not sent", nil
		}
		if err != nil {
			return "", "", err
		}
		if !resume {
			if !intent.Dispatched {
				return cli.Failed, "not sent: the key was never sent", nil
			}
			return cli.Sending, "the key was sent but the certificate is not published; 'mydc op resume " + op.ID + "' finishes it", nil
		}
		result, err := certificatePut(c, g, s, op.ID, nil, nil)
		if result == nil {
			return "", "", err
		}
		st, detail := changeState(*result, false)
		return st, detail, nil
	}
	return cli.Handler{
		Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, false) },
		Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, true) },
	}
}

func init() {
	opKinds["certificate-put"] = certificatePutHandler
}
