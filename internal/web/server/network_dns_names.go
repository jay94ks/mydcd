// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// GET /api/v1/t/{t}/networks/{name}/dns/names: the names the network's
// managed DNS answers, and on each server whether its DNS has the current
// policy (the network row's state, as in /resources).
type dnsNameRow struct {
	Name    string `json:"name"`
	App     string `json:"app"`
	Service string `json:"service"`
	Task    string `json:"task,omitempty"`
	Family  string `json:"family"` // ipv4, ipv6
	Address string `json:"address"`
}

// dnsRecordRow is a record added by hand. Served is false while an app
// service has the same name (the app's address is answered).
type dnsRecordRow struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // A, AAAA, CNAME, TXT, MX, SRV, CAA
	Value  string `json:"value"`
	TTL    uint32 `json:"ttl,omitempty"`
	Served bool   `json:"served"`
}

type dnsServerRow struct {
	Node      string   `json:"node"`
	State     string   `json:"state"`
	Ready     *bool    `json:"ready,omitempty"`
	Resolvers []string `json:"resolvers"`
}

type dnsNamesView struct {
	Managed  bool           `json:"managed"`
	Enabled  bool           `json:"enabled"`
	Revision uint64         `json:"revision"`
	Zone     string         `json:"zone,omitempty"`
	Names    []dnsNameRow   `json:"names"`
	Records  []dnsRecordRow `json:"records"`
	Servers  []dnsServerRow `json:"servers"`
}

func (s *Server) handleNetworkDNSNames(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, name := r.PathValue("t"), r.PathValue("name")
	if !validName(name) {
		writeError(w, http.StatusNotFound, "not-found", "no such network")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (dnsNamesView, error) {
		n, _, err := findNetwork(ctx, c, tenant, name)
		if err != nil {
			return dnsNamesView{}, err
		}
		names, err := c.NetworkDNSNames(ctx, tenant, name)
		if err != nil {
			return dnsNamesView{}, err
		}
		out := dnsNamesView{Managed: names.Managed, Revision: names.Revision, Zone: names.Zone, Names: make([]dnsNameRow, 0, len(names.Names)), Records: make([]dnsRecordRow, 0, len(names.Records)), Servers: []dnsServerRow{}}
		for _, x := range names.Names {
			out.Names = append(out.Names, dnsNameRow{x.Name, x.App, x.Service, x.Task, x.Family, x.Address})
		}
		for _, x := range names.Records {
			out.Records = append(out.Records, dnsRecordRow{x.Name, x.Type, x.Value, x.TTL, x.Served})
		}
		if n.DNS != nil {
			out.Enabled = n.DNS.Enabled
			for _, m := range n.Members {
				row := dnsServerRow{Node: m.Node, State: n.DNS.State, Ready: n.DNS.Ready, Resolvers: []string{}}
				if m.DNS != nil {
					row.State, row.Ready, row.Resolvers = m.DNS.State, m.DNS.Ready, append([]string{}, m.DNS.Resolvers...)
				}
				out.Servers = append(out.Servers, row)
			}
		}
		return out, nil
	})
}

// PATCH /api/v1/t/{t}/networks/{name}/dns/records: change the names added
// by hand by a delta against the revision they were read at.
//
//	{opId, expected, remove: [{name, type, value}], add: [{name, type, value}]}
//
// Changing one record is removing the old one and adding the new one in
// the same call. name is a name under the zone ("www", or "www.<zone>");
// type is A (value an IPv4 address) or CNAME (value a full name, such as
// api.sample.<zone> or example.org). expected is the DNS policy revision of
// dns/names; when the policy has moved on since, the call is refused (409
// stale) and nothing is changed. Removing a record the list does not have,
// or adding one it has, is refused; an added name an app service already has
// is refused (an older one stays and waits, served false).
type dnsRecordInput struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

// sameDNSRecord is one record whatever its TTL.
func sameDNSRecord(a, b services.DNSRecord) bool {
	return a.Name == b.Name && a.Type == b.Type && a.Value == b.Value
}

func (s *Server) handleNetworkDNSRecords(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string           `json:"opId"`
		Expected uint64           `json:"expected"`
		Remove   []dnsRecordInput `json:"remove"`
		Add      []dnsRecordInput `json:"add"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, name := r.PathValue("t"), r.PathValue("name")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if !validName(name) {
			return "", nil, 0, "", invalid("network name")
		}
		if len(req.Remove)+len(req.Add) == 0 || len(req.Remove) > services.MaxDNSRecords || len(req.Add) > services.MaxDNSRecords {
			return "", nil, 0, "", invalid("remove, add: at least one record, at most 64 each")
		}
		if req.Expected == 0 {
			return "", nil, 0, "", invalid("expected: the DNS revision the list was read at")
		}
		n, _, err := findNetwork(ctx, c, tenant, name)
		if err != nil {
			return "", nil, 0, "", err
		}
		if n.DNS == nil || n.DNS.Policy.Transports == nil {
			return "", nil, 0, "", invalidCode("no-dns", "the network has no managed DNS; turn it on first")
		}
		if n.DNS.Revision != req.Expected {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "stale", "the DNS changed since it was read; read it again"}
		}
		p := n.DNS.Policy
		zone, err := services.Domain(p.Zone)
		if err != nil {
			return "", nil, 0, "", err
		}
		clientZone := ""
		if p.ClientZone != "" {
			clientZone, _ = services.Domain(p.ClientZone)
		}
		records := slices.Clone(p.Records)
		for _, x := range req.Remove {
			rec, err := dnsRecordOf(x, zone)
			if err != nil {
				return "", nil, 0, "", err
			}
			i := slices.IndexFunc(records, func(o services.DNSRecord) bool { return sameDNSRecord(o, rec) })
			if i < 0 {
				return "", nil, 0, "", invalidCode("no-such-record", "the list has no "+rec.Type+" "+rec.Name+" "+rec.Value)
			}
			records = slices.Delete(records, i, i+1)
		}
		var added []services.DNSRecord
		for _, x := range req.Add {
			rec, err := dnsRecordOf(x, zone)
			if err != nil {
				return "", nil, 0, "", err
			}
			if slices.ContainsFunc(records, func(o services.DNSRecord) bool { return sameDNSRecord(o, rec) }) {
				return "", nil, 0, "", invalidCode("exists", "the list already has "+rec.Type+" "+rec.Name+" "+rec.Value)
			}
			records = append(records, rec)
			added = append(added, rec)
		}
		records, err = services.ValidDNSRecords(zone, clientZone, records)
		if err != nil {
			return "", nil, 0, "", invalid("records: each name under the zone (not the zone or ns); a CNAME alone at its name; up to 8 of one type per name, with one ttl; at most 64")
		}
		if len(added) > 0 {
			names, err := c.NetworkDNSNames(ctx, tenant, name)
			if err != nil {
				return "", nil, 0, "", err
			}
			for _, rec := range added {
				kept := slices.ContainsFunc(p.Records, func(o services.DNSRecord) bool { return sameDNSRecord(o, rec) })
				taken := slices.ContainsFunc(names.Names, func(x sfc.NetworkDNSName) bool { return x.Name == rec.Name })
				if taken && !kept {
					return "", nil, 0, "", invalidCode("name-taken", "an app service already has the name "+rec.Name)
				}
			}
		}
		p.Records = records
		d := services.ManagedDNSDefinition{Schema: 1, Tenant: tenant, Network: name, Policy: p}
		return sfc.ActionConfigureNetworkDNS, d, req.Expected, name, nil
	})
}

// dnsRecordOf is the record x names, in the form the policy keeps. A TXT
// value that is not already quoted is one string.
func dnsRecordOf(x dnsRecordInput, zone string) (services.DNSRecord, error) {
	rec := services.DNSRecord{Name: strings.ToLower(strings.TrimSpace(x.Name)), Type: strings.ToUpper(strings.TrimSpace(x.Type)), Value: strings.TrimSpace(x.Value), TTL: x.TTL}
	bare := strings.TrimSuffix(zone, ".")
	if rec.Name == "" || strings.HasSuffix(rec.Name, ".") {
		return rec, invalid("records: name is a name under the zone, such as www")
	}
	switch {
	case rec.Name == "@":
		rec.Name = zone
	case rec.Name == bare || strings.HasSuffix(rec.Name, "."+bare):
		rec.Name += "."
	default:
		rec.Name += "." + zone
	}
	if !slices.Contains(services.DNSRecordTypes, rec.Type) {
		return rec, invalid("records: type is one of " + strings.Join(services.DNSRecordTypes, ", "))
	}
	if rec.Type == "TXT" && !strings.HasPrefix(rec.Value, `"`) {
		rec.Value = `"` + strings.ReplaceAll(strings.ReplaceAll(rec.Value, `\`, `\\`), `"`, `\"`) + `"`
	}
	if rec.TTL > 3600 {
		return rec, invalid("records: ttl is at most 3600 (the network's TTL caps it)")
	}
	parsed, _, err := services.ParseDNSRecord(rec)
	if err != nil {
		return rec, invalid("records: " + rec.Type + " value is not valid: " + dnsValueHint[rec.Type])
	}
	return parsed, nil
}

var dnsValueHint = map[string]string{
	"A":     "an IPv4 address, such as 192.0.2.7",
	"AAAA":  "an IPv6 address, such as 2001:db8::7",
	"CNAME": "a full name, such as example.org",
	"TXT":   `text, or quoted strings such as "v=spf1 -all" (255 bytes each)`,
	"MX":    "preference and host, such as 10 mail.example.org",
	"SRV":   "priority, weight, port and host, such as 10 5 5432 db.example.org",
	"CAA":   `flag, tag (issue, issuewild, iodef) and value, such as 0 issue "letsencrypt.org"`,
}
