// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/servicecall"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

type serviceCallOptions struct {
	tenant, port, path, bodyFile, scheme, timeout onceString
	headers                                       serviceCallHeaders
	insecure                                      bool
	app, service                                  string
}
type serviceCallHeaders map[string]string

func (h *serviceCallHeaders) String() string { return "[service headers]" }
func (h *serviceCallHeaders) Set(value string) error {
	key, body, ok := strings.Cut(value, "=")
	if !ok || key == "" {
		return errors.New("header requires NAME=VALUE")
	}
	if *h == nil {
		*h = serviceCallHeaders{}
	}
	for existing := range *h {
		if strings.EqualFold(existing, key) {
			return errors.New("duplicate header")
		}
	}
	(*h)[key] = body
	return nil
}
func serviceCallHelp(out io.Writer) {
	fmt.Fprintln(out, "sfcli [account options] service-call APP SERVICE --port N --path /path [--scheme http|https] [--insecure-skip-verify] [--header NAME=VALUE ...] [--body-file FILE] [--timeout-ms N] [--tenant TENANT]")
	fmt.Fprintln(out, "One POST to a currently healthy owned Task. Requires call-service scope/current manager rights. Body ≤256KiB, response ≤64KiB, timeout ≤30s; redirects/proxies and arbitrary hosts are disabled. HTTPS verifies the Task IP against system/installed tenant CAs unless explicitly skipped.")
	fmt.Fprintln(out, "No automatic retry or journal: timeout/unknown/relay failure may follow an applied remote effect. Inspect the service before any explicit retry.")
}
func parseServiceCallOptions(args []string, out io.Writer) (serviceCallOptions, error) {
	var o serviceCallOptions
	if len(args) < 2 {
		return o, errors.New("service-call requires app and service")
	}
	o.app, o.service = args[0], args[1]
	f := flag.NewFlagSet("service-call", flag.ContinueOnError)
	f.SetOutput(out)
	f.Var(&o.tenant, "tenant", "tenant name")
	f.Var(&o.port, "port", "service TCP port")
	f.Var(&o.path, "path", "relative HTTP request path")
	f.Var(&o.bodyFile, "body-file", "regular file with at most256KiB")
	f.Var(&o.scheme, "scheme", "http (default) or https")
	f.Var(&o.timeout, "timeout-ms", "1..30000 (default10000)")
	f.Var(&o.headers, "header", "Content-Type or X-SFC-* NAME=VALUE")
	f.BoolVar(&o.insecure, "insecure-skip-verify", false, "explicitly disable certificate verification for this HTTPS call")
	if f.Parse(args[2:]) != nil || f.NArg() != 0 {
		return o, errors.New("invalid service-call options")
	}
	q, err := o.request()
	if err != nil || !q.Valid() {
		return o, errors.New("invalid service target/path/headers/timeout")
	}
	return o, nil
}
func (o serviceCallOptions) request() (servicecall.Request, error) {
	port, err := strconv.Atoi(o.port.value)
	if err != nil || strconv.Itoa(port) != o.port.value {
		return servicecall.Request{}, errors.New("canonical TCP port required")
	}
	q := servicecall.Request{App: o.app, Service: o.service, Port: port, Path: o.path.value, Method: "POST", Headers: map[string]string(o.headers), Scheme: o.scheme.value, InsecureSkipVerify: o.insecure}
	if o.timeout.set {
		q.TimeoutMS, err = strconv.Atoi(o.timeout.value)
		if err != nil || strconv.Itoa(q.TimeoutMS) != o.timeout.value || q.TimeoutMS <= 0 {
			return q, errors.New("invalid timeout")
		}
	}
	return q, nil
}
func runServiceCall(ctx context.Context, args []string, c userauth.Client, target sfcp.Peer, stored userauth.Stored, defaults cliprofile.Selection, out, diagnostic io.Writer) int {
	o, err := parseServiceCallOptions(args, diagnostic)
	if err != nil {
		return failure(diagnostic, err, 2)
	}
	tenant := o.tenant.value
	if tenant == "" {
		tenant = stored.TargetTenant
		if tenant == "" {
			tenant = stored.Tenant
		}
	}
	tenant, err = defaults.CheckTenant(tenant, "", false)
	if err != nil || tenant == "" {
		return failure(diagnostic, cliprofile.ErrSelection, 2)
	}
	q, err := o.request()
	if err != nil {
		return failure(diagnostic, err, 2)
	}
	if o.bodyFile.set {
		file, err := os.Open(o.bodyFile.value)
		if err != nil {
			return failure(diagnostic, errors.New("cannot open service request body"), 2)
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > servicecall.MaxBody {
			_ = file.Close()
			return failure(diagnostic, errors.New("service request body must be a regular file of at most256KiB"), 2)
		}
		body, readErr := io.ReadAll(io.LimitReader(file, servicecall.MaxBody+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(body) > servicecall.MaxBody {
			return failure(diagnostic, errors.New("service request body read failed"), 2)
		}
		q.Body = body
		defer clear(body)
	}
	result, err := c.CallService(ctx, target, stored.Session, tenant, q)
	if err != nil {
		return userFailure(diagnostic, err)
	}
	if code := userOutput(out, diagnostic, result); code != 0 {
		return code
	}
	if result.Code != "" {
		return 3
	}
	return 0
}
