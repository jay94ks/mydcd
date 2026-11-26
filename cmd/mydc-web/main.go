// SPDX-License-Identifier: Apache-2.0

// mydc-web serves the MyDC web UI and its /api/v1 API. It runs as its own
// container with mydcd's Unix socket mounted in, and talks to mydcd only
// through the internal/web/mydc client interface. It holds no management
// power of its own: every cluster call runs on the logged-in user's session.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jay94ks/mydcd/apps/mydc-web/ui"
	"github.com/jay94ks/mydcd/internal/web/acme"
	"github.com/jay94ks/mydcd/internal/web/ai"
	"github.com/jay94ks/mydcd/internal/web/config"
	"github.com/jay94ks/mydcd/internal/web/dns"
	"github.com/jay94ks/mydcd/internal/web/provlog"
	"github.com/jay94ks/mydcd/internal/web/seal"
	"github.com/jay94ks/mydcd/internal/web/server"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "provider-log" {
		os.Exit(providerLogTool(os.Args[2:], os.Stdout, os.Stderr, os.Getenv))
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("mydc-web", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Parse(os.Args[1:], os.Getenv)
	if err != nil {
		return err
	}
	client, err := newClient(cfg)
	if err != nil {
		return err
	}
	if ok, err := store.ApplyRestore(cfg.DBPath(), cfg.RestorePath(), time.Now()); err != nil {
		return err
	} else if ok {
		log.Warn("restored web data from the staged backup; the previous file was kept beside it")
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()

	box, err := openSeal(cfg, log)
	if err != nil {
		return err
	}

	var static fs.FS = ui.FS()
	if cfg.StaticDir != "" {
		static = os.DirFS(cfg.StaticDir)
	}
	// provider diagnostic log: off until an administrator turns it on
	plog, err := provlog.Open(filepath.Join(cfg.DataDir, "logs"), provlog.Options{})
	if err != nil {
		return err
	}
	defer plog.Close()
	// Certificate authorities (the fake CA is a test double only).
	cas := &acme.Registry{}
	for _, c := range acme.LetsEncrypt(plog) {
		cas.Register(c)
	}
	hide, err := cfg.AIHideModels()
	if err != nil {
		return err
	}
	srv := server.New(server.Options{
		AI:            ai.Endpoints{ClaudeURL: cfg.AIClaudeURL, OpenAIURL: cfg.AIOpenAIURL},
		AIHideModels:  hide,
		Client:        client,
		Store:         st,
		Static:        static,
		CookieSecure:  cfg.CookieSecure,
		LoginTTL:      cfg.LoginTimeout,
		OpRetention:   cfg.OpRetention,
		Logger:        log,
		Seal:          box,
		DataDir:       cfg.DataDir,
		Version:       version,
		DBPath:        cfg.DBPath(),
		SealKeySource: cfg.SealKeySource(),
		Socket:        cfg.Socket,
		DNS:           dns.NewRegistry(plog),
		ACME:          cas,
		ProviderLog:   plog,
		ACMEHTTP01:    cfg.ACMEListen != "",
		ACMEAdvertise: cfg.ACMEAdvertiseAddress(),
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() { srv.Run(ctx); close(done) }()

	hs := &http.Server{Addr: cfg.Listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "socket", cfg.Socket, "tls", cfg.TLSCert != "")
		if cfg.TLSCert != "" {
			errc <- hs.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	if cfg.ACMEListen != "" {
		// plain HTTP: ingress forwards /.well-known/acme-challenge/ here
		as := &http.Server{Addr: cfg.ACMEListen, Handler: srv.ACMEHandler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute}
		go func() {
			log.Info("ACME HTTP-01 responder listening", "addr", cfg.ACMEListen)
			if err := as.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("acme-listen: %w", err)
			}
		}()
		defer as.Close()
	}
	select {
	case err := <-errc:
		stop()
		<-done
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = hs.Shutdown(sctx)
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// openSeal opens the sealed secret folder. A missing or wrong key is not
// fatal: the box reports why and the features that need it stay off. A key
// of the wrong format is a configuration error.
func openSeal(cfg config.Config, log *slog.Logger) (*seal.Box, error) {
	text, err := cfg.ReadSealKey()
	if err != nil {
		return nil, err
	}
	nextText, err := cfg.ReadSealKeyNext()
	if err != nil {
		return nil, err
	}
	os.Unsetenv("MYDC_WEB_SEAL_KEY")
	os.Unsetenv("MYDC_WEB_SEAL_KEY_NEXT")
	key, err := seal.ParseKey(text)
	if err != nil {
		return nil, err
	}
	next, err := seal.ParseKey(nextText)
	if err != nil {
		return nil, fmt.Errorf("MYDC_WEB_SEAL_KEY_NEXT: %w", err)
	}
	if len(next) > 0 && len(key) == 0 {
		return nil, errors.New("MYDC_WEB_SEAL_KEY_NEXT needs MYDC_WEB_SEAL_KEY (the current key)")
	}
	box, err := seal.OpenRekey(cfg.SecretsDir(), key, next)
	if err != nil {
		return nil, err
	}
	if len(next) > 0 && box.Ready() {
		log.Warn("sealed files are now sealed with MYDC_WEB_SEAL_KEY_NEXT; make it MYDC_WEB_SEAL_KEY and remove the old key")
	}
	if st, reason := box.Status(); st != seal.StateReady {
		log.Warn("sealed storage unavailable; AI, external DNS, ACME and notification keys are off", "state", st, "reason", reason)
	}
	return box, nil
}
