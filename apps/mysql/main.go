// SPDX-License-Identifier: Apache-2.0

// mysqlapp is the real sample application's nonroot bootstrap/health command.
// Seafield Cluster still owns its container, writer gate, Volume and Secret lifecycle.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const socket = "/run/sfc/mysql.sock"
const clientFile = "/run/sfc/client.cnf"

func serverArgs() []string {
	return []string{"--no-defaults", "--datadir=/var/lib/mysql", "--socket=" + socket, "--pid-file=/run/sfc/mysql.pid", "--tmpdir=/tmp", "--mysqlx=OFF", "--skip-log-bin", "--innodb-buffer-pool-size=64M", "--innodb-redo-log-capacity=16M", "--max-connections=16", "--performance-schema=OFF", "--skip-name-resolve"}
}
func secret(name string) ([]byte, error) {
	b, err := os.ReadFile("/run/secrets/" + name)
	if err != nil || len(b) < 16 || len(b) > 128 {
		return nil, fmt.Errorf("protected input unavailable")
	}
	// The sample uses generated base64url credentials; no SQL/config quoting
	// ambiguity or credentials in an argv/env/log is permitted.
	for _, c := range b {
		if c != '-' && c != '_' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			clear(b)
			return nil, fmt.Errorf("invalid protected input")
		}
	}
	return b, nil
}
func sql(ctx context.Context, initial bool, input []byte) error {
	args := []string{"--defaults-extra-file=" + clientFile, "--protocol=socket", "--socket=" + socket, "--batch", "--skip-column-names"}
	if initial {
		args = []string{"--no-defaults", "--user=root", "--protocol=socket", "--socket=" + socket, "--batch", "--skip-column-names"}
	}
	c := exec.CommandContext(ctx, "mysql", args...)
	c.Stdin = bytes.NewReader(input)
	// Do not log SQL or client diagnostics containing private input.
	return c.Run()
}
func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if len(os.Args) == 2 && os.Args[1] == "--health" {
		c, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		return sql(c, false, []byte("SELECT 1 FROM sfc.records LIMIT 1;"))
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("explicit nonroot user required")
	}
	root, err := secret("db-root-password")
	if err != nil {
		return err
	}
	defer clear(root)
	password, err := secret("db-password")
	if err != nil {
		return err
	}
	defer clear(password)
	config := append([]byte("[client]\nuser=root\npassword="), root...)
	config = append(config, '\n')
	defer clear(config)
	if err = os.WriteFile(clientFile, config, 0600); err != nil {
		return err
	}
	mysqld, err := exec.LookPath("mysqld")
	if err != nil {
		return err
	}
	if _, err = os.Stat("/var/lib/mysql/mysql"); os.IsNotExist(err) {
		initArgs := append(serverArgs(), "--initialize-insecure")
		init := exec.CommandContext(ctx, mysqld, initArgs...)
		init.Stdout = os.Stdout
		init.Stderr = os.Stderr
		if err = init.Run(); err != nil {
			return fmt.Errorf("offline data initialization failed")
		}
		args := append(serverArgs(), "--skip-networking=ON")
		child := exec.CommandContext(ctx, mysqld, args...)
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err = child.Start(); err != nil {
			return err
		}
		done := make(chan error, 1)
		go func() { done <- child.Wait() }()
		joined := false
		defer func() {
			if !joined {
				_ = child.Process.Kill()
				<-done
			}
		}()
		deadline := time.NewTimer(30 * time.Second)
		defer deadline.Stop()
		ready := false
		for !ready {
			probe, stop := context.WithTimeout(ctx, time.Second)
			err = sql(probe, true, []byte("SELECT 1;"))
			stop()
			if err == nil {
				ready = true
				break
			}
			select {
			case err := <-done:
				joined = true
				return fmt.Errorf("private initializer exited: %v", err)
			case <-ctx.Done():
				return ctx.Err()
			case <-deadline.C:
				return fmt.Errorf("private SQL initialization unavailable")
			case <-time.After(50 * time.Millisecond):
			}
		}
		setup := []byte("CREATE DATABASE sfc; CREATE TABLE sfc.records(id VARCHAR(64) PRIMARY KEY,value MEDIUMBLOB NOT NULL) ENGINE=InnoDB; CREATE TABLE sfc.operations(operation_id VARCHAR(64) PRIMARY KEY,payload_hash CHAR(64) NOT NULL,result MEDIUMBLOB NULL) ENGINE=InnoDB; CREATE USER 'sfc'@'%' IDENTIFIED BY '")
		setup = append(setup, password...)
		setup = append(setup, []byte("'; GRANT SELECT,INSERT,UPDATE,DELETE ON sfc.* TO 'sfc'@'%'; ALTER USER 'root'@'localhost' IDENTIFIED BY '")...)
		setup = append(setup, root...)
		setup = append(setup, []byte("';\n")...)
		err = sql(ctx, true, setup)
		clear(setup)
		if err != nil {
			return fmt.Errorf("private SQL setup failed")
		}
		if err = child.Process.Signal(syscall.SIGTERM); err != nil {
			return err
		}
		select {
		case err = <-done:
			joined = true
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
		marker, err := os.OpenFile("/var/lib/mysql/.sfc-app-initialized", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = marker.Write([]byte("1\n"))
		if err == nil {
			err = marker.Sync()
		}
		closeErr := marker.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		dir, err := os.Open("/var/lib/mysql")
		if err != nil {
			return err
		}
		err = dir.Sync()
		_ = dir.Close()
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	// Existing datadirs are never initialized or assigned new credentials.
	marker, err := os.ReadFile("/var/lib/mysql/.sfc-app-initialized")
	if err != nil || string(marker) != "1\n" {
		return fmt.Errorf("incomplete offline initialization requires explicit recovery")
	}
	args := append([]string{filepath.Base(mysqld)}, serverArgs()...)
	args = append(args, "--bind-address=0.0.0.0")
	env := os.Environ()
	for _, v := range env {
		if strings.HasPrefix(v, "MYSQL_ROOT_PASSWORD=") {
			return fmt.Errorf("credential env forbidden")
		}
	}
	return syscall.Exec(mysqld, args, env)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sample mysql startup/health failed")
		os.Exit(1)
	}
}
