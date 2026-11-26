// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Owned native-test commands. The product exec engine has no knowledge of
// these protocols or paths; the same image intentionally contains no shell.
func execFixture(args []string) bool {
	if len(args) < 2 {
		return false
	}
	switch args[1] {
	case "--exec-args-fixture":
		_ = json.NewEncoder(os.Stdout).Encode(args[2:])
		return true
	case "--exec-burst-fixture":
		for range 64 {
			if _, err := fmt.Fprintln(os.Stdout, strings.Repeat("B", 16<<10)); err != nil {
				return true
			}
		}
		return true
	case "--exec-detach-fixture":
		fmt.Fprintln(os.Stdout, "exec-detach-ready")
		time.Sleep(30 * time.Second)
		return true
	case "--exec-closed-output-fixture":
		fmt.Fprintln(os.Stdout, "exec-output-closing")
		_ = os.Stdout.Close()
		_ = os.Stderr.Close()
		time.Sleep(30 * time.Second)
		return true
	case "--exec-io-fixture":
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt)
		defer signal.Stop(interrupt)
		go func() { <-interrupt; os.Exit(130) }()
		fmt.Fprintln(os.Stdout, "exec-io-ready")
		reader := bufio.NewScanner(os.Stdin)
		for reader.Scan() {
			line := reader.Text()
			if line == "size" {
				var size struct{ Rows, Cols, X, Y uint16 }
				_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&size)))
				if errno != 0 {
					fmt.Fprintln(os.Stdout, "size unavailable")
				} else {
					fmt.Fprintf(os.Stdout, "SIZE %d %d\n", size.Rows, size.Cols)
				}
				continue
			}
			if strings.HasPrefix(line, "exit ") {
				n, err := strconv.Atoi(strings.TrimPrefix(line, "exit "))
				if err == nil && n >= 0 && n <= 255 {
					os.Exit(n)
				}
			}
			fmt.Fprintln(os.Stdout, "OUT "+line)
			fmt.Fprintln(os.Stderr, "ERR "+line)
		}
		if reader.Err() != nil {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "exec-stdin-eof")
		return true
	}
	return false
}
