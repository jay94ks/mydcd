// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bufio"
	"net"
	"net/netip"
	"testing"
)

// The node.yaml port forwards to the app while set, and closes when the
// port is removed.
func TestClusterAppPortForwardsAndCloses(t *testing.T) {
	app, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	go func() {
		for {
			c, err := app.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				_, _ = c.Write([]byte("web:" + line))
			}()
		}
	}()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := free.Addr().String()
	free.Close()
	target := netip.MustParseAddrPort(app.Addr().String())
	var p clusterAppPort
	defer p.close()
	if err := p.set(listen, target); err != nil {
		t.Fatal(err)
	}
	if err := p.set(listen, target); err != nil {
		t.Fatal("the same port again", err)
	}
	c, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("hi\n"))
	got, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if got != "web:hi\n" {
		t.Fatalf("%q", got)
	}
	if err := p.set("", target); err != nil {
		t.Fatal(err)
	}
	if c, err := net.Dial("tcp", listen); err == nil {
		c.Close()
		t.Fatal("the port stayed open")
	}
	if got := clusterAppListen("192.0.2.10:7443", 8443); got != "192.0.2.10:8443" {
		t.Fatal(got)
	}
	if got := clusterAppListen("192.0.2.10:7443", 0); got != "" {
		t.Fatal(got)
	}
}
