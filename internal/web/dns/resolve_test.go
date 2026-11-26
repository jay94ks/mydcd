// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"testing"

	mdns "github.com/miekg/dns"
)

func TestWantMatchesAnswerForm(t *testing.T) {
	mx := &RRSet{Name: "@", Type: "MX", Records: []Record{{Content: "Mail.Example.com.", Priority: 10}}}
	rr, _ := mdns.NewRR("example.com. 300 IN MX 10 mail.example.com.")
	if got, want := answerValue(rr), WantValues(mx); !SameValues([]string{got}, want) {
		t.Fatalf("mx: %q vs %v", got, want)
	}
	a := &RRSet{Name: "shop", Type: "A", Records: []Record{{Content: "203.0.113.11"}, {Content: "203.0.113.10"}}}
	if !SameValues([]string{"203.0.113.10", "203.0.113.11"}, WantValues(a)) || SameValues([]string{"203.0.113.10"}, WantValues(a)) {
		t.Fatal("a sets")
	}
	txt, _ := mdns.NewRR(`example.com. 60 IN TXT "v=spf1 " "-all"`)
	if answerValue(txt) != "v=spf1 -all" {
		t.Fatalf("txt: %q", answerValue(txt))
	}
	if len(WantValues(nil)) != 0 {
		t.Fatal("absent")
	}
}
