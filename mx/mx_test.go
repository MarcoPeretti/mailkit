package mx

import (
	"context"
	"testing"

	"github.com/MarcoPeretti/mailkit/dnsx/dnstest"
)

func TestGoogleWorkspaceDomain(t *testing.T) {
	z := dnstest.Zone{
		MX: map[string][]dnstest.MXEntry{
			"example.com": {
				{Host: "alt2.aspmx.l.google.com", Pref: 10},
				{Host: "aspmx.l.google.com", Pref: 1},
				{Host: "alt1.aspmx.l.google.com", Pref: 5},
			},
		},
		A: map[string][]string{
			"aspmx.l.google.com":      {"142.250.1.26"},
			"alt1.aspmx.l.google.com": {"142.250.1.27"},
			"alt2.aspmx.l.google.com": {"142.250.1.28"},
		},
	}
	hosts, f := Lookup(context.Background(), dnstest.New(z), "example.com")

	if f.Incomplete || f.Missing || f.Null || f.SingleHost {
		t.Fatalf("flags = %+v", f)
	}
	want := []string{"aspmx.l.google.com", "alt1.aspmx.l.google.com", "alt2.aspmx.l.google.com"}
	got := Hosts(hosts)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hosts = %v, want %v (sorted by preference, then name)", got, want)
		}
	}
}

// The resolver deliberately shuffles equal-preference records. A description
// that changes between runs is not a description: it makes a domain look edited
// on every scan while nobody has touched DNS.
func TestOrderIsCanonicalNotResolverOrder(t *testing.T) {
	mk := func(entries []dnstest.MXEntry) []string {
		z := dnstest.Zone{
			MX: map[string][]dnstest.MXEntry{"example.com": entries},
			A: map[string][]string{
				"mx-a.example.com": {"192.0.2.2", "192.0.2.1"},
				"mx-b.example.com": {"192.0.2.3"},
			},
		}
		hosts, _ := Lookup(context.Background(), dnstest.New(z), "example.com")
		return Hosts(hosts)
	}

	// Same records, two arrival orders, at equal preference.
	one := mk([]dnstest.MXEntry{{Host: "mx-b.example.com", Pref: 10}, {Host: "mx-a.example.com", Pref: 10}})
	two := mk([]dnstest.MXEntry{{Host: "mx-a.example.com", Pref: 10}, {Host: "mx-b.example.com", Pref: 10}})

	if one[0] != two[0] || one[1] != two[1] {
		t.Fatalf("order depends on the resolver: %v vs %v", one, two)
	}
	if one[0] != "mx-a.example.com" {
		t.Errorf("equal preferences should break ties by name, got %v", one)
	}

	// Addresses are rotated by resolvers for the same reason, and get the same
	// treatment.
	z := dnstest.Zone{
		MX: map[string][]dnstest.MXEntry{"example.com": {{Host: "mx-a.example.com", Pref: 10}}},
		A:  map[string][]string{"mx-a.example.com": {"192.0.2.2", "192.0.2.1"}},
	}
	hosts, _ := Lookup(context.Background(), dnstest.New(z), "example.com")
	if hosts[0].IPs[0] != "192.0.2.1" {
		t.Errorf("addresses not sorted: %v", hosts[0].IPs)
	}
}

// RFC 5321 section 5.1: no MX means the domain's own address record is the
// implicit MX. Reporting such a domain as having no mail routing would be wrong.
func TestImplicitMX(t *testing.T) {
	z := dnstest.Zone{A: map[string][]string{"example.com": {"192.0.2.1"}}}
	hosts, f := Lookup(context.Background(), dnstest.New(z), "example.com")

	if f.Missing {
		t.Error("a domain with an address record is not missing mail routing")
	}
	if !f.Implicit || len(hosts) != 1 || !hosts[0].Implicit {
		t.Fatalf("hosts = %+v, flags = %+v", hosts, f)
	}
}

func TestNullMX(t *testing.T) {
	z := dnstest.Zone{MX: map[string][]dnstest.MXEntry{"example.com": {{Host: ".", Pref: 0}}}}
	hosts, f := Lookup(context.Background(), dnstest.New(z), "example.com")

	if !f.Null {
		t.Error("a single \".\" target is RFC 7505's null MX")
	}
	if f.Missing {
		t.Error("null MX is a deliberate declaration, not missing configuration")
	}
	if len(hosts) != 0 {
		t.Errorf("hosts = %+v, want none", hosts)
	}
}

func TestMissingWhenNeitherMXNorAddress(t *testing.T) {
	_, f := Lookup(context.Background(), dnstest.New(dnstest.Zone{}), "absent.example")
	if !f.Missing {
		t.Error("a domain with neither MX nor address records has nowhere for mail to go")
	}
	if f.Incomplete {
		t.Error("NXDOMAIN is an answer, not a failure to ask")
	}
}

func TestIPLiteralAndUnresolvableTargets(t *testing.T) {
	z := dnstest.Zone{
		MX: map[string][]dnstest.MXEntry{"example.com": {
			{Host: "192.0.2.5", Pref: 10},
			{Host: "gone.example.com", Pref: 20},
			{Host: "ok.example.com", Pref: 30},
		}},
		A: map[string][]string{"ok.example.com": {"192.0.2.9"}},
	}
	_, f := Lookup(context.Background(), dnstest.New(z), "example.com")

	if len(f.IPLiteral) != 1 || f.IPLiteral[0] != "192.0.2.5" {
		t.Errorf("IPLiteral = %v", f.IPLiteral)
	}
	if len(f.Unresolvable) != 1 || f.Unresolvable[0] != "gone.example.com" {
		t.Errorf("Unresolvable = %v", f.Unresolvable)
	}
	if f.Incomplete {
		t.Error("every lookup answered; nothing here is incomplete")
	}
}

// Our own network trouble must never be reported as the domain's problem.
func TestLookupFailureIsIncompleteNotMissing(t *testing.T) {
	z := dnstest.Zone{Fail: map[string]string{"example.com": dnstest.FailServFail}}
	_, f := Lookup(context.Background(), dnstest.New(z), "example.com")

	if !f.Incomplete {
		t.Error("a failed lookup must set Incomplete")
	}
	if f.Missing || f.Null {
		t.Errorf("flags = %+v; nothing may be asserted about a domain we could not ask about", f)
	}
	if f.Error == "" {
		t.Error("Incomplete should carry why")
	}
}
