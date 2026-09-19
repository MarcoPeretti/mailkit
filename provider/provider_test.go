package provider

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

func TestEmbeddedTableLoads(t *testing.T) {
	// Load already rejects duplicate suffixes, unknown categories and missing
	// ids, so simply reaching here proves the shipped table satisfies all three.
	if len(Default().All()) == 0 {
		t.Fatal("the embedded vendor table is empty")
	}
}

// The single most dangerous bug in this package would be matching part of a
// label: it would attribute a stranger's infrastructure to the domain being
// scanned, in a report sent to that domain's owner.
func TestSuffixRespectsLabelBoundary(t *testing.T) {
	m := Default()

	cases := []struct {
		name, target string
		wantID       string // "" means no match
	}{
		{"exact", "sendgrid.net", "sendgrid"},
		{"subdomain", "u123.wl.sendgrid.net", "sendgrid"},
		{"trailing dot", "sendgrid.net.", "sendgrid"},
		{"uppercase", "SendGrid.NET", "sendgrid"},
		// The ones that must NOT match. strings.HasSuffix says true for all of
		// these.
		{"prefixed label", "notsendgrid.net", ""},
		{"evil parent", "sendgrid.net.evil.example", ""},
		{"substring only", "mysendgrid.net", ""},
		{"unknown", "some-random-host.example", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, ok := m.MatchSPF(c.target)
			if c.wantID == "" {
				if ok {
					t.Fatalf("MatchSPF(%q) matched %q, want no match", c.target, v.ID)
				}
				return
			}
			if !ok || v.ID != c.wantID {
				t.Fatalf("MatchSPF(%q) = %q/%v, want %q", c.target, v.ID, ok, c.wantID)
			}
		})
	}
}

func TestLongestSuffixWins(t *testing.T) {
	table := []byte(`[
	  {"id":"parent","name":"Parent","category":"esp","spf":["example.com"],"outbound":true},
	  {"id":"child","name":"Child","category":"esp","spf":["mail.example.com"],"outbound":true}
	]`)
	m, err := Load(table)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := m.MatchSPF("mail.example.com"); v.ID != "child" {
		t.Errorf("got %q, want the more specific rule to win", v.ID)
	}
	if v, _ := m.MatchSPF("other.example.com"); v.ID != "parent" {
		t.Errorf("got %q, want the parent rule", v.ID)
	}
}

// MX and SPF are separate tables on purpose: an MX host must never be able to
// answer the question "who sends as this domain".
func TestMXAndSPFTablesAreSeparate(t *testing.T) {
	m := Default()

	// Microsoft's inbound host is an MX rule only.
	if _, ok := m.MatchSPF("mail.protection.outlook.com"); ok {
		t.Error("an inbound MX host matched as an outbound SPF target")
	}
	if v, ok := m.MatchMX("acme-com.mail.protection.outlook.com"); !ok || v.ID != "microsoft365" {
		t.Errorf("MatchMX gave %q/%v, want microsoft365", v.ID, ok)
	}

	// SendGrid is outbound only and publishes no MX for its customers.
	if _, ok := m.MatchMX("sendgrid.net"); ok {
		t.Error("an outbound-only ESP matched as an inbound MX provider")
	}
}

func TestDuplicateSuffixIsRejected(t *testing.T) {
	_, err := Load([]byte(`[
	  {"id":"a","name":"A","category":"esp","spf":["shared.example"],"outbound":true},
	  {"id":"b","name":"B","category":"esp","spf":["shared.example"],"outbound":true}
	]`))
	if err == nil {
		t.Fatal("two vendors claiming one suffix must be a load error, not a silent last-wins")
	}
	if !strings.Contains(err.Error(), "shared.example") {
		t.Errorf("error should name the contested suffix: %v", err)
	}
}

func TestUnknownCategoryIsRejected(t *testing.T) {
	_, err := Load([]byte(`[{"id":"a","name":"A","category":"emails","spf":["a.example"]}]`))
	if err == nil {
		t.Fatal("an unrecognised category must be a load error")
	}
}

// A rule that is a bare public suffix, or has no dot at all, would match a huge
// share of the internet and attribute it to one vendor.
func TestNoRuleIsTooBroad(t *testing.T) {
	for _, v := range Default().All() {
		for _, s := range append(append([]string{}, v.MXSuffixes...), v.SPFSuffixes...) {
			if !strings.Contains(s, ".") {
				t.Errorf("%s: rule %q has no dot and would match a whole TLD", v.ID, s)
			}
			if strings.Count(s, ".") == 1 && strings.HasPrefix(s, ".") {
				t.Errorf("%s: rule %q is malformed", v.ID, s)
			}
		}
	}
}

// Sorted by id, so that a diff adding a vendor is one hunk in a predictable
// place rather than a reshuffle nobody reviews.
func TestVendorsJSONIsSortedByID(t *testing.T) {
	var vs []Provider
	if err := json.Unmarshal(providersJSON, &vs); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(vs))
	for i, v := range vs {
		ids[i] = v.ID
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("vendors.json is not sorted by id: %v", ids)
	}
}

// Every vendor must be reachable from at least one direction, or it is dead
// weight that will never match anything.
func TestEveryVendorIsReachable(t *testing.T) {
	for _, v := range Default().All() {
		if len(v.MXSuffixes) == 0 && len(v.SPFSuffixes) == 0 {
			t.Errorf("%s has no suffixes and can never match", v.ID)
		}
		if !v.Inbound && !v.Outbound {
			t.Errorf("%s is marked neither inbound nor outbound", v.ID)
		}
		if len(v.MXSuffixes) > 0 && !v.Inbound {
			t.Errorf("%s has MX rules but is not marked inbound", v.ID)
		}
	}
}

func TestForwardingVendorsAreIdentified(t *testing.T) {
	m := Default()
	// A domain whose only MX is registrar forwarding has no mail provider at
	// all, which is a stronger qualifying signal than any ESP.
	for _, host := range []string{
		"eforward1.registrar-servers.com",
		"mx1.forwardemail.net",
		"mx2.improvmx.com",
	} {
		v, ok := m.MatchMX(host)
		if !ok {
			t.Errorf("MatchMX(%q) found nothing", host)
			continue
		}
		if v.Category != CategoryForwarding {
			t.Errorf("MatchMX(%q) = %q with category %q, want %q", host, v.ID, v.Category, CategoryForwarding)
		}
	}
}
