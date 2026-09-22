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
		for _, s := range append(append(append([]string{}, v.MXSuffixes...), v.SPFSuffixes...), v.DKIMSuffixes...) {
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
		if len(v.MXSuffixes) == 0 && len(v.SPFSuffixes) == 0 && len(v.DKIMSuffixes) == 0 && len(v.DKIMSelectors) == 0 {
			t.Errorf("%s has no rules and can never match", v.ID)
		}
		if (len(v.DKIMSuffixes) > 0 || len(v.DKIMSelectors) > 0) && !v.Outbound {
			t.Errorf("%s has DKIM rules but is not marked outbound; a DKIM key is evidence of sending", v.ID)
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

// The targets this table was grown from, taken from the ranked queue a ten
// thousand domain crawl produced. Each one is a real include seen in the wild,
// so a regression here means a provider silently stopped being recognised.
func TestGrownFromRealObservations(t *testing.T) {
	m := Default()
	cases := map[string]string{
		"spf.mailjet.com":                "mailjet",
		"_spf.mx.cloudflare.net":         "cloudflare",
		"relay.mailchannels.net":         "mailchannels",
		"et._spf.pardot.com":             "salesforce",
		"aspmx.pardot.com":               "salesforce",
		"zcsend.net":                     "zoho",
		"zeptomail.net":                  "zoho",
		"spf.efwd.registrar-servers.com": "namecheap_forwarding",
		"_spf-ipv4-yc-a.yandex.ru":       "yandex",
		"_spf.mlsend.com":                "mailerlite",
		"biz-c.mail.qq.com":              "tencent_qq",
		"spf-0.secureserver.net":         "godaddy",
		"a.hichina.mail.aliyun.com":      "alibaba",
		"helpscoutemail.com":             "helpscout",
		"_spf.psm.knowbe4.com":           "knowbe4",
		"spf1.m.feishu.cn":               "feishu",
		"_spf-eu.ionos.com":              "ionos",
		"_spf.elasticemail.com":          "elasticemail",
		"_spf.atlassian.net":             "atlassian",
		"stspg-customer.com":             "atlassian",
		"_spf2.protonmail.ch":            "protonmail",
		"spf.unisender.com":              "unisender",
		"_spf.firebasemail.com":          "firebase",
		"_spf.createsend.com":            "campaignmonitor",
		"shops.shopify.com":              "shopify",
		"_spf.qualtrics.com":             "qualtrics",
	}
	for target, want := range cases {
		v, ok := m.MatchSPF(target)
		if !ok {
			t.Errorf("MatchSPF(%q) found nothing, want %s", target, want)
			continue
		}
		if v.ID != want {
			t.Errorf("MatchSPF(%q) = %s, want %s", target, v.ID, want)
		}
	}
}

// Broadening a rule to catch sub-includes must not broaden it past the
// organisation that owns it.
func TestGrownRulesStayWithinTheirOwner(t *testing.T) {
	m := Default()
	for _, target := range []string{
		"notyandex.ru", "evil-qq.com", "fakesecureserver.net",
		"mailjet.com.attacker.example", "shopify.com.evil.example",
	} {
		if v, ok := m.MatchSPF(target); ok {
			t.Errorf("MatchSPF(%q) matched %q; a broadened rule reached past its owner", target, v.ID)
		}
	}
}

// A domain already paying for DMARC management has a vendor for the problem
// this module detects, which is worth telling apart from one that has never
// looked.
func TestAuthenticationVendorsAreIdentified(t *testing.T) {
	m := Default()
	for target, want := range map[string]string{
		"%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email": "valimail",
		"spf.easydmarc.com":                        "easydmarc",
		"_spf.dmarcian.com":                        "dmarcian",
	} {
		v, ok := m.MatchSPF(target)
		if !ok || v.ID != want {
			t.Errorf("MatchSPF(%q) = %q/%v, want %s", target, v.ID, ok, want)
			continue
		}
		if v.Category != CategoryAuthentication {
			t.Errorf("%s category = %q, want %q", v.ID, v.Category, CategoryAuthentication)
		}
	}
}

// A DKIM key is a bare public key; the vendor is named by the CNAME target,
// or by a selector name that belongs to one vendor and no other.
func TestDKIMIsAttributedByTargetOrByOwnedSelector(t *testing.T) {
	m := Default()
	for cname, want := range map[string]string{
		"dkim.mcsv.net":                            "mailchimp",
		"s1.domainkey.u123.wl.sendgrid.net":        "sendgrid",
		"selector1-x._domainkey.x.onmicrosoft.com": "microsoft365",
		"mandrill._domainkey.mandrillapp.com":      "mandrill",
		"hs1-123.dkim.hubspotemail.net":            "hubspot",
	} {
		v, ok := m.MatchDKIM(cname)
		if !ok || v.ID != want {
			t.Errorf("MatchDKIM(%q) = %q, %v; want %q", cname, v.ID, ok, want)
		}
	}
	if _, ok := m.MatchDKIM("evilmcsv.net"); ok {
		t.Error("a DKIM suffix matched past a label boundary")
	}
	for sel, want := range map[string]string{"google": "google_workspace", "mandrill": "mandrill", "hs1": "hubspot", "K2": "mailchimp"} {
		v, ok := m.MatchDKIMSelector(sel)
		if !ok || v.ID != want {
			t.Errorf("MatchDKIMSelector(%q) = %q, %v; want %q", sel, v.ID, ok, want)
		}
	}
	// Shared selectors are not owned by anyone.
	for _, sel := range []string{"k1", "s1", "s2", "default", "mail", "dkim"} {
		if v, ok := m.MatchDKIMSelector(sel); ok {
			t.Errorf("selector %q is attributed to %q, but more than one vendor uses it", sel, v.ID)
		}
	}
}

func TestDuplicateDKIMSelectorIsRejected(t *testing.T) {
	_, err := Load([]byte(`[
		{"id":"a","name":"A","category":"esp","spf":["a.example"],"dkim_selectors":["x1"],"outbound":true},
		{"id":"b","name":"B","category":"esp","spf":["b.example"],"dkim_selectors":["x1"],"outbound":true}]`))
	if err == nil {
		t.Fatal("two vendors claiming one selector loaded silently")
	}
}
