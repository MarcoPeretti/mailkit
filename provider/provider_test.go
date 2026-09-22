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

	// Marketo is outbound only and publishes no MX for its customers.
	if _, ok := m.MatchMX("mktomail.com"); ok {
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
		for _, s := range append(append(append(append([]string{}, v.MXSuffixes...), v.SPFSuffixes...), v.DKIMSuffixes...), v.CNAMESuffixes...) {
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
		if len(v.MXSuffixes) == 0 && len(v.SPFSuffixes) == 0 && len(v.DKIMSuffixes) == 0 && len(v.DKIMSelectors) == 0 &&
			len(v.DKIMKeys) == 0 && len(v.CNAMESuffixes) == 0 && len(v.MailFrom) == 0 {
			t.Errorf("%s has no rules and can never match", v.ID)
		}
		if (len(v.DKIMSuffixes) > 0 || len(v.DKIMSelectors) > 0 || len(v.DKIMKeys) > 0 || len(v.MailFrom) > 0) && !v.Outbound {
			t.Errorf("%s has DKIM or MAIL FROM rules but is not marked outbound; both are evidence of sending", v.ID)
		}
		if !v.Inbound && !v.Outbound {
			t.Errorf("%s is marked neither inbound nor outbound", v.ID)
		}
		// An MX rule on an outbound-only vendor is allowed: it names the
		// bounce host of a MAIL FROM subdomain (feedback-smtp.*.amazonses.com,
		// p-pm-bounce-*.mtasv.net), which is sending infrastructure.
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

// A bare TXT key names nobody, but a key the vendor hands every customer
// does. The hash is of the p= value alone, so whitespace and tag order in
// the record do not change it.
func TestSharedKeysNameTheirVendor(t *testing.T) {
	m := Default()
	rec := "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"
	h := KeyHash(rec)
	if len(h) != keyHashLen {
		t.Fatalf("KeyHash = %q, want %d hex characters", h, keyHashLen)
	}
	if KeyHash("k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC; t=s") != h {
		t.Error("the hash depends on tags other than p=")
	}
	if KeyHash("v=DKIM1; k=rsa") != "" {
		t.Error("a record with no key hashed to something")
	}
	if v, ok := m.MatchDKIMKey("a63c243355a7ca90"); !ok || v.ID != "marketo" {
		t.Errorf("MatchDKIMKey(marketo pod key) = %q, %v", v.ID, ok)
	}
	if _, ok := m.MatchDKIMKey(h); ok {
		t.Error("an unknown key matched a vendor")
	}
	_, err := Load([]byte(`[{"id":"a","name":"A","category":"esp","dkim_keys":["nothex"],"outbound":true}]`))
	if err == nil {
		t.Error("a malformed key hash loaded silently")
	}
	_, err = Load([]byte(`[
		{"id":"a","name":"A","category":"esp","dkim_keys":["0000000000000000"],"outbound":true},
		{"id":"b","name":"B","category":"esp","dkim_keys":["0000000000000000"],"outbound":true}]`))
	if err == nil {
		t.Error("two vendors claiming one key loaded silently")
	}
}

// Two vendors on Amazon SES leave no record naming themselves; the label of
// the bounce subdomain is the only trace. The same label with a different
// vendor underneath is not a match.
func TestMailFromLabelsAreReadWithWhatIsUnderneath(t *testing.T) {
	m := Default()
	for _, c := range []struct{ label, on, want string }{
		{"send", "amazon_ses", "resend"},
		{"envelope", "amazon_ses", "loops"},
		{"pm-bounces", "postmark", "postmark"},
		{"mg", "mailgun", "mailgun"},
		{"send", "sendgrid", ""},
		{"send", "", ""},
		{"mail", "amazon_ses", ""},
	} {
		v, ok := m.MatchMailFrom(c.label, c.on)
		if c.want == "" {
			if ok {
				t.Errorf("MatchMailFrom(%q, %q) = %q, want no match", c.label, c.on, v.ID)
			}
			continue
		}
		if !ok || v.ID != c.want {
			t.Errorf("MatchMailFrom(%q, %q) = %q/%v, want %q", c.label, c.on, v.ID, ok, c.want)
		}
	}
	_, err := Load([]byte(`[
		{"id":"a","name":"A","category":"esp","mailfrom":[{"label":"x","on":"z"}],"outbound":true},
		{"id":"b","name":"B","category":"esp","mailfrom":[{"label":"x","on":"z"}],"outbound":true}]`))
	if err == nil {
		t.Error("two vendors claiming one label loaded silently")
	}
}

// The target a customer's subdomain is redirected to names the vendor whose
// guide dictated the redirect.
func TestCNAMETargetsNameTheirVendor(t *testing.T) {
	m := Default()
	for target, want := range map[string]string{
		"pm.mtasv.net":                    "postmark",
		"442-xlc-320.mktoweb.com":         "marketo",
		"cmd.emsend1.com":                 "activecampaign",
		"sendgrid.net":                    "sendgrid",
		"x.freshdesk.com":                 "freshdesk",
		"go.pardot.com":                   "salesforce",
		"abc.outrch.com":                  "outreach",
		"hyx3plhbq22t.stspg-customer.com": "",
	} {
		v, ok := m.MatchCNAME(target)
		if want == "" {
			if ok {
				t.Errorf("MatchCNAME(%q) = %q, want no match", target, v.ID)
			}
			continue
		}
		if !ok || v.ID != want {
			t.Errorf("MatchCNAME(%q) = %q/%v, want %q", target, v.ID, ok, want)
		}
	}
}

// The rules the 2026-09-22 measurement added, each seen in the wild.
func TestSendersFoundOnSubdomainsAreNamed(t *testing.T) {
	m := Default()
	for host, want := range map[string]string{
		"feedback-smtp.us-east-1.amazonses.com":      "amazon_ses",
		"inbound-smtp.eu-west-1.amazonaws.com":       "amazon_ses",
		"p-pm-bounce-smtp01a-aws-useast2a.mtasv.net": "postmark",
		"mx.sendgrid.net":                            "sendgrid",
		"mail-pod-28.int.zendesk.com":                "zendesk",
		"smtp.eu.sparkpostmail.com":                  "sparkpost",
		"mxa.freshdesk.com":                          "freshdesk",
		"mx1.acems1.com":                             "activecampaign",
	} {
		v, ok := m.MatchMX(host)
		if !ok || v.ID != want {
			t.Errorf("MatchMX(%q) = %q/%v, want %q", host, v.ID, ok, want)
		}
	}
	// ec2 hosts are not SES inbound: the SES rule is the exact regional name.
	if v, ok := m.MatchMX("ec2-1-2-3-4.compute-1.amazonaws.com"); ok {
		t.Errorf("an EC2 host matched %q", v.ID)
	}
	for cname, want := range map[string]string{
		"dkim.acdkim1.acems1.com":                               "activecampaign",
		"ml02.dkim.musvc.com":                                   "mailup",
		"543e9a9d-b89f-4ac1-b2b8-c5305335177c.dkim.intercom.io": "intercom",
		"sig1.dkim.example.com.at.icloudmailadmin.com":          "apple_icloud",
	} {
		v, ok := m.MatchDKIM(cname)
		if !ok || v.ID != want {
			t.Errorf("MatchDKIM(%q) = %q/%v, want %q", cname, v.ID, ok, want)
		}
	}
	for sel, want := range map[string]string{"resend": "resend", "acdkim1": "activecampaign", "m1": "marketo", "intercom": "intercom", "mte2": "mandrill", "ctct1": "constantcontact", "sig1": "apple_icloud"} {
		v, ok := m.MatchDKIMSelector(sel)
		if !ok || v.ID != want {
			t.Errorf("MatchDKIMSelector(%q) = %q/%v, want %q", sel, v.ID, ok, want)
		}
	}
}
