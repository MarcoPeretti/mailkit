package mailauth

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// fakeResolver serves TXT records from a fixed map, returning a DNS "not found"
// error for anything absent so callers exercise the same path as production.
// These tests came from unspam's internal/mailauth unmodified. The ones that
// exercised Diagnose or ExplainDelivery stayed behind, with the prose catalogue
// they render through. Passing the rest without edits is the evidence that the
// move was faithful.

type fakeResolver map[string][]string

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if txt, ok := f[strings.TrimSuffix(name, ".")]; ok {
		return txt, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func TestParseSPF(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantAll     string
		wantLookups int
	}{
		{"strict", "v=spf1 include:_spf.google.com -all", "-", 1},
		{"softfail", "v=spf1 a mx include:mailgun.org ~all", "~", 3},
		{"open relay", "v=spf1 +all", "+", 0},
		{"unqualified all defaults to pass", "v=spf1 all", "+", 0},
		{"neutral", "v=spf1 ip4:1.2.3.4 ?all", "?", 0},
		{"no all", "v=spf1 ip4:1.2.3.4", "", 0},
		{"redirect costs a lookup", "v=spf1 redirect=_spf.example.com", "", 1},
		{"ip mechanisms are free", "v=spf1 ip4:1.2.3.4 ip6:::1 -all", "-", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := ParseSPF(tc.raw)
			if err != nil {
				t.Fatalf("ParseSPF: %v", err)
			}
			if rec.All != tc.wantAll {
				t.Errorf("All = %q, want %q", rec.All, tc.wantAll)
			}
			if rec.Lookups != tc.wantLookups {
				t.Errorf("Lookups = %d, want %d", rec.Lookups, tc.wantLookups)
			}
		})
	}
	if _, err := ParseSPF("v=spf2 whatever"); err == nil {
		t.Error("ParseSPF accepted a non-SPF record")
	}
}

func TestParseDMARCDefaults(t *testing.T) {
	rec, err := ParseDMARC("v=DMARC1; p=quarantine")
	if err != nil {
		t.Fatalf("ParseDMARC: %v", err)
	}
	// The RFC 9989 §4.7 defaults must be applied, or every downstream check
	// silently uses the wrong mode.
	if rec.Pct != 100 {
		t.Errorf("Pct = %d, want default 100", rec.Pct)
	}
	if rec.ADKIM != "r" || rec.ASPF != "r" {
		t.Errorf("alignment = adkim %q aspf %q, want relaxed defaults", rec.ADKIM, rec.ASPF)
	}
}

func TestParseDMARCFull(t *testing.T) {
	rec, err := ParseDMARC("v=DMARC1; p=reject; sp=none; pct=50; adkim=s; aspf=s; rua=mailto:a@x.com,mailto:b@x.com")
	if err != nil {
		t.Fatalf("ParseDMARC: %v", err)
	}
	if rec.Policy != "reject" || rec.SubPolicy != "none" || rec.Pct != 50 {
		t.Errorf("got policy=%q sp=%q pct=%d", rec.Policy, rec.SubPolicy, rec.Pct)
	}
	if rec.ADKIM != "s" || rec.ASPF != "s" {
		t.Errorf("alignment = %q/%q, want strict", rec.ADKIM, rec.ASPF)
	}
	if len(rec.RUA) != 2 {
		t.Errorf("RUA = %v, want 2 addresses", rec.RUA)
	}
}

func TestParseDKIMRevoked(t *testing.T) {
	rec, err := ParseDKIM("s1", "v=DKIM1; k=rsa; p=")
	if err != nil {
		t.Fatalf("ParseDKIM: %v", err)
	}
	if !rec.Revoked {
		t.Error("Revoked = false; an empty p= tag withdraws the key")
	}
	if _, err := ParseDKIM("s1", "v=DKIM1; k=rsa"); err == nil {
		t.Error("ParseDKIM accepted a record with no p= tag")
	}
}

func TestParseDKIMTestingMode(t *testing.T) {
	rec, err := ParseDKIM("s1", "v=DKIM1; k=rsa; t=y; p=MIIBIjAN")
	if err != nil {
		t.Fatalf("ParseDKIM: %v", err)
	}
	if !rec.Testing {
		t.Error("Testing = false, want true for t=y")
	}
}

func TestLookupSPFNoRecord(t *testing.T) {
	r := fakeResolver{"x.com": {"some-unrelated-txt-record"}}
	if _, err := LookupSPF(context.Background(), r, "x.com"); !errors.Is(err, ErrNoRecord) {
		t.Errorf("err = %v, want ErrNoRecord", err)
	}
}

func TestAligned(t *testing.T) {
	// Where each organization begins is what these two records say, not what
	// a suffix list says: acme.co.uk aligns with its subdomain because it
	// publishes a record, not because co.uk is on a list.
	r := fakeResolver{
		"_dmarc.acme.com":   {"v=DMARC1; p=reject"},
		"_dmarc.acme.co.uk": {"v=DMARC1; p=reject"},
	}
	cases := []struct {
		from, auth, mode string
		want             bool
	}{
		{"acme.com", "acme.com", "r", true},
		{"acme.com", "acme.com", "s", true},
		{"acme.com", "mail.acme.com", "r", true},  // relaxed compares org domains
		{"acme.com", "mail.acme.com", "s", false}, // strict requires exact match
		{"acme.com", "sendgrid.net", "r", false},
		{"acme.co.uk", "mail.acme.co.uk", "r", true}, // multi-label public suffix
		{"acme.com", "", "r", false},
	}
	for _, tc := range cases {
		got, err := NewAligner(r).Aligned(context.Background(), tc.from, tc.auth, tc.mode)
		if err != nil {
			t.Fatalf("Aligned(%q,%q,%q): %v", tc.from, tc.auth, tc.mode, err)
		}
		if got != tc.want {
			t.Errorf("Aligned(%q,%q,%q) = %v, want %v", tc.from, tc.auth, tc.mode, got, tc.want)
		}
	}
}

// explain runs ExplainDelivery for a From domain that publishes a policy and
// nothing else, so every other name is its own organization and only a name
// at or under the From domain aligns with it.
func TestDMARCInheritedFromOrgDomain(t *testing.T) {
	f := fakeResolver{
		"_dmarc.example.com": {"v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com"},
	}
	rec, err := LookupDMARC(context.Background(), f, "mail.example.com")
	if err != nil {
		t.Fatalf("LookupDMARC: %v", err)
	}
	if rec.InheritedFrom != "example.com" {
		t.Errorf("InheritedFrom = %q, want example.com", rec.InheritedFrom)
	}
	// sp= exists to say what subdomains get, so it is the policy in force here.
	if rec.Policy != "quarantine" {
		t.Errorf("Policy = %q, want quarantine from sp=", rec.Policy)
	}
}

// TestDMARCAtOrgDomainIsNotInherited: an org domain with no record has none.
// The fallback must not invent one by climbing past the registrable domain.
func TestDMARCAtOrgDomainIsNotInherited(t *testing.T) {
	f := fakeResolver{}
	if _, err := LookupDMARC(context.Background(), f, "example.com"); !errors.Is(err, ErrNoRecord) {
		t.Errorf("err = %v, want ErrNoRecord", err)
	}
}

// TestDMARCOwnRecordBeatsInherited: a subdomain publishing its own policy is
// judged on that one, not the parent's.
func TestDMARCOwnRecordBeatsInherited(t *testing.T) {
	f := fakeResolver{
		"_dmarc.example.com":      {"v=DMARC1; p=reject"},
		"_dmarc.mail.example.com": {"v=DMARC1; p=none"},
	}
	rec, err := LookupDMARC(context.Background(), f, "mail.example.com")
	if err != nil {
		t.Fatalf("LookupDMARC: %v", err)
	}
	if rec.Policy != "none" || rec.InheritedFrom != "" {
		t.Errorf("got p=%s inherited=%q, want p=none and no inheritance", rec.Policy, rec.InheritedFrom)
	}
}

// np= is the policy for subdomains of this domain that do not exist. It was
// being dropped on the floor, so a record we reported was not the record that
// was published.
func TestParseDMARCKeepsNP(t *testing.T) {
	rec, err := ParseDMARC("v=DMARC1; p=none; sp=quarantine; np=reject; rua=mailto:d@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.NonExistentPolicy != "reject" {
		t.Errorf("NonExistentPolicy = %q, want %q", rec.NonExistentPolicy, "reject")
	}
	// The other two must not be disturbed by it: all three are separate
	// policies for separate populations of mail.
	if rec.Policy != "none" || rec.SubPolicy != "quarantine" {
		t.Errorf("p=%q sp=%q, want none/quarantine", rec.Policy, rec.SubPolicy)
	}
}

// Policy selection deliberately stops at sp=, because "does not exist" means
// NXDOMAIN (RFC 9989 §3.2.13) and Go's resolver cannot report response codes:
// IsNotFound is true both for NXDOMAIN and for a name that exists with no
// record of the type asked for.
//
// Pinned so that applying np= becomes a decision somebody makes rather than a
// change somebody makes by accident. It is usually the strictest of the three,
// so applying it to a domain that does exist would report a harsher policy
// than its owner asked for.
func TestParseDMARCReadsTestMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"t=y", "v=DMARC1; p=reject; t=y", true},
		{"t=n", "v=DMARC1; p=reject; t=n", false},
		{"absent defaults to off", "v=DMARC1; p=reject", false},
		// A tag we cannot read means the policy is applied, which is the safe
		// direction: the alternative is telling a sender nothing is enforced
		// when it is.
		{"unrecognised value", "v=DMARC1; p=reject; t=maybe", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := ParseDMARC(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if rec.Testing != tc.want {
				t.Errorf("Testing = %v, want %v", rec.Testing, tc.want)
			}
		})
	}
}

// RFC 9989 §4.7: t=y asks for "one level below the specified policy", not for
// none. Collapsing reject to none would overstate the problem as badly as
// reading it as reject understates it.
func TestAppliedPolicyStepsDownOneLevel(t *testing.T) {
	for _, tc := range []struct {
		policy  string
		testing bool
		want    string
	}{
		{"reject", true, "quarantine"},
		{"quarantine", true, "none"},
		{"none", true, "none"},
		{"reject", false, "reject"},
		{"quarantine", false, "quarantine"},
		{"none", false, "none"},
	} {
		d := &DMARCRecord{Policy: tc.policy, Testing: tc.testing}
		if got := d.Applied(); got != tc.want {
			t.Errorf("p=%s t=%v: Applied = %q, want %q", tc.policy, tc.testing, got, tc.want)
		}
	}
}

// The finding fires exactly where enforcement reaches zero. reject with t=y
// still quarantines, which is a deliberate rollout step rather than a fault,
// and reporting it as one would be the mistake #103 was about in another place.
type erringResolver struct{}
