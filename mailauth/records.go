// Package mailauth fetches and parses the DNS records that decide whether a
// sender's mail is authenticated: SPF, DKIM, and DMARC.
//
// It reads and parses; it does not judge. Turning a record into a verdict
// depends on who is asking -- a domain's owner being shown how to fix their
// mail and an operator ranking prospects want different severities for the
// same fact -- so evaluation lives with each consumer rather than here.
//
// For SPF, note that SPFRecord.Lookups counts only the record's own terms.
// Walking the include tree to get the true count is spf.Evaluate's job; see
// the comment on ParseSPF.
package mailauth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/MarcoPeretti/mailkit/dnsx"
)

// Resolver is the DNS surface this package needs.
//
// It is an alias rather than a distinct interface so that a caller holding a
// dnsx.Resolver, a dnsx.TracingResolver or a plain *net.Resolver can pass it
// here with no adapter and no conversion.
type Resolver = dnsx.TXTResolver

// ErrNoRecord means the domain publishes no record of the requested kind.
// It is dnsx's error, so that errors.Is works across package boundaries.
var ErrNoRecord = dnsx.ErrNoRecord

// unanswered reports whether an error means the lookup never completed, as
// opposed to completing and saying the name does not exist.
//
// It is deliberately not notFound's negation. LookupDKIM turns a genuine "no
// such name" into ErrNoRecord and wraps everything else, and ParseDKIM can fail
// on a record that answered perfectly well — so three outcomes arrive here as
// errors and only one of them means we could not ask.
func unanswered(err error) bool { return dnsx.Unanswered(err) }

// notFound reports whether a resolver error means "this name does not exist"
// rather than "the lookup could not be completed".
//
// The distinction matters: a domain with no records at all is the single most
// common finding built on this package, and it must surface as a missing record
// the domain's owner can fix, not as a transient infrastructure warning.
func notFound(err error) bool { return dnsx.NotFound(err) }

// ---------------------------------------------------------------- SPF

// SPFRecord is a parsed v=spf1 policy.
type SPFRecord struct {
	Raw string `json:"raw"`
	// All is the qualifier on the terminating "all" mechanism: "-" fail,
	// "~" softfail, "?" neutral, "+" pass, or "" when absent.
	All string `json:"all"`
	// Lookups counts mechanisms that each cost a DNS query. RFC 7208 caps the
	// total at 10; exceeding it makes evaluation return permerror, which most
	// receivers treat as a failure.
	Lookups     int      `json:"lookups"`
	Includes    []string `json:"includes"`
	Redirect    string   `json:"redirect,omitempty"`
	HasRedirect bool     `json:"has_redirect"`
}

// LookupSPF fetches and parses the SPF policy for a domain.
func LookupSPF(ctx context.Context, r Resolver, domain string) (*SPFRecord, error) {
	txts, err := r.LookupTXT(ctx, domain)
	if notFound(err) {
		return nil, ErrNoRecord
	}
	if err != nil {
		return nil, fmt.Errorf("mailkit/mailauth: lookup TXT %s: %w", domain, err)
	}
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
			return ParseSPF(txt)
		}
	}
	return nil, ErrNoRecord
}

// lookupCosting are the SPF mechanisms that each consume one of the 10 permitted
// DNS lookups.
var lookupCosting = map[string]bool{
	"include": true, "a": true, "mx": true, "ptr": true, "exists": true,
}

// ParseSPF parses a raw v=spf1 string.
//
// The lookup count is the record's own terms only; it does not recurse into
// includes, so it is a lower bound. A domain already over 10 at the top level is
// certainly broken, which is the case worth flagging automatically.
func ParseSPF(txt string) (*SPFRecord, error) {
	rec := &SPFRecord{Raw: strings.TrimSpace(txt)}
	fields := strings.Fields(rec.Raw)
	if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
		return nil, fmt.Errorf("mailkit/mailauth: %q is not an SPF record", txt)
	}
	for _, term := range fields[1:] {
		qualifier := ""
		switch term[0] {
		case '+', '-', '~', '?':
			qualifier, term = string(term[0]), term[1:]
		}
		name, arg, _ := strings.Cut(term, ":")
		name = strings.ToLower(name)
		if k, v, ok := strings.Cut(name, "="); ok {
			name, arg = k, v
		}
		switch {
		case name == "all":
			if qualifier == "" {
				qualifier = "+" // an unqualified mechanism defaults to pass
			}
			rec.All = qualifier
		case name == "redirect":
			rec.Redirect, rec.HasRedirect = arg, true
			rec.Lookups++
		case name == "include":
			rec.Includes = append(rec.Includes, arg)
			rec.Lookups++
		case lookupCosting[name]:
			rec.Lookups++
		}
	}
	return rec, nil
}

// ---------------------------------------------------------------- DMARC

// DMARCRecord is a parsed _dmarc policy.
type DMARCRecord struct {
	Raw string `json:"raw"`
	// Policy is p=: "none", "quarantine", or "reject".
	Policy    string `json:"policy"`
	SubPolicy string `json:"sub_policy,omitempty"`
	// NonExistentPolicy is np=: the policy for subdomains of this domain that
	// do not exist at all. Parsed so the record we report is the record that
	// was published; see LookupDMARC for why it does not take part in choosing
	// the policy in force.
	NonExistentPolicy string `json:"non_existent_policy,omitempty"`
	// Testing is the t= tag: the domain owner asking receivers to report on the
	// policy without applying it (RFC 9989 §4.7). It is the surviving half of
	// pct=, which §A.6 removed — t=y is what pct=0 was used for.
	Testing bool `json:"testing,omitempty"`
	// PSD says whether the record was published for a public suffix: "y" it
	// was, "n" it was not and this name is its own Organizational Domain, ""
	// (the default, "u") it declines to say. The tree walk reads it to know
	// where an organization begins; see RFC 9989 §4.7 and §4.10.2.
	PSD string `json:"psd,omitempty"`
	// Pct is the percentage of mail the policy applies to; defaults to 100.
	Pct int `json:"pct"`
	// ADKIM and ASPF are alignment modes: "r" relaxed (default) or "s" strict.
	ADKIM string   `json:"adkim"`
	ASPF  string   `json:"aspf"`
	RUA   []string `json:"rua,omitempty"`
	RUF   []string `json:"ruf,omitempty"`
	// InheritedFrom names the organizational domain a subdomain took this
	// record from, empty when the record was published at the domain asked
	// about. A sender using mail.example.com is covered by example.com's
	// policy and must not be told it has none.
	InheritedFrom string `json:"inherited_from,omitempty"`
	// ParentPolicy is the p= the inherited record publishes for its own
	// domain when sp= replaced it as Policy, so a fix can quote the record
	// back whole. Empty whenever PolicyTag is "p".
	ParentPolicy string `json:"parent_policy,omitempty"`
}

// LookupDMARC fetches the DMARC policy that applies to a domain.
//
// A subdomain with no record of its own is covered by its organizational
// domain's, with sp= replacing p= when one is set (RFC 9989 §4.10.1). Skipping
// that fallback reports every ESP-style sending subdomain — mail.example.com,
// mg.example.com — as publishing no DMARC at all, which is both wrong and the
// most alarming thing the report can say.
//
// Which domain that is comes from the DNS Tree Walk (§4.10), not from a public
// suffix list. See treewalk.go for why the standard moved; the consequence here
// is that a policy published at an intermediate name is found instead of jumped
// over. For a.mail.example.com the list method asks only about the name itself
// and example.com, so a record at mail.example.com — a perfectly ordinary way
// for a large organization to delegate its mail — was reported as no record at
// all.
//
// np= is deliberately not consulted, and the reason is a limit rather than an
// oversight. §4.10.1 selects np= over sp= when the author domain "does not
// exist", and §3.2.13 defines that strictly: the response code for a query on
// the name is NXDOMAIN. Go's resolver does not report response codes —
// net.DNSError.IsNotFound is true both for NXDOMAIN and for a name that plainly
// exists with no record of the type asked for, with the same "no such host"
// text, so nothing here can tell the two apart.
//
// Guessing would be the wrong way round. np= is typically stricter than sp=,
// so treating an existing domain as non-existent would report a harsher policy
// than the domain owner asked for. And the case does not arise in what this
// reads: the author domain of a message that was delivered exists. Publishing
// the tag in the record we report is therefore the honest half — a reader can
// see it, and nothing pretends to have applied it.
func LookupDMARC(ctx context.Context, r Resolver, domain string) (*DMARCRecord, error) {
	rec, err := lookupDMARCAt(ctx, r, domain)
	if err == nil || !errors.Is(err, ErrNoRecord) {
		return rec, err
	}
	names, records, err := walk(ctx, r, domain)
	if err != nil {
		return nil, err
	}
	org, rec := organizationalDomain(names, records)
	if rec == nil {
		return nil, ErrNoRecord
	}
	// InheritedFrom names where the record was actually published, which is not
	// always the Organizational Domain: a PSD record governs a subdomain whose
	// organization published nothing. Reporting the organization there would
	// attribute the policy to a domain that has no DMARC record, which is the
	// misattribution #103 was about.
	rec.InheritedFrom = org
	for _, f := range records {
		if f.rec == rec {
			rec.InheritedFrom = f.name
			break
		}
	}
	// sp= exists precisely to say what subdomains get; when it is set it is
	// the policy in force here, and the report must judge that one.
	if rec.SubPolicy != "" {
		rec.ParentPolicy = rec.Policy
		rec.Policy = rec.SubPolicy
	}
	return rec, nil
}

func lookupDMARCAt(ctx context.Context, r Resolver, domain string) (*DMARCRecord, error) {
	txts, err := r.LookupTXT(ctx, "_dmarc."+domain)
	if notFound(err) {
		return nil, ErrNoRecord
	}
	if err != nil {
		return nil, fmt.Errorf("mailkit/mailauth: lookup _dmarc.%s: %w", domain, err)
	}
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=dmarc1") {
			return ParseDMARC(txt)
		}
	}
	return nil, ErrNoRecord
}

// ParseDMARC parses a raw v=DMARC1 string, applying the RFC 9989 §4.7 defaults.
func ParseDMARC(txt string) (*DMARCRecord, error) {
	rec := &DMARCRecord{Raw: strings.TrimSpace(txt), Pct: 100, ADKIM: "r", ASPF: "r"}
	parts := strings.Split(rec.Raw, ";")
	if len(parts) == 0 || !strings.EqualFold(strings.TrimSpace(parts[0]), "v=DMARC1") {
		return nil, fmt.Errorf("mailkit/mailauth: %q is not a DMARC record", txt)
	}
	for _, part := range parts[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "p":
			rec.Policy = strings.ToLower(v)
		case "sp":
			rec.SubPolicy = strings.ToLower(v)
		case "np":
			rec.NonExistentPolicy = strings.ToLower(v)
		case "psd":
			rec.PSD = strings.ToLower(v)
		case "t":
			// Only "y" enables it; the default and anything unrecognised mean
			// the policy is to be applied, which is the safe direction to
			// resolve a malformed tag in.
			rec.Testing = strings.EqualFold(v, "y")
		case "pct":
			if n, err := strconv.Atoi(v); err == nil {
				rec.Pct = n
			}
		case "adkim":
			rec.ADKIM = strings.ToLower(v)
		case "aspf":
			rec.ASPF = strings.ToLower(v)
		case "rua":
			rec.RUA = splitURIs(v)
		case "ruf":
			rec.RUF = splitURIs(v)
		}
	}
	return rec, nil
}

// PolicyTag names the tag Policy was read from: "sp" when a subdomain took
// its policy from the parent's sp=, otherwise "p". sp= governs only the
// subdomains of the domain publishing it (RFC 9989 §4.7), so at the domain
// itself p is always the tag, whatever sp says.
//
// Everything that tells a reader which tag to edit must ask this, because on
// the inherited path Policy already holds sp's value and the parent's p= may
// say something stricter: telling mg.example.com to "set p=quarantine" on a
// record reading "p=reject; sp=none" is a downgrade for the parent, and does
// nothing for the subdomain.
func (d *DMARCRecord) PolicyTag() string {
	if d.InheritedFrom != "" && d.SubPolicy != "" {
		return "sp"
	}
	return "p"
}

// Applied is the policy receivers are asked to enforce, which is not always the
// policy published.
//
// t=y asks for the published policy to be reported but not applied, and RFC 9989
// §4.7 is specific about what happens instead: "one level below the specified
// policy" — reject becomes quarantine, quarantine becomes none. It has no effect
// on a policy that is already none.
//
// Policy is the one to read for "what does this record say"; Applied is the one
// to read for "what happens to failing mail". Grading the criterion on Policy is
// how a domain that enforces nothing was reported as enforcing.
func (d *DMARCRecord) Applied() string {
	if !d.Testing {
		return d.Policy
	}
	switch d.Policy {
	case "reject":
		return "quarantine"
	case "quarantine":
		return "none"
	}
	return d.Policy
}

func splitURIs(v string) []string {
	var out []string
	for _, u := range strings.Split(v, ",") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// ---------------------------------------------------------------- DKIM

// DKIMRecord is a parsed public key record at <selector>._domainkey.<domain>.
type DKIMRecord struct {
	Raw      string `json:"raw"`
	Selector string `json:"selector"`
	KeyType  string `json:"key_type"`
	// Revoked is true when p= is present but empty, the RFC 6376 way of
	// withdrawing a key without deleting the record.
	Revoked bool `json:"revoked"`
	// KeyBits is the RSA modulus size, or 0 when it could not be determined.
	KeyBits int  `json:"key_bits"`
	Testing bool `json:"testing"`
}

// LookupDKIM fetches the DKIM key for one selector.
func LookupDKIM(ctx context.Context, r Resolver, domain, selector string) (*DKIMRecord, error) {
	name := selector + "._domainkey." + domain
	txts, err := r.LookupTXT(ctx, name)
	if notFound(err) {
		return nil, ErrNoRecord
	}
	if err != nil {
		return nil, fmt.Errorf("mailkit/mailauth: lookup %s: %w", name, err)
	}
	if len(txts) == 0 {
		return nil, ErrNoRecord
	}
	// Long keys are split across strings by DNS; the receiver concatenates them.
	return ParseDKIM(selector, strings.Join(txts, ""))
}

// ParseDKIM parses a DKIM key record and, for RSA keys, recovers the key size.
func ParseDKIM(selector, txt string) (*DKIMRecord, error) {
	rec := &DKIMRecord{Raw: strings.TrimSpace(txt), Selector: selector, KeyType: "rsa"}
	var pubB64 string
	var sawP bool
	for _, part := range strings.Split(rec.Raw, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "k":
			rec.KeyType = strings.ToLower(v)
		case "p":
			sawP, pubB64 = true, v
		case "t":
			rec.Testing = strings.Contains(strings.ToLower(v), "y")
		}
	}
	if !sawP {
		return nil, fmt.Errorf("mailkit/mailauth: DKIM record for %q has no p= tag", selector)
	}
	if pubB64 == "" {
		rec.Revoked = true
		return rec, nil
	}
	if rec.KeyType == "rsa" {
		rec.KeyBits = rsaBits(pubB64)
	}
	return rec, nil
}

// rsaBits decodes a base64 SubjectPublicKeyInfo and returns the modulus size,
// or 0 if the key cannot be parsed.
func rsaBits(b64 string) int {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	if err != nil {
		return 0
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return 0
	}
	if k, ok := pub.(*rsa.PublicKey); ok {
		return k.N.BitLen()
	}
	return 0
}

// NetResolver returns the standard library resolver.
//
// Deprecated: use dnsx.NetResolver, or dnsx/publicres when the caller needs
// response codes and explicit nameserver selection -- neither of which
// *net.Resolver can report.
func NetResolver() Resolver { return dnsx.NetResolver() }
