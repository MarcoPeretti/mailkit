package dnsx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

// A *net.Resolver must satisfy Resolver with no adapter. This is not a
// nice-to-have: it is the property that lets unspam adopt mailkit without
// changing how it resolves anything, so it is asserted at compile time.
var _ Resolver = (*net.Resolver)(nil)

func TestNormalize(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "example.com", "example.com"},
		{"uppercase", "EXAMPLE.COM", "example.com"},
		{"trailing dot", "example.com.", "example.com"},
		{"surrounding space", "  example.com  ", "example.com"},
		{"leading www", "www.example.com", "example.com"},
		{"https url", "https://example.com/pricing?a=1", "example.com"},
		{"http url with www", "http://www.example.com/", "example.com"},
		{"bare host and path", "example.com/pricing", "example.com"},
		{"port", "example.com:443", "example.com"},
		{"email address", "user@example.com", "example.com"},
		{"subdomain kept", "mail.example.com", "mail.example.com"},
		{"underscore label kept", "_dmarc.example.com", "_dmarc.example.com"},
		{"empty", "", ""},
		{"space only", "   ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Normalize(c.in); got != c.want {
				t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestIsSubdomainOfRespectsLabelBoundary(t *testing.T) {
	cases := []struct {
		name, host, parent string
		want               bool
	}{
		{"identical", "example.com", "example.com", true},
		{"child", "mail.example.com", "example.com", true},
		{"grandchild", "a.b.example.com", "example.com", true},
		{"dmarc label", "_dmarc.example.com", "example.com", true},
		{"case insensitive", "MAIL.Example.COM", "example.com", true},
		{"trailing dot", "mail.example.com.", "example.com", true},
		// The one that matters. A plain strings.HasSuffix would say true here,
		// and this module would then attribute a stranger's DNS to the domain
		// being scanned.
		{"suffix but not subdomain", "evilexample.com", "example.com", false},
		{"unrelated", "example.org", "example.com", false},
		{"parent is not child", "example.com", "mail.example.com", false},
		{"empty host", "", "example.com", false},
		{"empty parent", "example.com", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsSubdomainOf(c.host, c.parent); got != c.want {
				t.Errorf("IsSubdomainOf(%q, %q) = %v, want %v", c.host, c.parent, got, c.want)
			}
		})
	}
}

func TestNotFoundVsUnanswered(t *testing.T) {
	notFoundErr := &net.DNSError{Err: "no such host", Name: "x.example", IsNotFound: true}
	timeoutErr := &net.DNSError{Err: "i/o timeout", Name: "x.example", IsTimeout: true}
	tempErr := &net.DNSError{Err: "server misbehaving", Name: "x.example", IsTemporary: true}

	cases := []struct {
		name                 string
		err                  error
		notFound, unanswered bool
	}{
		{"nil", nil, false, false},
		{"nxdomain", notFoundErr, true, false},
		{"nxdomain wrapped", fmt.Errorf("looking up: %w", notFoundErr), true, false},
		{"timeout", timeoutErr, false, true},
		{"temporary", tempErr, false, true},
		{"context deadline", context.DeadlineExceeded, false, true},
		{"context canceled", context.Canceled, false, true},
		// ErrNoRecord is an answer: the name resolved and published nothing.
		// It must never read as a failure to ask.
		{"no record published", ErrNoRecord, true, false},
		{"no record wrapped", fmt.Errorf("spf: %w", ErrNoRecord), true, false},
		// An error we do not recognise is treated as "could not ask", which
		// produces a warning about our own visibility rather than an
		// accusation about someone else's DNS.
		{"unknown error", errors.New("something else"), false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NotFound(c.err); got != c.notFound {
				t.Errorf("NotFound(%v) = %v, want %v", c.err, got, c.notFound)
			}
			if got := Unanswered(c.err); got != c.unanswered {
				t.Errorf("Unanswered(%v) = %v, want %v", c.err, got, c.unanswered)
			}
			if c.notFound && c.unanswered {
				t.Fatal("a single error must not be both a definite answer and a failure to ask")
			}
		})
	}
}

func TestAnswerEmpty(t *testing.T) {
	cases := []struct {
		name string
		a    *Answer
		want bool
	}{
		{"nil", nil, true},
		{"nxdomain", &Answer{RCode: RcodeNameError}, true},
		// NODATA: the name exists, but publishes nothing of this type. RFC 7208
		// section 4.6.4 counts it as a void lookup exactly like NXDOMAIN, and
		// net.DNSError cannot tell the two apart -- which is why Answer exists.
		{"noerror empty", &Answer{RCode: RcodeSuccess}, true},
		{"noerror with txt", &Answer{RCode: RcodeSuccess, TXT: []string{"v=spf1 -all"}}, false},
		{"noerror with mx", &Answer{RCode: RcodeSuccess, MX: []*net.MX{{Host: "mx.example.com"}}}, false},
		{"noerror with host", &Answer{RCode: RcodeSuccess, Hosts: []string{"192.0.2.1"}}, false},
		// A server failure is not a void lookup. It is not an answer at all,
		// and counting it toward the void limit would turn our bad minute into
		// their permerror.
		{"servfail", &Answer{RCode: RcodeServerFail}, false},
		{"refused", &Answer{RCode: RcodeRefused}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.a.Empty(); got != c.want {
				t.Errorf("Empty() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestLabels(t *testing.T) {
	got := Labels("Mail.Example.COM.")
	want := []string{"mail", "example", "com"}
	if len(got) != len(want) {
		t.Fatalf("Labels() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Labels() = %v, want %v", got, want)
		}
	}
	if Labels("") != nil {
		t.Error("Labels(\"\") should be nil")
	}
}
