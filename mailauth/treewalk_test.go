package mailauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestTreeWalkNames(t *testing.T) {
	cases := []struct {
		domain string
		want   []string
	}{
		{"example.com", []string{"com"}},
		{"mail.example.com", []string{"example.com", "com"}},
		{"a.mail.example.com", []string{"mail.example.com", "example.com", "com"}},
		// Eight labels is where the shortcut engages: the walk starts at seven
		// rather than at the immediate parent, so the whole of policy discovery
		// stays inside eight queries (RFC 9989 §4.10 step 4).
		{"a.b.c.d.e.f.g.h.i.j.mail.example.com", []string{
			"g.h.i.j.mail.example.com",
			"h.i.j.mail.example.com",
			"i.j.mail.example.com",
			"j.mail.example.com",
			"mail.example.com",
			"example.com",
			"com",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.domain, func(t *testing.T) {
			got := treeWalkNames(tc.domain)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("treeWalkNames(%q)\n got %v\nwant %v", tc.domain, got, tc.want)
			}
		})
	}
}

// countingResolver records how many times it was asked, which is the only way to
// test a denial-of-service bound: the answer is identical either way.
type countingResolver struct {
	fakeResolver
	n int
}

func (c *countingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	c.n++
	return c.fakeResolver.LookupTXT(ctx, name)
}

// The bound is the reason the shortcut exists. The domain comes from a
// stranger's From header, so without it one message buys one query per label.
func TestTreeWalkAsksAtMostEightTimes(t *testing.T) {
	r := &countingResolver{fakeResolver: fakeResolver{}}
	long := "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.mail.example.com"
	if _, err := LookupDMARC(context.Background(), r, long); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("err = %v, want ErrNoRecord", err)
	}
	if r.n > 8 {
		t.Errorf("%d DNS queries for a %d-label domain, want at most 8",
			r.n, len(strings.Split(long, ".")))
	}
}

// The change the walk actually makes. A policy published at an intermediate
// name is what a large organization does when it delegates its mail; the public
// suffix list jumps straight past it to the registrable domain and reports the
// sender as publishing no DMARC at all.
func TestPolicyPublishedAtAnIntermediateNameIsFound(t *testing.T) {
	r := fakeResolver{
		"_dmarc.mail.example.com": {"v=DMARC1; p=reject; sp=quarantine"},
	}
	rec, err := LookupDMARC(context.Background(), r, "a.mail.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.InheritedFrom != "mail.example.com" {
		t.Errorf("InheritedFrom = %q, want mail.example.com", rec.InheritedFrom)
	}
	if rec.Policy != "quarantine" {
		t.Errorf("applied policy = %q, want the sp= value quarantine", rec.Policy)
	}
}

// RFC 9989 §4.10.2 rule 3: with records at several ancestors and no psd= tag to
// say otherwise, the shortest name is the Organizational Domain.
func TestShortestPublishedNameIsTheOrganizationalDomain(t *testing.T) {
	r := fakeResolver{
		"_dmarc.mail.example.com": {"v=DMARC1; p=none"},
		"_dmarc.example.com":      {"v=DMARC1; p=reject; sp=reject"},
	}
	rec, err := LookupDMARC(context.Background(), r, "a.mail.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.InheritedFrom != "example.com" {
		t.Errorf("InheritedFrom = %q, want example.com", rec.InheritedFrom)
	}
	if rec.Policy != "reject" {
		t.Errorf("applied policy = %q, want reject", rec.Policy)
	}
}

// psd=n is a domain saying "the organization starts here". It both ends the walk
// and settles the answer, so a parent's stricter policy must not reach down.
func TestPSDNoEndsTheWalkAndIsTheOrganization(t *testing.T) {
	r := &countingResolver{fakeResolver: fakeResolver{
		"_dmarc.mail.example.com": {"v=DMARC1; p=none; psd=n"},
		"_dmarc.example.com":      {"v=DMARC1; p=reject; sp=reject"},
	}}
	rec, err := LookupDMARC(context.Background(), r, "a.mail.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.InheritedFrom != "mail.example.com" {
		t.Errorf("InheritedFrom = %q, want mail.example.com", rec.InheritedFrom)
	}
	if rec.Policy != "none" {
		t.Errorf("applied policy = %q, want none", rec.Policy)
	}
	// Author domain plus one: the record above it must not have been asked for.
	if r.n != 2 {
		t.Errorf("%d queries, want 2 — psd=n did not stop the walk", r.n)
	}
}

// psd=y is a registry saying "everything under me belongs to somebody else", so
// the organization is one label below. Its own record still governs, because the
// organization published nothing: §4.10.1 ranks the PSD after the Organizational
// Domain rather than beside it, and the report must name where the record really
// is rather than a domain that has none.
func TestPSDYesPutsTheOrganizationOneLabelBelow(t *testing.T) {
	r := fakeResolver{
		"_dmarc.com": {"v=DMARC1; p=reject; sp=quarantine; psd=y"},
	}
	rec, err := LookupDMARC(context.Background(), r, "a.mail.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.InheritedFrom != "com" {
		t.Errorf("InheritedFrom = %q, want com — the name that published it", rec.InheritedFrom)
	}
	if rec.Policy != "quarantine" {
		t.Errorf("applied policy = %q, want quarantine", rec.Policy)
	}
}

// failingResolver answers "no such name" for one name and fails for everything
// else, so the walk can be interrupted after it has started.
type failingResolver struct{ absent string }

func (f failingResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if strings.TrimSuffix(name, ".") == f.absent {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return nil, fmt.Errorf("lookup %s: server misbehaving", name)
}

// Unknown is not pass, and it is not "no policy" either. A resolver that stopped
// answering halfway up must not produce a report telling a sender they publish no
// DMARC — that is the single most alarming thing the document can say, and it
// would be said on no evidence.
func TestAnInterruptedWalkIsNotAnAbsentPolicy(t *testing.T) {
	r := failingResolver{absent: "_dmarc.mail.example.com"}
	_, err := LookupDMARC(context.Background(), r, "mail.example.com")
	if err == nil {
		t.Fatal("a failed walk was reported as a successful lookup")
	}
	if errors.Is(err, ErrNoRecord) {
		t.Fatalf("a failed walk was reported as no record published: %v", err)
	}
}

func TestParseDMARCKeepsPSD(t *testing.T) {
	rec, err := ParseDMARC("v=DMARC1; p=reject; psd=y")
	if err != nil {
		t.Fatal(err)
	}
	if rec.PSD != "y" {
		t.Errorf("PSD = %q, want y", rec.PSD)
	}
}
