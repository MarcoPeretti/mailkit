package mailauth

import (
	"context"
	"strings"
	"testing"
)

// The examples are RFC 9989 §4.10.2's own, plus the two edges it states in
// prose: a walk that finds nothing, and a psd=y on the name the walk started
// from, which rule 2 excludes.
func TestOrganizationalDomain(t *testing.T) {
	const p = "v=DMARC1; p=reject"
	cases := []struct {
		name    string
		records fakeResolver
		domain  string
		want    string
	}{
		{"fewest labels with a record", fakeResolver{
			"_dmarc.mail.example.com": {p},
			"_dmarc.example.com":      {p},
		}, "a.mail.example.com", "example.com"},
		{"psd=n is the organization", fakeResolver{
			"_dmarc.mail.example.com": {p + "; psd=n"},
			"_dmarc.example.com":      {p},
		}, "a.mail.example.com", "mail.example.com"},
		{"one label below psd=y", fakeResolver{
			"_dmarc.com": {p + "; psd=y"},
		}, "a.mail.example.com", "example.com"},
		{"nothing published: the name itself", fakeResolver{},
			"a.mail.example.com", "a.mail.example.com"},
		{"psd=y at the start does not put the organization below it", fakeResolver{
			"_dmarc.example.com": {p + "; psd=y"},
		}, "example.com", "example.com"},
		{"a record of its own does not end the walk", fakeResolver{
			"_dmarc.mail.example.com": {p},
			"_dmarc.example.com":      {p},
		}, "mail.example.com", "example.com"},
		{"only its own record: itself", fakeResolver{
			"_dmarc.mail.example.com": {p},
		}, "mail.example.com", "mail.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OrganizationalDomain(context.Background(), tc.records, tc.domain)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("OrganizationalDomain(%s) = %q, want %q", tc.domain, got, tc.want)
			}
		})
	}
}

// The name comes from a stranger's header, so the alignment walk is bounded the
// same way policy discovery is: the name itself plus seven more.
func TestOrganizationalDomainAsksAtMostEightTimes(t *testing.T) {
	r := &countingResolver{fakeResolver: fakeResolver{}}
	long := "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.mail.example.com"
	if _, err := OrganizationalDomain(context.Background(), r, long); err != nil {
		t.Fatal(err)
	}
	if r.n > 8 {
		t.Errorf("%d queries for a %d-label name; RFC 9989 §4.10 allows 8", r.n, strings.Count(long, ".")+1)
	}
}

// The case a suffix list gets wrong, and the reason alignment moved to the
// walk. mail.example.com has published a record and example.com has not, so
// the domain owner has said the organization begins at mail.example.com: a
// signature by example.com does not align with a From under it, and one by a
// sibling under mail.example.com does. eTLD+1 says the opposite on both.
func TestAlignmentFollowsThePublishedRecords(t *testing.T) {
	r := fakeResolver{"_dmarc.mail.example.com": {"v=DMARC1; p=reject"}}
	al := NewAligner(r)
	from := "a.mail.example.com"

	if ok, err := al.Aligned(context.Background(), from, "example.com", "r"); err != nil || ok {
		t.Errorf("example.com aligned with %s = %v, %v; the organization begins at mail.example.com", from, ok, err)
	}
	if ok, err := al.Aligned(context.Background(), from, "b.mail.example.com", "r"); err != nil || !ok {
		t.Errorf("b.mail.example.com aligned with %s = %v, %v; both are under mail.example.com", from, ok, err)
	}
}

// One message asks about the From domain several times over. The walks are
// shared, so the second question costs nothing.
func TestAlignerWalksEachNameOnce(t *testing.T) {
	r := &countingResolver{fakeResolver: fakeResolver{"_dmarc.example.com": {"v=DMARC1; p=none"}}}
	al := NewAligner(r)
	for range 3 {
		if _, err := al.Aligned(context.Background(), "news.example.com", "mail.example.com", "r"); err != nil {
			t.Fatal(err)
		}
	}
	// news.example.com, example.com, com; then mail.example.com and nothing
	// new above it, since example.com and com are remembered.
	if want := 4; r.n != want {
		t.Errorf("%d queries for three identical questions, want %d", r.n, want)
	}
}

// Strict alignment and identical names are string comparisons. A resolver that
// answers nothing must not turn either into an error.
func TestStrictAlignmentAsksNothing(t *testing.T) {
	al := NewAligner(failingResolver{})
	cases := []struct {
		from, auth, mode string
		want             bool
	}{
		{"example.com", "example.com", "r", true},
		{"example.com", "example.com", "s", true},
		{"example.com", "mail.example.com", "s", false},
	}
	for _, tc := range cases {
		got, err := al.Aligned(context.Background(), tc.from, tc.auth, tc.mode)
		if err != nil {
			t.Errorf("Aligned(%q,%q,%q) asked the network: %v", tc.from, tc.auth, tc.mode, err)
		}
		if got != tc.want {
			t.Errorf("Aligned(%q,%q,%q) = %v, want %v", tc.from, tc.auth, tc.mode, got, tc.want)
		}
	}
}

// A walk that did not complete is not "not aligned". The receiver's own
// conclusion still stands; what is withheld is the diagnosis of which
// identifier let it down, because that would be made up.
