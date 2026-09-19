package mailauth

import (
	"context"
	"errors"
	"strings"
)

// Identifier alignment, RFC 9989 §3.2.10 and §4.10.2.
//
// DMARC passes when an authenticated identifier — the DKIM d= or the SPF
// domain — aligns with the From domain. Strict alignment is string equality.
// Relaxed alignment is equality of Organizational Domains, and since RFC 9989
// the Organizational Domain of a name is found by the DNS Tree Walk rather than
// a public suffix list: the records a domain owner has published say where the
// organization begins. That makes relaxed alignment a DNS question, which is
// why the functions here take a resolver where the RFC 7489 version took none.

// OrganizationalDomain finds the Organizational Domain of any name, per
// RFC 9989 §4.10.2.
//
// This is the alignment half of the walk, and it differs from policy discovery
// in where it starts: at the name itself, whose own record is a candidate like
// any other. LookupDMARC starts one label up because it has already asked the
// Author Domain and found nothing, and the two must not be merged — a From
// domain that publishes its own record still walks upward here, because a
// record above it may say the organization is wider than that one name.
//
// A name that finds no record anywhere is its own Organizational Domain. An
// error means a lookup did not complete, and it is an error rather than a
// guess for the reason walk gives.
func OrganizationalDomain(ctx context.Context, r Resolver, domain string) (string, error) {
	o, err := orgWalk(ctx, r, domain)
	return o.org, err
}

// orgAnswer is what one alignment walk learned: the Organizational Domain,
// and whether any record at all was found on the way, which is what decides
// whether DMARC — and so alignment — applies to the name at all.
type orgAnswer struct {
	org       string
	published bool
}

func orgWalk(ctx context.Context, r Resolver, domain string) (orgAnswer, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	names := []string{domain}
	var records []found
	rec, err := lookupDMARCAt(ctx, r, domain)
	switch {
	case err == nil:
		records = append(records, found{0, domain, rec})
		// §4.10 step 2: a record that states whether it is a public suffix
		// ends the walk before it climbs.
		if rec.PSD == "y" || rec.PSD == "n" {
			org, _ := organizationalDomain(names, records)
			return orgAnswer{org, true}, nil
		}
	case !errors.Is(err, ErrNoRecord):
		return orgAnswer{}, err
	}
	above, higher, err := walk(ctx, r, domain)
	if err != nil {
		return orgAnswer{}, err
	}
	names = append(names, above...)
	for _, f := range higher {
		f.step++ // the walk numbered from the parent; the name itself is 0 here
		records = append(records, f)
	}
	org, _ := organizationalDomain(names, records)
	if org == "" {
		return orgAnswer{domain, false}, nil
	}
	return orgAnswer{org, true}, nil
}

// Aligner answers alignment questions for one message, remembering every name
// it has asked about.
//
// One message asks the same question several times over — the From domain
// against each DKIM signature, the SPF identity and the Return-Path — and each
// answer costs up to eight DNS queries per name. The names share ancestors:
// a From at news.example.com and a Return-Path at bounce.example.com walk the
// same example.com and com. So what is remembered is each answer the resolver
// gave, not each organization found, and the second walk asks only for the
// names the first did not. It is per message rather than global because a
// remembered answer about somebody's DNS should not outlive the report that
// asked.
type Aligner struct {
	r    *memoResolver
	orgs map[string]orgAnswer
}

// NewAligner returns an Aligner that walks through r.
func NewAligner(r Resolver) *Aligner {
	return &Aligner{r: &memoResolver{Resolver: r, txt: map[string]txtAnswer{}}, orgs: map[string]orgAnswer{}}
}

// walked returns what the walk from a name learned, walking at most once per
// name. A walk that did not complete is not remembered, so the next question
// asks again rather than inheriting the failure.
func (a *Aligner) walked(ctx context.Context, domain string) (orgAnswer, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if o, ok := a.orgs[domain]; ok {
		return o, nil
	}
	o, err := orgWalk(ctx, a.r, domain)
	if err != nil {
		return orgAnswer{}, err
	}
	a.orgs[domain] = o
	return o, nil
}

// Org returns the Organizational Domain of a name.
func (a *Aligner) Org(ctx context.Context, domain string) (string, error) {
	o, err := a.walked(ctx, domain)
	return o.org, err
}

// PolicyApplies reports whether any DMARC record governs a From domain — its
// own, its organization's or its public suffix's.
//
// When none does, RFC 9989 §4.10.2 says alignment is not evaluated at all: the
// mechanism does not apply to the message, and receivers record no dmarc=
// result for it. Judging alignment anyway would judge it against the wrong
// map, because with nothing published every name is its own organization, and
// a Return-Path at send.example.com would be called misaligned with
// example.com when the one change the sender is already being told to make —
// publish a record — is exactly what aligns them.
func (a *Aligner) PolicyApplies(ctx context.Context, fromDomain string) (bool, error) {
	o, err := a.walked(ctx, fromDomain)
	return o.published, err
}

// memoResolver remembers TXT answers, including "no such name", for the life
// of one Aligner. Errors are not remembered: a lookup that did not complete is
// asked again by the next walk that needs it.
type memoResolver struct {
	Resolver
	txt map[string]txtAnswer
}

type txtAnswer struct {
	txts []string
	err  error
}

func (m *memoResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if a, ok := m.txt[name]; ok {
		return a.txts, a.err
	}
	txts, err := m.Resolver.LookupTXT(ctx, name)
	if err == nil || notFound(err) {
		m.txt[name] = txtAnswer{txts, err}
	}
	return txts, err
}

// Aligned reports whether authDomain aligns with fromDomain under the given
// DMARC mode ("s" strict, anything else relaxed).
//
// Strict alignment and identical names are answered without the network.
// Relaxed alignment compares Organizational Domains, so the same two names can
// align for one sender and not for another, depending on what each has
// published. An error means a walk did not complete; it is an error rather
// than false because "not aligned" is a verdict about somebody's configuration
// and this is a verdict about our resolver.
func (a *Aligner) Aligned(ctx context.Context, fromDomain, authDomain, mode string) (bool, error) {
	f := strings.ToLower(strings.TrimSuffix(fromDomain, "."))
	d := strings.ToLower(strings.TrimSuffix(authDomain, "."))
	if f == "" || d == "" {
		return false, nil
	}
	if f == d {
		return true, nil
	}
	if mode == "s" {
		return false, nil
	}
	fo, err := a.walked(ctx, f)
	if err != nil {
		return false, err
	}
	do, err := a.walked(ctx, d)
	if err != nil {
		return false, err
	}
	return fo.org == do.org, nil
}
