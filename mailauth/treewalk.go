package mailauth

import (
	"context"
	"errors"
	"strings"
)

// The DNS Tree Walk, RFC 9989 §4.10.
//
// It replaces the Public Suffix List as the way the Organizational Domain of an
// Author Domain is found. RFC 7489 §3.2 defined that domain as "the domain that
// was registered with a domain name registrar" and pointed at a PSL to find it,
// while mandating no particular list and no refresh cadence; §4.10 records why
// that was abandoned — two receivers with two lists disagree about whose policy
// governs a message, and the list is a third party's file rather than anything
// the domain owner controls.
//
// The walk asks the domain owner instead: query _dmarc upwards, label by label,
// and let the records that exist say where the organization begins. A domain
// owner can therefore publish a policy at mail.example.com and have it govern
// a.mail.example.com, which the PSL method cannot express at all — it would jump
// straight from a.mail.example.com to example.com and never ask.

// maxTreeWalkLabels caps the walk at seven labels below the root, which with the
// Author Domain's own query makes eight lookups (RFC 9989 §4.10).
//
// This is a denial-of-service bound, not a tidiness one: the domain being walked
// comes from a stranger's From header, so without it a header carrying a hundred
// labels buys a hundred DNS queries per message analysed.
const maxTreeWalkLabels = 7

// treeWalkNames lists the names to query after the Author Domain itself, in
// order, per RFC 9989 §4.10 steps 3-4 and the starting point in §4.10.1.
//
// The Author Domain is not included: policy discovery queries it first and only
// walks when it published nothing, so returning it here would ask twice.
func treeWalkNames(domain string) []string {
	labels := strings.Split(strings.Trim(strings.ToLower(domain), "."), ".")
	// The walk starts at the immediate parent, except for a name of eight or
	// more labels, which is shortened to seven in one step rather than walked
	// down to. That shortcut is the whole of the query bound.
	start := len(labels) - 1
	if start > maxTreeWalkLabels {
		start = maxTreeWalkLabels
	}
	var names []string
	for n := start; n >= 1; n-- {
		names = append(names, strings.Join(labels[len(labels)-n:], "."))
	}
	return names
}

// found is one name the walk retrieved a valid DMARC record from, with its
// position in the walk. The position is what lets "one label below this one" be
// answered by name rather than by guesswork: the walk visits every ancestor in
// order, so the name below names[i] is names[i-1] whether or not it published
// anything.
type found struct {
	step int // index into the walk's query order
	name string
	rec  *DMARCRecord
}

// walk queries upwards from the Author Domain's parent and returns every valid
// record it retrieved, longest name first.
//
// A lookup that did not complete aborts the walk with its error rather than
// being read as "nothing published there". RFC 9989 §4.10.1 draws that
// distinction explicitly, and it is the house rule besides: a transient resolver
// failure reported as an absent policy is a confident wrong answer about
// somebody else's domain.
func walk(ctx context.Context, r Resolver, domain string) ([]string, []found, error) {
	names := treeWalkNames(domain)
	var out []found
	for i, name := range names {
		rec, err := lookupDMARCAt(ctx, r, name)
		switch {
		case err == nil:
			out = append(out, found{i, name, rec})
			// §4.10 steps 2 and 6: a record that states whether it is a public
			// suffix ends the walk. Everything above it is somebody else's
			// namespace, so there is nothing left to learn by asking.
			if rec.PSD == "y" || rec.PSD == "n" {
				return names, out, nil
			}
		case errors.Is(err, ErrNoRecord):
			// Nothing published here. Keep climbing.
		default:
			return nil, nil, err
		}
	}
	return names, out, nil
}

// organizationalDomain picks the Organizational Domain out of what the walk
// retrieved, per RFC 9989 §4.10.2, and returns it with the record published
// there when there is one.
//
// The three rules read as one sentence: a domain that says it is not a public
// suffix is the organization; a domain that says it is one puts the organization
// one label below it; otherwise the shortest name that published anything is the
// organization. Only the third fires in practice — psd= is published by a
// handful of registries — but the first two are the reason the walk exists, so
// implementing the common case alone would be implementing the old behaviour
// with more queries.
func organizationalDomain(names []string, records []found) (string, *DMARCRecord) {
	at := make(map[string]*DMARCRecord, len(records))
	for _, f := range records {
		at[f.name] = f.rec
	}
	for _, f := range records { // longest first, as walk returns them
		switch {
		case f.rec.PSD == "n":
			return f.name, f.rec
		case f.rec.PSD == "y" && f.step > 0:
			// One label below a public suffix. Excluding step 0 is §4.10.2's
			// own carve-out: the name the walk started from cannot put the
			// organization below itself. The name below may have published
			// nothing, in which case the PSD's record is what applies —
			// §4.10.1 ranks the PSD after the Organizational Domain rather
			// than beside it.
			below := names[f.step-1]
			if rec, ok := at[below]; ok {
				return below, rec
			}
			return below, f.rec
		}
	}
	if len(records) == 0 {
		return "", nil
	}
	last := records[len(records)-1] // fewest labels
	return last.name, last.rec
}
