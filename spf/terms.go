package spf

import "strings"

// Term is one parsed term of an SPF record.
//
// RFC 7208 section 4.6.1 splits terms into mechanisms (which may carry a
// qualifier and match a connection) and modifiers (name=value, at most one of
// each). This type covers both, because the thing this package counts -- DNS
// lookups -- is spent by mechanisms and by the redirect modifier alike.
type Term struct {
	Raw string

	// Qualifier is "+", "-", "~" or "?" for a mechanism, and "" for a modifier.
	// An absent qualifier means "+" per section 4.6.2, and Parse fills it in,
	// because a record that says "all" and one that says "+all" are the same
	// record and must not produce different findings.
	Qualifier string

	// Name is the lowercased mechanism or modifier name: include, a, mx, ptr,
	// exists, ip4, ip6, all, redirect, exp.
	Name string

	// Value is what followed the ":" or "=", verbatim and with its case intact.
	// Case is preserved because a domain is case-insensitive but a macro body
	// is not, and this is the string a report quotes back at its owner.
	Value string

	// Modifier records whether the term used "=" (a modifier) rather than ":"
	// or nothing (a mechanism).
	Modifier bool
}

// costsLookup lists the mechanisms that each spend one of the ten DNS lookups
// RFC 7208 section 4.6.4 permits. "redirect" costs one too, but is a modifier
// and so is handled separately by the caller.
var costsLookup = map[string]bool{
	"include": true,
	"a":       true,
	"mx":      true,
	"ptr":     true,
	"exists":  true,
}

// CostsLookup reports whether t spends one of the ten permitted DNS lookups.
//
// Note what is absent: ip4, ip6 and all cost nothing, and exp costs a lookup
// only when a message actually fails, which is never during a survey. Counting
// any of them would overstate the number this package exists to report
// accurately.
func (t Term) CostsLookup() bool {
	if t.Modifier {
		return t.Name == "redirect"
	}
	return costsLookup[t.Name]
}

// HasMacro reports whether t's value contains a macro expansion.
//
// A macro such as %{i} expands from the connecting IP address, which a scanner
// looking only at DNS does not have. Such a term still costs a lookup, and is
// counted, but it cannot be resolved -- and guessing that it would have
// answered with nothing would manufacture a void lookup out of our own
// limitation.
func (t Term) HasMacro() bool { return strings.Contains(t.Value, "%") }

// IsVersion reports whether s is the "v=spf1" token that must open a record.
func IsVersion(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "v=spf1") }

// Parse splits a raw v=spf1 record into terms.
//
// It does not validate: a term whose name is unknown is returned as-is, so that
// the caller can report an unrecognised term as a syntax finding with the term
// in hand rather than having it silently dropped here.
func Parse(record string) []Term {
	fields := strings.Fields(strings.TrimSpace(record))
	if len(fields) == 0 || !IsVersion(fields[0]) {
		return nil
	}
	terms := make([]Term, 0, len(fields)-1)
	for _, f := range fields[1:] {
		terms = append(terms, parseTerm(f))
	}
	return terms
}

func parseTerm(f string) Term {
	t := Term{Raw: f}

	// A modifier is name=value, and "=" binds looser than ":" -- "exists:%{i}"
	// is a mechanism even though its value may contain "=". So look for "="
	// only before any ":".
	colon := strings.Index(f, ":")
	eq := strings.Index(f, "=")
	if eq > 0 && (colon < 0 || eq < colon) {
		t.Modifier = true
		t.Name = strings.ToLower(f[:eq])
		t.Value = f[eq+1:]
		return t
	}

	rest := f
	switch rest[0] {
	case '+', '-', '~', '?':
		t.Qualifier = string(rest[0])
		rest = rest[1:]
	default:
		// Section 4.6.2: an omitted qualifier is "+".
		t.Qualifier = "+"
	}
	if i := strings.Index(rest, ":"); i >= 0 {
		t.Name = strings.ToLower(rest[:i])
		t.Value = rest[i+1:]
		return t
	}
	// "a/24" and "mx/24" carry a CIDR length with no value.
	if i := strings.Index(rest, "/"); i >= 0 {
		t.Name = strings.ToLower(rest[:i])
		return t
	}
	t.Name = strings.ToLower(rest)
	return t
}

// Records returns the SPF records among a name's TXT records.
//
// Every v=spf1 string is returned, not just the first. More than one is a
// permanent error under section 4.5, and it is a finding worth reporting
// precisely -- so the caller needs to see both records rather than be handed
// whichever happened to come back first.
func Records(txt []string) []string {
	var out []string
	for _, t := range txt {
		if IsVersion(firstField(t)) {
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out
}

func firstField(s string) string {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) == 0 {
		return ""
	}
	return f[0]
}
