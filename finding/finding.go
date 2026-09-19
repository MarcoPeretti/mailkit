// Package finding is the observation model shared by everything built on
// mailkit.
//
// A Finding is a fact about a domain, identified by a code and parameterised by
// whatever the fact needs. The prose that describes that fact to a human is
// deliberately not produced here, because it depends entirely on who is
// reading: a domain's owner being told how to fix their SPF record and an
// operator ranking prospects are looking at the same fact and need different
// words for it, and in the second case no words at all.
//
// So mailkit emits codes, and a consumer supplies a Renderer if it wants prose.
// The struct keeps the field names and JSON tags unspam already stores, so
// adopting this package does not move any stored record or any API contract.
package finding

import (
	"fmt"
	"sort"
)

// Severity ranks how much a finding hurts the domain it is about.
//
// It is not a ranking of how interesting the finding is to whoever is reading:
// that is a separate judgement, it belongs to the consumer, and conflating the
// two is how one product's opinion ends up imposed on another's.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

// Rank orders severities, most severe first.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityWarning:
		return 1
	case SeverityInfo:
		return 2
	}
	return 3
}

// Message is rendered prose for one finding.
type Message struct {
	Title  string
	Detail string
	Fix    string
	Why    string
	Steps  []string
	Paste  string
}

// Finding is one observation about a domain.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Fix      string   `json:"fix,omitempty"`
	Why      string   `json:"why,omitempty"`
	Steps    []string `json:"steps,omitempty"`
	Paste    string   `json:"paste,omitempty"`

	// Params carries the specifics: which include was dead, how many lookups
	// were counted, which two records were fighting. A renderer interpolates
	// them; a consumer with no renderer stores them and queries them.
	Params map[string]string `json:"params,omitempty"`
}

// New builds a finding with no prose.
//
// kv is an alternating sequence of parameter names and values, each value
// stringified with fmt.Sprint. It panics on an odd count, because a mismatched
// parameter list is a programming error that would otherwise surface as a
// silently missing value in a customer-facing sentence.
func New(code string, sev Severity, kv ...any) Finding {
	if len(kv)%2 != 0 {
		panic(fmt.Sprintf("finding: New(%q) got %d arguments; parameters must be name/value pairs", code, len(kv)))
	}
	f := Finding{Code: code, Severity: sev}
	if len(kv) > 0 {
		f.Params = make(map[string]string, len(kv)/2)
		for i := 0; i < len(kv); i += 2 {
			f.Params[fmt.Sprint(kv[i])] = fmt.Sprint(kv[i+1])
		}
	}
	return f
}

// Renderer turns a code and its parameters into prose in a given locale.
type Renderer interface {
	Has(code string) bool
	Render(locale, code string, params map[string]string) Message
}

// Render fills f's prose fields from r.
//
// It panics when r does not know f.Code. That is deliberate, and it is the
// guard unspam's own finding constructor has always had: a finding that
// silently renders as nothing is worse than one that is wrong, because nobody
// notices that it is not there. Consumers that want no prose simply never call
// this.
func (f *Finding) Render(r Renderer, locale string) {
	if f.Code == "" {
		return
	}
	if !r.Has(f.Code) {
		panic(fmt.Sprintf("finding: no catalogue entry for code %q", f.Code))
	}
	m := r.Render(locale, f.Code, f.Params)
	f.Title, f.Detail, f.Fix, f.Why, f.Steps, f.Paste = m.Title, m.Detail, m.Fix, m.Why, m.Steps, m.Paste
}

// Set is an ordered collection of findings.
type Set []Finding

// Add appends a finding built from code, sev and kv.
func (s *Set) Add(code string, sev Severity, kv ...any) {
	*s = append(*s, New(code, sev, kv...))
}

// Has reports whether the set contains code.
func (s Set) Has(code string) bool {
	for _, f := range s {
		if f.Code == code {
			return true
		}
	}
	return false
}

// Codes returns the codes present, in order.
func (s Set) Codes() []string {
	out := make([]string, 0, len(s))
	for _, f := range s {
		out = append(out, f.Code)
	}
	return out
}

// Worst returns the most severe severity present, or "" for an empty set.
func (s Set) Worst() Severity {
	worst := Severity("")
	for _, f := range s {
		if worst == "" || f.Severity.Rank() < worst.Rank() {
			worst = f.Severity
		}
	}
	return worst
}

// SortBySeverity orders the set most severe first, then by code, so that two
// runs over the same domain produce byte-identical output.
func (s Set) SortBySeverity() {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Severity.Rank() != s[j].Severity.Rank() {
			return s[i].Severity.Rank() < s[j].Severity.Rank()
		}
		return s[i].Code < s[j].Code
	})
}

// Render renders every finding in the set.
func (s Set) Render(r Renderer, locale string) {
	for i := range s {
		s[i].Render(r, locale)
	}
}
