// Package spf evaluates a domain's SPF policy by walking it, rather than by
// reading only the record published at the domain itself.
//
// The difference is the point. A record such as
//
//	v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net -all
//
// has two terms, and a shallow reading reports two of the ten DNS lookups RFC
// 7208 section 4.6.4 permits. Walked, the same record commonly costs eleven or
// more, because each include is itself a record with includes. Past ten, a
// receiver stops and returns permerror, which means the policy does not apply
// at all -- and the domain's owner cannot see this by looking at their own
// record, because the cost is in somebody else's.
//
// This package therefore resolves the tree, in term order, and reports the true
// count along with the term that spent the tenth lookup.
package spf

import (
	"context"
	"fmt"
	"strings"

	"github.com/MarcoPeretti/mailkit/dnsx"
)

// Evaluate walks domain's SPF policy.
//
// It never returns an error: a failure to resolve is part of the finding, not
// an alternative to it, and is reported in Result.TempError. A caller that
// treats a returned error as "no SPF record" is the exact bug this signature
// prevents.
func Evaluate(ctx context.Context, r dnsx.Resolver, domain string, lim Limits) *Result {
	domain = dnsx.Normalize(domain)
	tracer, canTrace := r.(dnsx.TracingResolver)

	st := &state{
		res:    r,
		tracer: tracer,
		lim:    lim,
		seen:   map[string]bool{},
		out: &Result{
			Domain:     domain,
			TermsExact: true,
			VoidExact:  canTrace,
		},
	}

	records, outcome := st.records(ctx, domain)
	switch outcome {
	case OutcomeTempError:
		return st.out
	case OutcomeNXDomain, OutcomeNoRecord:
		st.node(Node{Target: domain, Via: ViaRoot, Outcome: outcome})
		return st.out
	case OutcomeMultiple:
		st.out.Records = records
		st.out.PermError = PermMultipleRecords
		st.out.PermDetail = fmt.Sprintf("%s publishes %d v=spf1 records; RFC 7208 section 4.5 makes that a permanent error", domain, len(records))
		st.node(Node{Target: domain, Via: ViaRoot, Outcome: OutcomeMultiple})
		return st.out
	}

	st.out.Records = records
	st.out.Raw = records[0]
	st.out.Found = true
	st.node(Node{Target: domain, Via: ViaRoot, Raw: records[0], Outcome: OutcomeOK})
	st.walk(ctx, domain, records[0], []string{domain}, 0)
	return st.out
}

type state struct {
	res    dnsx.Resolver
	tracer dnsx.TracingResolver
	lim    Limits
	out    *Result
	seen   map[string]bool // for Result.Includes deduplication only, never for cycles
	halted bool
}

func (s *state) node(n Node) {
	n.Seq = len(s.out.Nodes)
	n.TermAt = s.out.Terms
	if n.Depth > s.out.MaxDepth {
		s.out.MaxDepth = n.Depth
	}
	s.out.Nodes = append(s.out.Nodes, n)
}

// walk evaluates one record's terms, left to right, recursing into include and
// redirect targets.
//
// path is the chain of names from the root to this record. It is a path, not a
// global set of visited names, and that distinction is load-bearing: a target
// reached twice down two different branches is a diamond, which is legal and
// costs two lookups, while a target reached twice on one path is a loop. A
// global set would treat the first case as the second and undercount every
// Microsoft 365 and Google Workspace domain there is.
func (s *state) walk(ctx context.Context, domain, record string, path []string, depth int) {
	if s.halted {
		return
	}
	terms := Parse(record)

	// Section 6.1: redirect is only consulted when no mechanism matched and the
	// record has no "all". We are describing a record rather than evaluating a
	// message, so we follow it regardless, but we record whether a receiver
	// would have.
	var redirect *Term

	for i := range terms {
		if s.halted {
			return
		}
		t := terms[i]

		if t.Modifier {
			if t.Name == "redirect" {
				redirect = &terms[i]
			}
			continue // exp= and unknown modifiers cost no lookup
		}

		if t.Name == "all" {
			if depth == 0 {
				s.out.All = t.Qualifier
			}
			// Section 5.1: everything after "all" is ignored by a receiver, so
			// it costs nothing and we stop reading this record.
			return
		}

		if !t.CostsLookup() {
			continue // ip4, ip6, and anything else free
		}

		// The count is incremented before the lookup, and regardless of whether
		// any cache would serve it. The limit counts terms evaluated, not
		// packets sent: a record that includes the same target twice spends two
		// of its ten, even though a resolver answers the second from memory.
		s.out.Terms++
		if s.out.Terms > s.lim.MaxTerms {
			s.out.PermError = PermOverTermLimit
			s.out.PermDetail = fmt.Sprintf("the limit of %d DNS-costing terms is reached at %q in the record for %s", s.lim.MaxTerms, t.Raw, domain)
			s.out.TermsExact = false
			s.node(Node{Parent: domain, Target: valueOrDomain(t, domain), Via: viaFor(t), Depth: depth + 1, Outcome: OutcomeLimit})
			s.halted = true
			return
		}

		switch t.Name {
		case "include":
			s.descend(ctx, domain, t.Value, ViaInclude, path, depth)
		case "a", "mx", "ptr", "exists":
			s.terminal(ctx, domain, t, depth)
		}
	}

	if redirect != nil && !s.halted {
		// redirect costs a lookup of its own (section 6.1).
		s.out.Terms++
		if s.out.Terms > s.lim.MaxTerms {
			s.out.PermError = PermOverTermLimit
			s.out.PermDetail = fmt.Sprintf("the limit of %d DNS-costing terms is reached at %q in the record for %s", s.lim.MaxTerms, redirect.Raw, domain)
			s.out.TermsExact = false
			s.halted = true
			return
		}
		s.descend(ctx, domain, redirect.Value, ViaRedirect, path, depth)
	}
}

// descend follows an include or redirect target.
func (s *state) descend(ctx context.Context, parent, target, via string, path []string, depth int) {
	target = dnsx.Normalize(target)
	if target == "" {
		s.out.PermError = PermSyntax
		s.out.PermDetail = fmt.Sprintf("%s: %s with no target", parent, via)
		return
	}

	if !s.seen[target] {
		s.seen[target] = true
		s.out.Includes = append(s.out.Includes, target)
	}

	// A cycle is a target already on THIS path. See walk's comment.
	for _, p := range path {
		if p == target {
			s.out.Cycles = append(s.out.Cycles, Cycle{Path: append(append([]string(nil), path...), target)})
			s.node(Node{Parent: parent, Target: target, Via: via, Depth: depth + 1, Outcome: OutcomeCycle})
			return
		}
	}

	if depth+1 > s.lim.MaxDepth {
		s.out.TermsExact = false
		s.node(Node{Parent: parent, Target: target, Via: via, Depth: depth + 1, Outcome: OutcomeLimit})
		s.halted = true
		return
	}

	records, outcome := s.records(ctx, target)
	switch outcome {
	case OutcomeTempError:
		s.node(Node{Parent: parent, Target: target, Via: via, Depth: depth + 1, Outcome: OutcomeTempError})
		s.halted = true
		return

	case OutcomeNXDomain, OutcomeNoRecord, OutcomeMultiple:
		// Section 5.2: an include whose target yields anything other than a
		// usable record is a permanent error for the including record. This is
		// the "they changed provider and left the include behind" signal.
		s.out.Broken = append(s.out.Broken, Broken{Parent: parent, Target: target, Via: via, Reason: outcome})
		if s.out.PermError == "" {
			s.out.PermError = PermIncludeNoRecord
			s.out.PermDetail = fmt.Sprintf("%s %s: %s", via, target, brokenPhrase(outcome))
		}
		s.node(Node{Parent: parent, Target: target, Via: via, Depth: depth + 1, Outcome: outcome})
		return
	}

	s.node(Node{Parent: parent, Target: target, Via: via, Depth: depth + 1, Raw: records[0], Outcome: OutcomeOK})
	s.walk(ctx, target, records[0], append(path, target), depth+1)
}

// terminal handles the mechanisms that cost a lookup but do not recurse.
func (s *state) terminal(ctx context.Context, domain string, t Term, depth int) {
	target := valueOrDomain(t, domain)

	// A macro expands from the connecting IP address, which a survey of DNS
	// does not have. The term is counted, because a receiver spends the lookup;
	// it is not resolved, and it is certainly not recorded as having answered
	// with nothing, which would invent a void lookup out of our own blindness.
	if t.HasMacro() {
		s.node(Node{Parent: domain, Target: t.Value, Via: viaFor(t), Depth: depth + 1, Outcome: OutcomeMacro})
		return
	}

	qtype := dnsx.TypeA
	if t.Name == "mx" {
		qtype = dnsx.TypeMX
	}
	if t.Name == "ptr" {
		// ptr is deprecated (section 5.5) and resolving it needs the connecting
		// IP. Count it, record it, do not resolve it.
		s.node(Node{Parent: domain, Target: target, Via: ViaPTR, Depth: depth + 1, Outcome: OutcomeMacro})
		return
	}

	empty, err := s.void(ctx, target, qtype)
	switch {
	case err != nil:
		s.out.TempError = err.Error()
		s.out.TermsExact = false
		s.node(Node{Parent: domain, Target: target, Via: viaFor(t), Depth: depth + 1, Outcome: OutcomeTempError})
		s.halted = true
	case empty:
		s.countVoid()
		s.node(Node{Parent: domain, Target: target, Via: viaFor(t), Depth: depth + 1, Outcome: OutcomeVoid})
	default:
		s.node(Node{Parent: domain, Target: target, Via: viaFor(t), Depth: depth + 1, Outcome: OutcomeOK})
	}
}

func (s *state) countVoid() {
	s.out.Void++
	if s.out.Void > s.lim.MaxVoid && s.out.PermError == "" {
		s.out.PermError = PermOverVoidLimit
		s.out.PermDetail = fmt.Sprintf("%d void lookups; RFC 7208 section 4.6.4 permits %d", s.out.Void, s.lim.MaxVoid)
	}
}

// void reports whether a lookup answered with nothing.
func (s *state) void(ctx context.Context, name string, qtype uint16) (bool, error) {
	if s.tracer != nil {
		a, err := s.tracer.Query(ctx, name, qtype)
		if err != nil {
			if dnsx.NotFound(err) {
				return true, nil
			}
			return false, err
		}
		return a.Empty(), nil
	}

	// Without a tracing resolver we can only ask the standard library, which
	// reports "no such host" for both NXDOMAIN and "exists with no records of
	// this type". Result.VoidExact already records that the count is therefore
	// approximate.
	var err error
	switch qtype {
	case dnsx.TypeMX:
		recs, e := s.res.LookupMX(ctx, name)
		if e == nil {
			return len(recs) == 0, nil
		}
		err = e
	default:
		hosts, e := s.res.LookupHost(ctx, name)
		if e == nil {
			return len(hosts) == 0, nil
		}
		err = e
	}
	if dnsx.NotFound(err) {
		return true, nil
	}
	return false, err
}

// records fetches the SPF records published at name and classifies the answer.
func (s *state) records(ctx context.Context, name string) ([]string, string) {
	var (
		txt []string
		err error
	)
	if s.tracer != nil {
		a, qerr := s.tracer.Query(ctx, name, dnsx.TypeTXT)
		if qerr != nil {
			err = qerr
		} else {
			txt = a.TXT
			if a.RCode == dnsx.RcodeNameError {
				return nil, OutcomeNXDomain
			}
		}
	} else {
		txt, err = s.res.LookupTXT(ctx, name)
	}

	if err != nil {
		if dnsx.NotFound(err) {
			return nil, OutcomeNXDomain
		}
		s.out.TempError = err.Error()
		s.out.TermsExact = false
		return nil, OutcomeTempError
	}

	recs := Records(txt)
	switch {
	case len(recs) == 0:
		return nil, OutcomeNoRecord
	case len(recs) > 1:
		return recs, OutcomeMultiple
	}
	return recs, OutcomeOK
}

func brokenPhrase(outcome string) string {
	switch outcome {
	case OutcomeNXDomain:
		return "the name does not resolve, so the policy it was meant to authorise is gone"
	case OutcomeMultiple:
		return "it publishes more than one SPF record"
	default:
		return "the name resolves but publishes no SPF record"
	}
}

func valueOrDomain(t Term, domain string) string {
	if v := strings.TrimSpace(t.Value); v != "" {
		return dnsx.Normalize(v)
	}
	return domain
}

func viaFor(t Term) string {
	switch t.Name {
	case "include":
		return ViaInclude
	case "a":
		return ViaA
	case "mx":
		return ViaMX
	case "ptr":
		return ViaPTR
	case "exists":
		return ViaExists
	}
	return t.Name
}
