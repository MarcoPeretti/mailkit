package spf

// Limits are the evaluation bounds from RFC 7208 section 4.6.4.
type Limits struct {
	// MaxTerms is the number of DNS-costing terms permitted across the whole
	// tree before a receiver returns permerror. The RFC fixes it at 10.
	MaxTerms int

	// MaxVoid is the number of void lookups permitted. The RFC says SHOULD,
	// and names two as the default.
	MaxVoid int

	// MaxMXAddrs and MaxPTRAddrs cap the address records resolved for a single
	// mx or ptr mechanism. These do not count toward MaxTerms, but a name
	// beyond the cap is not resolved.
	MaxMXAddrs  int
	MaxPTRAddrs int

	// MaxDepth bounds how deep the include tree may nest. It is not in the RFC:
	// MaxTerms already bounds the work. It is here because the shape of the
	// tree is controlled by a stranger, and a second, independent bound costs
	// nothing.
	MaxDepth int
}

// DefaultLimits returns the limits RFC 7208 section 4.6.4 specifies.
func DefaultLimits() Limits {
	return Limits{MaxTerms: 10, MaxVoid: 2, MaxMXAddrs: 10, MaxPTRAddrs: 10, MaxDepth: 20}
}

// Outcomes a Node can have.
const (
	OutcomeOK        = "ok"               // a record was found and evaluated
	OutcomeNoRecord  = "no_record"        // the name exists but publishes no SPF
	OutcomeNXDomain  = "nxdomain"         // the name does not exist
	OutcomeMultiple  = "multiple"         // more than one v=spf1 record
	OutcomeTempError = "temperror"        // the lookup did not complete
	OutcomeCycle     = "cycle"            // the target is already on the path
	OutcomeLimit     = "limit"            // evaluation stopped here at a limit
	OutcomeMacro     = "macro_unexpanded" // counted, but not resolvable from DNS alone
	OutcomeVoid      = "void"             // answered with nothing
)

// Via records how a node was reached.
const (
	ViaRoot     = "root"
	ViaInclude  = "include"
	ViaRedirect = "redirect"
	ViaA        = "a"
	ViaMX       = "mx"
	ViaPTR      = "ptr"
	ViaExists   = "exists"
)

// Reasons for a permanent error, as stored in Result.PermError.
const (
	PermMultipleRecords = "multiple_records"
	PermOverTermLimit   = "over_term_limit"
	PermOverVoidLimit   = "over_void_limit"
	PermIncludeNoRecord = "include_no_record"
	PermSyntax          = "syntax"
)

// Node is one name visited while walking an SPF tree.
type Node struct {
	// Seq is the visit order, from 0. Order is deterministic for a given zone,
	// which is what makes a stored tree diffable between runs.
	Seq int

	Parent string
	Target string
	Via    string
	Depth  int

	// TermAt is the running term count at the moment this node was entered.
	// It is what lets a report name the include that pushed a domain past ten,
	// rather than only saying that something did.
	TermAt int

	// Raw is the record found at Target, or "" when none was.
	Raw string

	Outcome string
}

// Broken is a target an SPF record points at that did not resolve to a usable
// record.
//
// This is the most commercially interesting thing this package finds. An
// include naming a provider that no longer publishes a record is evidence that
// the domain's owner changed email providers and never cleaned up DNS -- a
// concrete, checkable fact about their configuration.
type Broken struct {
	Parent string
	Target string
	Via    string
	Reason string // OutcomeNoRecord, OutcomeNXDomain, OutcomeMultiple
}

// Cycle is a target that appears twice on one path from the root.
type Cycle struct{ Path []string }

// Result is the full evaluation of one domain's SPF tree.
type Result struct {
	Domain string

	// Records holds every v=spf1 TXT string published at Domain. More than one
	// is itself the finding, and both are kept so a report can show them.
	Records []string

	// Raw is the record actually evaluated, when there was exactly one.
	Raw string

	Found bool

	// All is the qualifier on the terminating "all" mechanism: "+", "-", "~",
	// "?", or "" when the record has none.
	All string

	// Terms is the recursive count of DNS-costing terms across the whole tree.
	// This is the number the whole package exists to compute: a shallow count
	// of the top-level record reports 1 for a Microsoft 365 domain that really
	// costs 10.
	Terms int

	// TermsExact is false when evaluation stopped early, making Terms a lower
	// bound rather than the count.
	TermsExact bool

	Void int

	// VoidExact is false when the resolver could not report response codes, so
	// NXDOMAIN and "exists but has no records" could not be told apart. An
	// approximate void count is reported as approximate, never as a fact.
	VoidExact bool

	MaxDepth int

	Nodes    []Node
	Includes []string // every target reached, deduplicated, in visit order
	Broken   []Broken
	Cycles   []Cycle

	// PermError names which rule failed, using the Perm* constants. Empty when
	// no permanent error was found.
	PermError string

	// PermDetail is the human-readable half: which term, at which name.
	PermDetail string

	// TempError is set when some lookup in the tree did not complete.
	//
	// When it is set, every other field describing the shape of the tree is
	// incomplete, and the caller must not report a term count, a broken
	// include, or a limit verdict. We could not ask; that is not the same as
	// having an answer.
	TempError string
}

// OverTermLimit reports whether the tree exceeds the permitted DNS-costing
// terms, in a way that is safe to tell the domain's owner about.
//
// It is false whenever a lookup failed, because our own inability to complete
// the walk must never be reported as their misconfiguration.
func (r *Result) OverTermLimit(lim Limits) bool {
	return r.TempError == "" && r.Terms > lim.MaxTerms
}

// Usable reports whether the result describes a complete walk.
func (r *Result) Usable() bool { return r.TempError == "" }
