package spf

import (
	"context"
	"testing"
	"time"

	"github.com/MarcoPeretti/mailkit/dnsx/dnstest"
)

// googleZone is a trimmed but faithful copy of the real Google Workspace SPF
// tree: one include at the top, which fans out to three _netblocks records.
//
// It is the fixture that matters most, because it is the shape a shallow
// reading gets wrong. The published record has ONE include. Walked, it spends
// four of the ten permitted lookups.
func googleZone() dnstest.Zone {
	return dnstest.Zone{
		TXT: map[string][]string{
			"example.com":            {"v=spf1 include:_spf.google.com ~all"},
			"_spf.google.com":        {"v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"},
			"_netblocks.google.com":  {"v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all"},
			"_netblocks2.google.com": {"v=spf1 ip6:2001:4860:4000::/36 ~all"},
			"_netblocks3.google.com": {"v=spf1 ip4:172.217.0.0/19 ~all"},
		},
	}
}

func TestEvaluateCountsRecursively(t *testing.T) {
	r := dnstest.New(googleZone())
	got := Evaluate(context.Background(), r, "example.com", DefaultLimits())

	// 1 for include:_spf.google.com, plus 3 for the _netblocks includes it
	// names. The leaves hold only ip4/ip6 terms, which cost nothing.
	const want = 4
	if got.Terms != want {
		t.Errorf("Terms = %d, want %d\n\nThis is the test that fails if the evaluator stops at the\n"+
			"top-level record: a shallow count reports 1 here.", got.Terms, want)
	}
	if !got.TermsExact {
		t.Error("TermsExact = false; the walk completed and the count is exact")
	}
	if !got.Found {
		t.Error("Found = false, want true")
	}
	if got.All != "~" {
		t.Errorf("All = %q, want %q", got.All, "~")
	}
	if got.PermError != "" {
		t.Errorf("PermError = %q, want none", got.PermError)
	}
	if got.TempError != "" {
		t.Errorf("TempError = %q, want none", got.TempError)
	}
}

// A target reached twice down two different branches is a diamond. It is legal,
// and RFC 7208 counts it twice: the limit counts terms evaluated, not distinct
// names, and certainly not packets sent.
func TestDiamondTargetCountsTwice(t *testing.T) {
	z := dnstest.Zone{
		TXT: map[string][]string{
			"example.com":    {"v=spf1 include:a.example include:b.example -all"},
			"a.example":      {"v=spf1 include:shared.example -all"},
			"b.example":      {"v=spf1 include:shared.example -all"},
			"shared.example": {"v=spf1 ip4:192.0.2.0/24 -all"},
		},
	}
	got := Evaluate(context.Background(), dnstest.New(z), "example.com", DefaultLimits())

	// include:a + include:b + shared (from a) + shared (from b) = 4.
	const want = 4
	if got.Terms != want {
		t.Errorf("Terms = %d, want %d\n\nA global visited-set would report %d here and silently\n"+
			"undercount every domain whose providers share infrastructure.", got.Terms, want, want-1)
	}
	if len(got.Cycles) != 0 {
		t.Errorf("Cycles = %v; a diamond is not a loop", got.Cycles)
	}
}

func TestCycleIsDetectedAndTerminates(t *testing.T) {
	z := dnstest.Zone{
		TXT: map[string][]string{
			"a.example": {"v=spf1 include:b.example -all"},
			"b.example": {"v=spf1 include:a.example -all"},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := Evaluate(ctx, dnstest.New(z), "a.example", DefaultLimits())

	if len(got.Cycles) != 1 {
		t.Fatalf("Cycles = %v, want exactly one", got.Cycles)
	}
	if ctx.Err() != nil {
		t.Fatal("evaluation did not terminate on its own")
	}
	// The loop is reported, and the terms actually spent are still counted.
	if got.Terms != 2 {
		t.Errorf("Terms = %d, want 2", got.Terms)
	}
}

func TestOverLimitNamesTheOffendingTerm(t *testing.T) {
	// Eleven includes at the top level: the eleventh is the one that breaks it.
	z := dnstest.Zone{TXT: map[string][]string{
		"example.com": {"v=spf1 include:i1.example include:i2.example include:i3.example " +
			"include:i4.example include:i5.example include:i6.example include:i7.example " +
			"include:i8.example include:i9.example include:i10.example include:i11.example -all"},
	}}
	for _, n := range []string{"i1", "i2", "i3", "i4", "i5", "i6", "i7", "i8", "i9", "i10", "i11"} {
		z.TXT[n+".example"] = []string{"v=spf1 ip4:192.0.2.0/24 -all"}
	}

	got := Evaluate(context.Background(), dnstest.New(z), "example.com", DefaultLimits())

	if got.PermError != PermOverTermLimit {
		t.Fatalf("PermError = %q, want %q", got.PermError, PermOverTermLimit)
	}
	// Naming the term is the whole value: "you are over the limit" is not
	// actionable, "the limit is reached at include:i11.example" is.
	if !contains(got.PermDetail, "i11.example") {
		t.Errorf("PermDetail = %q; it must name the term that reached the limit", got.PermDetail)
	}
	if got.TermsExact {
		t.Error("TermsExact = true, but evaluation stopped early")
	}
}

func TestBrokenIncludeIsRecorded(t *testing.T) {
	z := dnstest.Zone{TXT: map[string][]string{
		"example.com": {"v=spf1 include:_spf.google.com include:_spf.oldesp.example -all"},
		// _spf.oldesp.example is absent from every map: NXDOMAIN. The domain
		// changed provider and never cleaned up.
		"_spf.google.com": {"v=spf1 ip4:35.190.247.0/24 ~all"},
	}}

	got := Evaluate(context.Background(), dnstest.New(z), "example.com", DefaultLimits())

	if len(got.Broken) != 1 {
		t.Fatalf("Broken = %+v, want exactly one", got.Broken)
	}
	b := got.Broken[0]
	if b.Target != "_spf.oldesp.example" || b.Reason != OutcomeNXDomain {
		t.Errorf("Broken[0] = %+v, want target _spf.oldesp.example with reason %q", b, OutcomeNXDomain)
	}
	// The terms are still counted: a receiver spends the lookup either way.
	if got.Terms != 2 {
		t.Errorf("Terms = %d, want 2", got.Terms)
	}
}

func TestMultipleRecordsIsPermErrorAndKeepsBoth(t *testing.T) {
	z := dnstest.Zone{TXT: map[string][]string{
		"example.com": {
			"v=spf1 include:_spf.google.com ~all",
			"v=spf1 include:sendgrid.net ~all",
		},
	}}

	got := Evaluate(context.Background(), dnstest.New(z), "example.com", DefaultLimits())

	if got.PermError != PermMultipleRecords {
		t.Errorf("PermError = %q, want %q", got.PermError, PermMultipleRecords)
	}
	// Both records are kept, because "which two are fighting" is the half of
	// this finding the owner can act on.
	if len(got.Records) != 2 {
		t.Errorf("Records = %v, want both", got.Records)
	}
	if got.Terms != 0 {
		t.Errorf("Terms = %d; evaluation must not proceed past a section 4.5 error", got.Terms)
	}
}

// The most damaging false positive this package could produce is telling a
// company their provider's include is dead because our own resolver had a bad
// second. When any lookup fails, the walk is incomplete and no verdict about
// their configuration may be drawn from it.
func TestTempErrorSuppressesEveryVerdict(t *testing.T) {
	z := dnstest.Zone{
		TXT: map[string][]string{
			"example.com": {"v=spf1 include:flaky.example include:_spf.google.com -all"},
		},
		Fail: map[string]string{"flaky.example": dnstest.FailServFail},
	}

	got := Evaluate(context.Background(), dnstest.New(z), "example.com", DefaultLimits())

	if got.TempError == "" {
		t.Fatal("TempError is empty, but a lookup in the tree failed")
	}
	if got.Usable() {
		t.Error("Usable() = true on an incomplete walk")
	}
	if len(got.Broken) != 0 {
		t.Errorf("Broken = %+v; a lookup that did not answer is not a broken include", got.Broken)
	}
	if got.OverTermLimit(DefaultLimits()) {
		t.Error("OverTermLimit() = true on an incomplete walk")
	}
	if got.TermsExact {
		t.Error("TermsExact = true on an incomplete walk")
	}
}

func TestVoidLookupsCountedExactlyWhenResolverCanTrace(t *testing.T) {
	z := dnstest.Zone{
		TXT: map[string][]string{
			"example.com": {"v=spf1 a:gone1.example a:gone2.example a:gone3.example -all"},
			// The three targets exist in the zone as TXT-only names, so an A
			// query returns NOERROR with an empty answer -- NODATA, not
			// NXDOMAIN. Both count as void lookups under section 4.6.4, and
			// this is the distinction net.DNSError cannot express.
			"gone1.example": {"some other txt"},
			"gone2.example": {"some other txt"},
			"gone3.example": {"some other txt"},
		},
	}

	r := dnstest.New(z)
	got := Evaluate(context.Background(), r, "example.com", DefaultLimits())

	if !got.VoidExact {
		t.Error("VoidExact = false, but the resolver implements TracingResolver")
	}
	if got.Void != 3 {
		t.Errorf("Void = %d, want 3", got.Void)
	}
	if got.PermError != PermOverVoidLimit {
		t.Errorf("PermError = %q, want %q", got.PermError, PermOverVoidLimit)
	}

	// The same zone through a resolver that cannot report response codes must
	// say the count is approximate rather than assert it.
	plain := Evaluate(context.Background(), dnstest.NoTrace(dnstest.New(z)), "example.com", DefaultLimits())
	if plain.VoidExact {
		t.Error("VoidExact = true on a resolver that cannot report response codes")
	}
}

func TestMacroTermIsCountedButNotResolved(t *testing.T) {
	z := dnstest.Zone{TXT: map[string][]string{
		"example.com": {"v=spf1 exists:%{i}._spf.example.com -all"},
	}}
	r := dnstest.New(z)
	got := Evaluate(context.Background(), r, "example.com", DefaultLimits())

	if got.Terms != 1 {
		t.Errorf("Terms = %d, want 1: a receiver spends the lookup", got.Terms)
	}
	if got.Void != 0 {
		t.Errorf("Void = %d, want 0: we cannot expand the macro, which is our limitation, not their void lookup", got.Void)
	}
	for _, q := range r.Queries() {
		if contains(q, "%") {
			t.Errorf("the evaluator queried an unexpanded macro: %q", q)
		}
	}
}

func TestNoRecordAndNXDomainAreDistinct(t *testing.T) {
	// A name that exists but publishes no SPF.
	present := dnstest.Zone{TXT: map[string][]string{"example.com": {"some other txt"}}}
	got := Evaluate(context.Background(), dnstest.New(present), "example.com", DefaultLimits())
	if got.Found {
		t.Error("Found = true for a domain with no v=spf1 record")
	}
	if got.TempError != "" {
		t.Errorf("TempError = %q; the lookup answered fine, there is simply no record", got.TempError)
	}

	// A name that does not exist at all.
	got = Evaluate(context.Background(), dnstest.New(dnstest.Zone{}), "nope.example", DefaultLimits())
	if got.Found {
		t.Error("Found = true for a nonexistent domain")
	}
	if got.TempError != "" {
		t.Errorf("TempError = %q; NXDOMAIN is an answer", got.TempError)
	}
}

func TestRedirectIsFollowedAndCosts(t *testing.T) {
	z := dnstest.Zone{TXT: map[string][]string{
		"example.com":      {"v=spf1 redirect=_spf.example.net"},
		"_spf.example.net": {"v=spf1 include:_spf.google.com -all"},
		"_spf.google.com":  {"v=spf1 ip4:35.190.247.0/24 ~all"},
	}}
	got := Evaluate(context.Background(), dnstest.New(z), "example.com", DefaultLimits())

	// redirect (1) + the include it leads to (1).
	if got.Terms != 2 {
		t.Errorf("Terms = %d, want 2", got.Terms)
	}
	if len(got.Includes) != 2 {
		t.Errorf("Includes = %v, want both the redirect target and the include", got.Includes)
	}
}

// Everything after "all" is ignored by a receiver (section 5.1), so it must not
// be counted -- otherwise a record with trailing junk reports lookups nobody
// ever spends.
func TestTermsAfterAllAreNotCounted(t *testing.T) {
	z := dnstest.Zone{TXT: map[string][]string{
		"example.com": {"v=spf1 include:a.example -all include:b.example include:c.example"},
		"a.example":   {"v=spf1 ip4:192.0.2.0/24 -all"},
	}}
	got := Evaluate(context.Background(), dnstest.New(z), "example.com", DefaultLimits())
	if got.Terms != 1 {
		t.Errorf("Terms = %d, want 1", got.Terms)
	}
}

func TestNodesAreOrderedAndStable(t *testing.T) {
	r := dnstest.New(googleZone())
	a := Evaluate(context.Background(), r, "example.com", DefaultLimits())
	b := Evaluate(context.Background(), dnstest.New(googleZone()), "example.com", DefaultLimits())

	if len(a.Nodes) != len(b.Nodes) {
		t.Fatalf("node counts differ between runs: %d vs %d", len(a.Nodes), len(b.Nodes))
	}
	for i := range a.Nodes {
		if a.Nodes[i].Target != b.Nodes[i].Target || a.Nodes[i].TermAt != b.Nodes[i].TermAt {
			t.Fatalf("node %d differs between runs: %+v vs %+v", i, a.Nodes[i], b.Nodes[i])
		}
		if a.Nodes[i].Seq != i {
			t.Fatalf("node %d has Seq %d", i, a.Nodes[i].Seq)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
