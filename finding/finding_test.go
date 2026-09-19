package finding

import "testing"

type catalogue map[string]Message

func (c catalogue) Has(code string) bool { return c[code].Title != "" }
func (c catalogue) Render(_, code string, p map[string]string) Message {
	m := c[code]
	m.Detail = m.Detail + p["lookups"]
	return m
}

func TestNewStoresParams(t *testing.T) {
	f := New(CodeSPFOverLookupLimit, SeverityCritical, "lookups", 14, "limit", 10)
	if f.Params["lookups"] != "14" || f.Params["limit"] != "10" {
		t.Fatalf("Params = %v", f.Params)
	}
	// A consumer with no renderer must get usable output with empty prose,
	// never a panic and never a placeholder sentence.
	if f.Title != "" || f.Detail != "" {
		t.Error("New must not invent prose")
	}
}

func TestNewPanicsOnOddParams(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New must panic on an unpaired parameter list")
		}
	}()
	New(CodeSPFMissing, SeverityCritical, "lookups")
}

func TestRenderPanicsOnUnknownCode(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Render must panic rather than leave a finding silently blank")
		}
	}()
	f := New("not_a_real_code", SeverityInfo)
	f.Render(catalogue{}, "en")
}

func TestRenderFillsProse(t *testing.T) {
	c := catalogue{CodeSPFOverLookupLimit: {Title: "Too many lookups", Detail: "You are at "}}
	f := New(CodeSPFOverLookupLimit, SeverityCritical, "lookups", 14)
	f.Render(c, "en")
	if f.Title != "Too many lookups" || f.Detail != "You are at 14" {
		t.Fatalf("Render gave %+v", f)
	}
}

func TestWorstAndSort(t *testing.T) {
	var s Set
	s.Add(CodeSPFNoAll, SeverityWarning)
	s.Add(CodeDKIMSelectorObserved, SeverityInfo)
	s.Add(CodeSPFOverLookupLimit, SeverityCritical)

	if got := s.Worst(); got != SeverityCritical {
		t.Errorf("Worst() = %q, want %q", got, SeverityCritical)
	}
	s.SortBySeverity()
	if s[0].Code != CodeSPFOverLookupLimit || s[2].Code != CodeDKIMSelectorObserved {
		t.Errorf("SortBySeverity gave %v", s.Codes())
	}

	if (Set{}).Worst() != "" {
		t.Error("an empty set has no worst severity")
	}
}

// Every code declared as a constant must be in Codes(), or a consumer's
// catalogue test will pass while the code it forgot is still reachable.
func TestCodesIsExhaustive(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Codes() {
		if seen[c] {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = true
	}
	for _, c := range []string{
		CodeSPFMissing, CodeSPFMultiple, CodeSPFOverLookupLimit, CodeSPFBrokenInclude,
		CodeSPFEvalIncomplete, CodeDMARCMissing, CodeDMARCMonitoringOnly,
		CodeMXMissing, CodeVendorUnknownInclude, CodeDKIMSelectorObserved, CodeLookupFailed,
	} {
		if !seen[c] {
			t.Errorf("code %q is declared but missing from Codes()", c)
		}
	}
}

// There must be no code asserting that DKIM is absent. Selectors cannot be
// enumerated from DNS, so such a finding could only ever be a guess presented
// as a fact about someone else's mail.
func TestNoDKIMMissingCode(t *testing.T) {
	for _, c := range Codes() {
		if c == "dkim_missing" || c == "dkim_absent" {
			t.Fatalf("%q must not exist: DKIM absence is not observable from DNS", c)
		}
	}
}
