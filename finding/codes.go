package finding

import "sort"

// Every code mailkit can emit.
//
// The list is exhaustive on purpose. A consumer that renders prose can test
// that its catalogue covers Codes() and fail its own build when a mailkit
// upgrade introduces a code it has no words for -- which is strictly better
// than discovering the gap when a report is generated for a customer.
const (
	// SPF: the record itself.
	CodeSPFMissing       = "spf_missing"
	CodeSPFMultiple      = "spf_multiple_records"
	CodeSPFSyntaxInvalid = "spf_syntax_invalid"

	// SPF: the walk. These are the codes a shallow reading of the record
	// cannot produce, and they are the reason this module exists.
	CodeSPFOverLookupLimit = "spf_too_many_lookups"
	CodeSPFNearLookupLimit = "spf_lookups_near_limit"
	CodeSPFBrokenInclude   = "spf_broken_include"
	CodeSPFIncludeCycle    = "spf_include_cycle"
	CodeSPFVoidLimit       = "spf_void_lookups_exceeded"
	CodeSPFRedirectIgnored = "spf_redirect_ignored"

	// SPF: the terminating qualifier.
	CodeSPFAllPass     = "spf_all_pass"
	CodeSPFAllNeutral  = "spf_all_neutral"
	CodeSPFAllSoftfail = "spf_all_softfail"
	CodeSPFNoAll       = "spf_no_all"

	// SPF: our own visibility. Never a verdict about the domain.
	CodeSPFEvalIncomplete = "spf_eval_incomplete"

	// DMARC.
	CodeDMARCMissing           = "dmarc_missing"
	CodeDMARCMultiple          = "dmarc_multiple_records"
	CodeDMARCSyntaxInvalid     = "dmarc_syntax_invalid"
	CodeDMARCMonitoringOnly    = "dmarc_monitoring_only"
	CodeDMARCBadPolicy         = "dmarc_bad_policy"
	CodeDMARCNoRUA             = "dmarc_no_rua"
	CodeDMARCRUAUnauthorized   = "dmarc_rua_external_unverified"
	CodeDMARCTestingMode       = "dmarc_testing_mode"
	CodeDMARCPartialPercentage = "dmarc_partial_pct"

	// MX.
	CodeMXMissing        = "mx_missing"
	CodeMXNull           = "mx_null"
	CodeMXForwardingOnly = "mx_forwarding_only"
	CodeMXUnresolvable   = "mx_unresolvable"
	CodeMXIPLiteral      = "mx_ip_literal"

	// Vendor attribution.
	CodeVendorUnknownInclude = "spf_unknown_provider"

	// DKIM. There is deliberately no "missing" code: selectors cannot be
	// enumerated from DNS, so absence is unprovable and only a positive
	// observation is ever recorded.
	CodeDKIMSelectorObserved = "dkim_selector_observed"

	// A lookup that did not answer. Distinct from every finding above,
	// because not knowing is not the same as knowing something is wrong.
	CodeLookupFailed = "lookup_failed"
)

var all = []string{
	CodeSPFMissing, CodeSPFMultiple, CodeSPFSyntaxInvalid,
	CodeSPFOverLookupLimit, CodeSPFNearLookupLimit, CodeSPFBrokenInclude,
	CodeSPFIncludeCycle, CodeSPFVoidLimit, CodeSPFRedirectIgnored,
	CodeSPFAllPass, CodeSPFAllNeutral, CodeSPFAllSoftfail, CodeSPFNoAll,
	CodeSPFEvalIncomplete,
	CodeDMARCMissing, CodeDMARCMultiple, CodeDMARCSyntaxInvalid,
	CodeDMARCMonitoringOnly, CodeDMARCBadPolicy, CodeDMARCNoRUA,
	CodeDMARCRUAUnauthorized, CodeDMARCTestingMode, CodeDMARCPartialPercentage,
	CodeMXMissing, CodeMXNull, CodeMXForwardingOnly, CodeMXUnresolvable, CodeMXIPLiteral,
	CodeVendorUnknownInclude,
	CodeDKIMSelectorObserved,
	CodeLookupFailed,
}

// Codes returns every code mailkit can emit, sorted.
func Codes() []string {
	out := append([]string(nil), all...)
	sort.Strings(out)
	return out
}
