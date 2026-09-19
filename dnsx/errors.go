package dnsx

import (
	"context"
	"errors"
	"net"
)

// The three questions this file answers about a resolver error are the whole
// reason it exists. Before mailkit they were answered separately, and slightly
// differently, in unspam's mailauth and in spam-audit's dnscheck. Getting them
// wrong in either direction is a reportable defect:
//
//   - treating "we could not ask" as "they have nothing" invents a finding
//     about a stranger's domain out of our own network trouble;
//   - treating "they have nothing" as "we could not ask" silently drops the
//     single most common real finding there is.
//
// So: unknown is not pass, and unknown is not fail either.

// NotFound reports whether err means the name does not exist, as distinct from
// the lookup failing to complete.
func NotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNoRecord) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// Unanswered reports whether err means the lookup never completed.
//
// It is deliberately not NotFound's negation. A caller may turn a genuine "no
// such name" into ErrNoRecord, wrap everything else, and separately fail to
// parse a record that answered perfectly well -- so three different outcomes
// arrive here as errors and only one of them means we could not ask.
func Unanswered(err error) bool {
	if err == nil || errors.Is(err, ErrNoRecord) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return !dnsErr.IsNotFound
	}
	// An error we do not recognise is treated as a failure to ask rather than
	// as an answer. That is the conservative direction: it produces a warning
	// about our own visibility instead of an accusation about someone's DNS.
	return true
}

// Void reports whether an error means the lookup counted as a "void lookup" in
// the RFC 7208 section 4.6.4 sense -- a name error, or success with an empty
// answer section.
//
// Answered through an error value this can only be approximate, because
// net.DNSError collapses NXDOMAIN and NODATA into one boolean. A caller that
// needs the exact count must go through TracingResolver.Query and use
// Answer.Empty instead; this exists for callers that cannot.
func Void(err error) bool {
	return NotFound(err)
}
