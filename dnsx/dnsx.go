// Package dnsx is the DNS seam shared by everything in mailkit.
//
// It exists because the fleet had three incompatible resolver interfaces and
// two implementations, and because one caller (a bulk crawler) needs things the
// standard library structurally cannot express while the others are happy with
// *net.Resolver and should not be forced to change.
//
// The resolution is two interfaces. Resolver uses the standard library's own
// signatures, so *net.Resolver satisfies it with no adapter at all.
// TracingResolver is the optional extension implemented only by resolvers that
// can report a response code and a TTL; callers discover it by type assertion
// and degrade honestly when it is absent.
package dnsx

import (
	"context"
	"errors"
	"net"
	"strings"
)

// ErrNoRecord reports that a name resolved but published no record of the kind
// asked for. It is deliberately distinct from a lookup that did not complete:
// "they have no SPF record" is a finding, "we could not find out" is not.
var ErrNoRecord = errors.New("dnsx: no record published")

// TXTResolver is the narrow surface record parsing needs. *net.Resolver
// satisfies it, which is what lets a caller holding one adopt this package
// without changing how it resolves anything.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Resolver is the full surface the MX and SPF evaluators need.
//
// Every signature here is the standard library's, deliberately. Nicer types
// (netip.Addr, a value-typed MX) would cost an adapter in every caller that
// already holds a *net.Resolver, and the whole point of this interface is that
// such a caller needs no adapter.
type Resolver interface {
	TXTResolver
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// TracingResolver is what a resolver implements when it can report the two
// things net.Resolver cannot: the response code, and the TTL.
//
// RFC 7208 section 4.6.4 defines the void-lookup limit on response codes --
// "RCODE 0 with an answer count of 0, or a Name Error (RCODE 3)". Go's
// net.DNSError.IsNotFound is true for both and distinguishes neither, so an
// evaluator running on the standard library can only approximate that limit.
// Callers type-assert for this interface and record that the number is an
// approximation when it is absent, rather than reporting a guess as a fact.
type TracingResolver interface {
	Resolver
	Query(ctx context.Context, name string, qtype uint16) (*Answer, error)
}

// Answer is one DNS response, including the parts the standard library discards.
type Answer struct {
	Name  string
	Qtype uint16

	// RCode is the response code, using the values in github.com/miekg/dns
	// (0 NOERROR, 3 NXDOMAIN). It is what separates a name that does not exist
	// from one that exists with no records of this type -- a distinction the
	// SPF void-lookup limit is defined in terms of.
	RCode int

	// TTL is the minimum TTL across the answer section, or 0 when it is empty.
	// Without it a cache cannot honour the zone's own expiry.
	TTL uint32

	TXT   []string
	MX    []*net.MX
	Hosts []string

	// Server records which resolver answered, so a run is reproducible and a
	// single misbehaving recursor is identifiable after the fact.
	Server string
}

// Empty reports whether a is a void answer in the RFC 7208 section 4.6.4 sense:
// a name error, or success with nothing in the answer section.
func (a *Answer) Empty() bool {
	if a == nil {
		return true
	}
	return a.RCode == RcodeNameError ||
		(a.RCode == RcodeSuccess && len(a.TXT) == 0 && len(a.MX) == 0 && len(a.Hosts) == 0)
}

// Response codes, mirroring github.com/miekg/dns so that packages which never
// talk to a network do not have to import a DNS library to read an Answer.
const (
	RcodeSuccess    = 0
	RcodeFormatErr  = 1
	RcodeServerFail = 2
	RcodeNameError  = 3
	RcodeNotImpl    = 4
	RcodeRefused    = 5
)

// Query types, same reasoning as the response codes above.
const (
	TypeA    uint16 = 1
	TypeNS   uint16 = 2
	TypePTR  uint16 = 12
	TypeMX   uint16 = 15
	TypeTXT  uint16 = 16
	TypeAAAA uint16 = 28
)

// NetResolver returns the standard library resolver, which satisfies Resolver.
// It is the right choice for a caller answering one question about one domain;
// a caller crawling thousands of domains wants dnsx/publicres instead, for the
// response codes and the explicit nameserver selection.
func NetResolver() Resolver { return &net.Resolver{} }

// Normalize reduces a hostname to the form every lookup and every map key in
// this module uses: lowercase, no surrounding whitespace, no trailing dot.
//
// It also accepts the shapes that turn up in real input files -- a URL with a
// scheme and a path, a leading "www." -- because the alternative is that each
// caller reimplements this slightly differently, which is the state this
// package was created to end.
func Normalize(domain string) string {
	d := strings.TrimSpace(domain)
	if d == "" {
		return ""
	}
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	// Strip anything after the host: path, query, fragment, or a port.
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if i := strings.LastIndex(d, "@"); i >= 0 { // an address rather than a domain
		d = d[i+1:]
	}
	if i := strings.LastIndex(d, ":"); i >= 0 && !strings.Contains(d, "]") {
		d = d[:i]
	}
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	d = strings.TrimPrefix(d, "www.")
	return d
}

// IsSubdomainOf reports whether host is name itself or a descendant of it,
// matching on label boundaries.
//
// The label-boundary check is the whole point: a plain suffix test would report
// that "evilexample.com" is inside "example.com", which in this module would
// mean attributing one organisation's DNS to another.
func IsSubdomainOf(host, name string) bool {
	host, name = Normalize(host), Normalize(name)
	if host == "" || name == "" {
		return false
	}
	return host == name || strings.HasSuffix(host, "."+name)
}

// Labels splits a normalized name into its labels, left to right.
func Labels(name string) []string {
	n := Normalize(name)
	if n == "" {
		return nil
	}
	return strings.Split(n, ".")
}
