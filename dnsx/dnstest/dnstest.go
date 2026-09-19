// Package dnstest provides a static DNS world for tests.
//
// Nothing in mailkit or its consumers may contact a real resolver from a test.
// Real DNS makes a test suite that fails when someone else changes their
// records, passes when the network is down and a cache is warm, and cannot
// express the cases that matter most here -- a name that exists with no records
// of the type asked for, a nameserver that times out, an include loop.
//
// A Zone expresses all of those, and Queries returns the ordered query log,
// which is how tests assert *how many* lookups an evaluator made. For the SPF
// evaluator that count is not a performance detail: it is the verdict.
package dnstest

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/MarcoPeretti/mailkit/dnsx"
)

// Zone is a static DNS world.
//
// The distinction the SPF void-lookup limit turns on is expressed by presence
// rather than content: a name absent from every map is NXDOMAIN, and a name
// present with an empty slice is NOERROR with an empty answer section. Those
// are different answers, and a fake that cannot tell them apart cannot test the
// code that has to.
type Zone struct {
	TXT  map[string][]string  `json:"txt,omitempty"`
	MX   map[string][]MXEntry `json:"mx,omitempty"`
	A    map[string][]string  `json:"a,omitempty"`
	PTR  map[string][]string  `json:"ptr,omitempty"`
	TTL  map[string]uint32    `json:"ttl,omitempty"`
	Fail map[string]string    `json:"fail,omitempty"` // name -> error kind
}

// MXEntry is a JSON-friendly MX record.
type MXEntry struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

// Failure kinds a Zone can express, by name.
const (
	FailTimeout  = "timeout"  // the lookup did not complete in time
	FailServFail = "servfail" // the nameserver answered with an error
	FailRefused  = "refused"
)

// Resolver serves a Zone. It implements dnsx.TracingResolver, so code paths
// that depend on response codes are exercised; NoTrace strips that back to a
// plain dnsx.Resolver to test the degraded path.
type Resolver struct {
	zone Zone

	mu      sync.Mutex
	queries []string
}

var (
	_ dnsx.Resolver        = (*Resolver)(nil)
	_ dnsx.TracingResolver = (*Resolver)(nil)
)

// New returns a Resolver serving z.
func New(z Zone) *Resolver { return &Resolver{zone: z} }

// Load reads a zone fixture written by "dnscrawler capture".
func Load(t *testing.T, path string) *Resolver {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("dnstest: reading fixture: %v", err)
	}
	var z Zone
	if err := json.Unmarshal(b, &z); err != nil {
		t.Fatalf("dnstest: parsing fixture %s: %v", path, err)
	}
	return New(z)
}

// Queries returns the names looked up so far, in order, as "TYPE name".
//
// Order and count are both assertable, because an evaluator that visits an SPF
// tree in the wrong order reports the wrong term as the one that broke the
// limit, and one that visits a name twice reports the wrong count.
func (r *Resolver) Queries() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.queries...)
}

// CountOf returns how many times name was looked up for qtype.
func (r *Resolver) CountOf(qtype uint16, name string) int {
	key := qname(qtype, name)
	n := 0
	for _, q := range r.Queries() {
		if q == key {
			n++
		}
	}
	return n
}

// Reset clears the query log, keeping the zone.
func (r *Resolver) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = nil
}

func (r *Resolver) record(qtype uint16, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, qname(qtype, name))
}

func qname(qtype uint16, name string) string {
	t := "TYPE" + fmt.Sprint(qtype)
	switch qtype {
	case dnsx.TypeA:
		t = "A"
	case dnsx.TypeMX:
		t = "MX"
	case dnsx.TypeTXT:
		t = "TXT"
	case dnsx.TypePTR:
		t = "PTR"
	}
	return t + " " + dnsx.Normalize(name)
}

// Query implements dnsx.TracingResolver.
func (r *Resolver) Query(ctx context.Context, name string, qtype uint16) (*dnsx.Answer, error) {
	name = dnsx.Normalize(name)
	r.record(qtype, name)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if kind, ok := r.zone.Fail[name]; ok {
		return nil, failError(kind, name)
	}

	a := &dnsx.Answer{Name: name, Qtype: qtype, RCode: dnsx.RcodeSuccess, Server: "dnstest", TTL: r.zone.TTL[name]}
	present := false
	switch qtype {
	case dnsx.TypeTXT:
		a.TXT, present = r.zone.TXT[name]
	case dnsx.TypeMX:
		var mxs []MXEntry
		mxs, present = r.zone.MX[name]
		for _, m := range mxs {
			a.MX = append(a.MX, &net.MX{Host: m.Host, Pref: m.Pref})
		}
	case dnsx.TypeA, dnsx.TypeAAAA:
		a.Hosts, present = r.zone.A[name]
	case dnsx.TypePTR:
		a.Hosts, present = r.zone.PTR[name]
	}

	// A name is "present" for NODATA purposes if it appears in ANY map: it
	// exists in the zone, just not with this record type. Only a name that
	// appears nowhere is a name error.
	if !present && !r.nameExists(name) {
		a.RCode = dnsx.RcodeNameError
	}
	return a, nil
}

func (r *Resolver) nameExists(name string) bool {
	if _, ok := r.zone.TXT[name]; ok {
		return true
	}
	if _, ok := r.zone.MX[name]; ok {
		return true
	}
	if _, ok := r.zone.A[name]; ok {
		return true
	}
	_, ok := r.zone.PTR[name]
	return ok
}

func failError(kind, name string) error {
	switch kind {
	case FailTimeout:
		return &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true, IsTemporary: true}
	case FailRefused:
		return &net.DNSError{Err: "query refused", Name: name, IsTemporary: true}
	default:
		return &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
}

// notFound builds the error the standard library would return for a name error,
// so that callers exercising the plain dnsx.Resolver path see exactly what they
// would see from *net.Resolver.
func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// LookupTXT implements dnsx.Resolver.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	a, err := r.Query(ctx, name, dnsx.TypeTXT)
	if err != nil {
		return nil, err
	}
	if a.RCode == dnsx.RcodeNameError {
		return nil, notFound(name)
	}
	return a.TXT, nil
}

// LookupMX implements dnsx.Resolver.
func (r *Resolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	a, err := r.Query(ctx, name, dnsx.TypeMX)
	if err != nil {
		return nil, err
	}
	if a.RCode == dnsx.RcodeNameError {
		return nil, notFound(name)
	}
	return a.MX, nil
}

// LookupHost implements dnsx.Resolver.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	a, err := r.Query(ctx, host, dnsx.TypeA)
	if err != nil {
		return nil, err
	}
	if a.RCode == dnsx.RcodeNameError || len(a.Hosts) == 0 {
		return nil, notFound(host)
	}
	return a.Hosts, nil
}

// LookupAddr implements dnsx.Resolver.
func (r *Resolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	a, err := r.Query(ctx, addr, dnsx.TypePTR)
	if err != nil {
		return nil, err
	}
	if a.RCode == dnsx.RcodeNameError {
		return nil, notFound(addr)
	}
	return a.Hosts, nil
}

// NoTrace wraps r so that it satisfies dnsx.Resolver but NOT
// dnsx.TracingResolver.
//
// It exists to test the degraded path: an evaluator handed a standard library
// resolver cannot count void lookups exactly, and must say so rather than
// report an approximation as a fact. That behaviour needs a resolver which
// genuinely lacks Query, not one that merely promises not to use it.
func NoTrace(r dnsx.Resolver) dnsx.Resolver { return plainResolver{r} }

type plainResolver struct{ dnsx.Resolver }
