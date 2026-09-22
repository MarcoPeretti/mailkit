// Package publicres resolves DNS against nameservers chosen by the caller.
//
// It exists because a survey of many domains needs four things the standard
// library cannot provide:
//
//   - the response code, so that "this name does not exist" and "this name
//     exists but has no records of that type" can be told apart. RFC 7208
//     section 4.6.4 defines the void-lookup limit in terms of that difference,
//     and net.DNSError collapses both into one boolean;
//   - the TTL, without which a cache cannot honour a zone's own expiry;
//   - explicit nameserver selection, because thousands of domains resolved
//     through a home router's forwarder will be throttled into returning
//     failures -- which, under an honest reading, turns our own infrastructure
//     problem into thousands of "we could not check" results;
//   - per-query timeout and retry, independent of the deadline bounding the
//     whole domain.
//
// It is the only package in mailkit that imports a DNS library. Everything
// else takes a dnsx.Resolver, so a caller happy with the standard library pays
// nothing for this one existing.
package publicres

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/MarcoPeretti/mailkit/dnsx"
)

// DefaultServers are the public recursive resolvers used when none are given:
// Cloudflare, Google and Quad9.
//
// Three rather than one, because a retry that stays on the same server retries
// the thing that just failed. Rotating across operators means one recursor
// having a bad minute degrades into a slower answer rather than a wrong one.
var DefaultServers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// Config configures a Resolver.
type Config struct {
	// Servers are host:port nameservers, tried in rotation.
	Servers []string

	// Timeout bounds a single query. It is deliberately separate from the
	// context deadline, which bounds everything a caller is doing with one
	// domain: one slow name must not consume the whole domain's budget.
	Timeout time.Duration

	// Attempts is the total number of tries per query, each on the next
	// server in rotation.
	Attempts int

	// UDPSize advertises an EDNS0 buffer size. 1232 is the DNS flag day
	// recommendation: large enough for the SPF and DMARC records this module
	// asks for, small enough to avoid fragmentation.
	UDPSize uint16
}

func (c Config) withDefaults() Config {
	if len(c.Servers) == 0 {
		c.Servers = DefaultServers
	}
	for i, s := range c.Servers {
		if !strings.Contains(s, ":") {
			c.Servers[i] = s + ":53"
		}
	}
	if c.Timeout <= 0 {
		c.Timeout = 3 * time.Second
	}
	if c.Attempts <= 0 {
		c.Attempts = 2
	}
	if c.UDPSize == 0 {
		c.UDPSize = 1232
	}
	return c
}

// Resolver queries a rotation of nameservers.
type Resolver struct {
	cfg  Config
	udp  *dns.Client
	tcp  *dns.Client
	next atomic.Uint64
}

var (
	_ dnsx.Resolver        = (*Resolver)(nil)
	_ dnsx.TracingResolver = (*Resolver)(nil)
)

// New returns a Resolver. It is safe for concurrent use by many goroutines,
// which is the point: one instance is shared by every worker so the rotation
// and any wrapping cache are global rather than per-worker.
func New(cfg Config) *Resolver {
	cfg = cfg.withDefaults()
	return &Resolver{
		cfg: cfg,
		udp: &dns.Client{Net: "udp", Timeout: cfg.Timeout},
		tcp: &dns.Client{Net: "tcp", Timeout: cfg.Timeout},
	}
}

// Servers returns the configured nameservers, for recording on a run so a
// result is reproducible.
func (r *Resolver) Servers() []string { return append([]string(nil), r.cfg.Servers...) }

// Query implements dnsx.TracingResolver.
func (r *Resolver) Query(ctx context.Context, name string, qtype uint16) (*dnsx.Answer, error) {
	fqdn := dns.Fqdn(dnsx.Normalize(name))
	if fqdn == "." {
		return nil, &net.DNSError{Err: "empty name", Name: name, IsNotFound: true}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, qtype)
	msg.SetEdns0(r.cfg.UDPSize, false)
	msg.RecursionDesired = true

	var lastErr error
	for attempt := 0; attempt < r.cfg.Attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		server := r.cfg.Servers[int(r.next.Add(1)-1)%len(r.cfg.Servers)]

		resp, err := r.exchange(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}

		switch resp.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			return answerFrom(resp, name, qtype, server), nil
		case dns.RcodeServerFailure, dns.RcodeRefused:
			// A server that failed or refused has not answered the question.
			// Try the next one rather than reporting its mood as the zone's
			// content.
			lastErr = &net.DNSError{
				Err:         fmt.Sprintf("%s from %s", dns.RcodeToString[resp.Rcode], server),
				Name:        name,
				Server:      server,
				IsTemporary: true,
			}
			continue
		default:
			return nil, &net.DNSError{
				Err:    fmt.Sprintf("%s from %s", dns.RcodeToString[resp.Rcode], server),
				Name:   name,
				Server: server,
			}
		}
	}
	if lastErr == nil {
		lastErr = &net.DNSError{Err: "no answer", Name: name, IsTemporary: true}
	}
	return nil, lastErr
}

func (r *Resolver) exchange(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	qctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	resp, _, err := r.udp.ExchangeContext(qctx, msg, server)
	if err != nil {
		return nil, wrapNet(err, msg, server)
	}
	if resp.Truncated {
		// A truncated answer is not a short answer, it is an incomplete one.
		// Long TXT records -- exactly what this module reads -- are the common
		// cause, so retry over TCP rather than parse what arrived.
		resp, _, err = r.tcp.ExchangeContext(qctx, msg, server)
		if err != nil {
			return nil, wrapNet(err, msg, server)
		}
	}
	return resp, nil
}

func wrapNet(err error, msg *dns.Msg, server string) error {
	name := strings.TrimSuffix(msg.Question[0].Name, ".")
	timeout := false
	if ne, ok := err.(net.Error); ok {
		timeout = ne.Timeout()
	}
	return &net.DNSError{
		Err:         err.Error(),
		Name:        name,
		Server:      server,
		IsTimeout:   timeout,
		IsTemporary: true,
	}
}

func answerFrom(resp *dns.Msg, name string, qtype uint16, server string) *dnsx.Answer {
	a := &dnsx.Answer{Name: dnsx.Normalize(name), Qtype: qtype, RCode: resp.Rcode, Server: server}

	for _, rr := range resp.Answer {
		if a.TTL == 0 || rr.Header().Ttl < a.TTL {
			a.TTL = rr.Header().Ttl
		}
		switch v := rr.(type) {
		case *dns.TXT:
			// A TXT record is a sequence of strings which the zone's author
			// wrote as one value split at 255 bytes. Joining them is what the
			// standard library does, and what every SPF implementation does,
			// because a long SPF record is otherwise unreadable.
			a.TXT = append(a.TXT, strings.Join(v.Txt, ""))
		case *dns.MX:
			a.MX = append(a.MX, &net.MX{Host: strings.TrimSuffix(v.Mx, "."), Pref: v.Preference})
		case *dns.A:
			a.Hosts = append(a.Hosts, v.A.String())
		case *dns.AAAA:
			a.Hosts = append(a.Hosts, v.AAAA.String())
		case *dns.PTR:
			a.Hosts = append(a.Hosts, strings.TrimSuffix(v.Ptr, "."))
		case *dns.NS:
			a.Hosts = append(a.Hosts, strings.TrimSuffix(v.Ns, "."))
		case *dns.CNAME:
			// Followed by the recursor, so the records above are the
			// target's. The first hop is kept because it is the one thing
			// the owner wrote, and for a DKIM key it names the vendor.
			if a.CNAME == "" {
				a.CNAME = dnsx.Normalize(v.Target)
			}
		}
	}
	return a
}

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

// LookupHost implements dnsx.Resolver, asking for A and then AAAA.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	a, err := r.Query(ctx, host, dnsx.TypeA)
	if err != nil {
		return nil, err
	}
	hosts := a.Hosts
	if len(hosts) == 0 {
		if a6, err6 := r.Query(ctx, host, dnsx.TypeAAAA); err6 == nil {
			hosts = a6.Hosts
		}
	}
	if len(hosts) == 0 {
		return nil, notFound(host)
	}
	return hosts, nil
}

// LookupAddr implements dnsx.Resolver.
func (r *Resolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	arpa, err := dns.ReverseAddr(addr)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: addr}
	}
	a, qerr := r.Query(ctx, strings.TrimSuffix(arpa, "."), dnsx.TypePTR)
	if qerr != nil {
		return nil, qerr
	}
	if a.RCode == dnsx.RcodeNameError || len(a.Hosts) == 0 {
		return nil, notFound(addr)
	}
	return a.Hosts, nil
}
