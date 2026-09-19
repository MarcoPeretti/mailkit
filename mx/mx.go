// Package mx reads a domain's inbound mail routing.
//
// It reports facts and flags rather than findings, because the same fact earns
// a different severity depending on who is reading. A domain with no MX at all
// is a defect worth telling its owner about, and to someone building a list of
// companies to approach it is a reason to skip the row entirely. Turning flags
// into findings is each consumer's job.
//
// What this package will not do is treat MX as a map of who sends for a domain.
// MX names who RECEIVES mail; SPF names who may SEND as the domain. They are
// frequently different, and they are most different at exactly the companies
// worth paying attention to -- the ones running a marketing stack alongside
// their mailbox provider.
package mx

import (
	"context"
	"net"
	"sort"
	"strings"

	"github.com/MarcoPeretti/mailkit/dnsx"
)

// Host is one inbound mail host.
type Host struct {
	Host string
	Pref uint16
	IPs  []string

	// Implicit is true when the domain publishes no MX and the domain's own
	// address record is standing in for one (RFC 5321 section 5.1).
	Implicit bool
}

// Flags are the observations a caller may want to report on.
type Flags struct {
	// Missing: the domain publishes neither MX nor address records, so there
	// is nowhere for mail to go.
	Missing bool

	// Null: a single "." target, RFC 7505's way of saying the domain accepts
	// no mail at all. That is a deliberate configuration rather than a defect,
	// though it does mean replies bounce.
	Null bool

	// Implicit: no MX, but the domain's own address record serves instead.
	Implicit bool

	// SingleHost: only one inbound host, so there is no failover.
	SingleHost bool

	// IPLiteral lists MX targets that are address literals, which RFC 1035
	// does not permit and many senders refuse outright.
	IPLiteral []string

	// Unresolvable lists MX targets that do not resolve to any address. Mail
	// to the domain queues and then bounces.
	Unresolvable []string

	// Incomplete is set when a lookup did not answer.
	//
	// When it is set, every other flag must be read as unknown rather than
	// false: we could not ask, which is not the same as having looked and
	// found nothing.
	Incomplete bool

	// Error carries why, when Incomplete is set.
	Error string
}

// Lookup reads the inbound mail routing for domain.
//
// It returns no error: a failure to resolve is recorded in Flags.Incomplete,
// because a caller that treats a returned error as "this domain has no MX"
// would manufacture a finding out of its own network trouble.
func Lookup(ctx context.Context, r dnsx.Resolver, domain string) ([]Host, Flags) {
	domain = dnsx.Normalize(domain)
	var f Flags

	mxs, err := r.LookupMX(ctx, domain)
	if err != nil && !dnsx.NotFound(err) {
		f.Incomplete, f.Error = true, err.Error()
		return nil, f
	}

	if len(mxs) == 0 {
		return implicitMX(ctx, r, domain, &f)
	}

	// RFC 7505: a single "." target declares that the domain accepts no mail.
	if len(mxs) == 1 && strings.TrimSuffix(mxs[0].Host, ".") == "" {
		f.Null = true
		return nil, f
	}

	var hosts []Host
	for _, m := range mxs {
		host := strings.TrimSuffix(m.Host, ".")
		rec := Host{Host: host, Pref: m.Pref}

		if net.ParseIP(host) != nil {
			f.IPLiteral = append(f.IPLiteral, host)
			hosts = append(hosts, rec)
			continue
		}

		ips, err := r.LookupHost(ctx, host)
		switch {
		case dnsx.NotFound(err) || (err == nil && len(ips) == 0):
			f.Unresolvable = append(f.Unresolvable, host)
		case err != nil:
			f.Incomplete, f.Error = true, err.Error()
		default:
			rec.IPs = ips
		}
		hosts = append(hosts, rec)
	}

	f.SingleHost = len(hosts) == 1
	sortHosts(hosts)
	return hosts, f
}

func implicitMX(ctx context.Context, r dnsx.Resolver, domain string, f *Flags) ([]Host, Flags) {
	// RFC 5321 section 5.1: with no MX, the domain's own address record is the
	// implicit MX. Only a domain with neither publishes nowhere for mail to go.
	ips, err := r.LookupHost(ctx, domain)
	switch {
	case err != nil && !dnsx.NotFound(err):
		f.Incomplete, f.Error = true, err.Error()
		return nil, *f
	case len(ips) == 0:
		f.Missing = true
		return nil, *f
	}
	sort.Strings(ips)
	f.Implicit, f.SingleHost = true, true
	return []Host{{Host: domain, Pref: 0, IPs: ips, Implicit: true}}, *f
}

// sortHosts puts the list in a canonical order, because the resolver's order is
// deliberately not one.
//
// net.Resolver.LookupMX shuffles equal-preference records before sorting by
// preference, which is RFC 5321 telling a *sender* to spread load across equal
// hosts. We are describing a configuration rather than delivering to it, and a
// description that comes out differently each time is not a description: a
// Google Workspace domain, with two hosts at preference 5 and two at 10,
// otherwise reports itself as changed on every scan while nobody has touched
// DNS. The same applies to the addresses under each host, which resolvers
// rotate for the same reason.
func sortHosts(hosts []Host) {
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Pref != hosts[j].Pref {
			return hosts[i].Pref < hosts[j].Pref
		}
		return hosts[i].Host < hosts[j].Host
	})
	for i := range hosts {
		sort.Strings(hosts[i].IPs)
	}
}

// Hosts returns just the hostnames, in canonical order.
func Hosts(hosts []Host) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h.Host)
	}
	return out
}
