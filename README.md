# mailkit

Go libraries for reading the DNS records that decide whether mail is
authenticated: SPF, DMARC, DKIM and MX.

```sh
go get github.com/MarcoPeretti/mailkit
```

It reads and parses; it does not judge. Turning a record into a verdict depends
on who is asking — a domain's owner being shown how to fix their mail and an
operator ranking prospects want different severities for the same fact — so
evaluation lives with each consumer.

## What is here that the standard library cannot do

### `spf` — a recursive lookup count

RFC 7208 §4.6.4 permits ten DNS-costing terms. Counting the terms in a domain's
own record is a lower bound, because includes contain includes:

```go
res := spf.Evaluate(ctx, resolver, "example.com", spf.DefaultLimits())
fmt.Println(res.Terms, res.TermsExact)   // 11 true
```

A record that lists ten includes reads as "at the limit" and may really cost
fourteen. Past ten a receiver stops and returns permerror, so the terms after
that point — often including the `all` mechanism — are never evaluated at all,
and nothing in the domain's own record shows it.

`Result.Nodes` is the whole walk in visit order, each node carrying the running
term count, so the number can be shown rather than asserted:

```
 1   include spfa.cpmails.com
 2     include spfa-a.cpmails.com
 6   exists  %{i}._spf.mta.salesforce.com   (macro: counted, not resolvable)
11 ✗ include sendgrid.net                   ← limit; nothing after this is evaluated
```

It also reports multiple records (§4.5: two records mean none), includes that
resolve to nothing, include cycles, void lookups, and whether the count is
exact.

### `dnsx` — response codes and TTLs

`net.Resolver` reports neither. That matters because §4.6.4's void-lookup limit
is defined on response codes — "RCODE 0 with an answer count of 0, or a Name
Error" — and `net.DNSError.IsNotFound` is true for both and distinguishes
neither.

```go
type Resolver interface {           // *net.Resolver satisfies this as-is
    LookupTXT(ctx, name) ([]string, error)
    LookupHost(ctx, host) ([]string, error)
    LookupMX(ctx, name) ([]*net.MX, error)
    LookupAddr(ctx, addr) ([]string, error)
}

type TracingResolver interface {    // dnsx/publicres implements this
    Resolver
    Query(ctx, name string, qtype uint16) (*Answer, error)
}
```

Every signature in `Resolver` is the standard library's, deliberately, so a
caller already holding a `*net.Resolver` needs no adapter. Everything miekg/dns
can do that the standard library cannot lives behind the optional
`TracingResolver`, discovered by type assertion — and a consumer that cannot
provide it is told its void count is approximate rather than handed a guess.

Subpackages:

| Package | |
|---|---|
| `dnsx/publicres` | miekg/dns against nameservers you choose, with rotation, retry and TCP fallback. **The only package that imports a DNS library**, so a consumer that does not need it pays nothing. |
| `dnsx/cache` | TTL-aware, negative-caching, request-collapsing wrapper |
| `dnsx/dnstest` | a static zone for tests, able to express NXDOMAIN, NODATA and timeouts separately |

### `mailauth`, `mx`, `provider`, `finding`

- **`mailauth`** — SPF, DMARC and DKIM record parsing, plus the RFC 9989 §4.10
  DNS tree walk for organizational domains, which replaced the public suffix
  list.
- **`mx`** — inbound routing, handling implicit MX (RFC 5321 §5.1), null MX
  (RFC 7505) and address literals. It returns flags rather than findings, and
  puts the result in a canonical order: resolvers shuffle equal-preference
  records on purpose, so a description that changes between runs is not a
  description.
- **`provider`** — identifies the service behind a record, from an embedded
  table. **Separate tables for MX and SPF**, because MX names who *receives*
  and SPF names who may *send*. A merged table would let an MX host answer an
  outbound question, and be wrong about exactly the organisations worth
  noticing — the ones running a marketing stack alongside a mailbox provider.
- **`finding`** — a code, a severity and parameters, with no prose. Supply a
  `Renderer` to add words, or none and store the codes.

## The rule running through all of it

**Unknown is not pass, and unknown is not fail.**

A lookup that did not answer is never a verdict. `spf.Evaluate` returns no
error: a failure is recorded in `Result.TempError`, and when it is set the term
count, the broken includes and the limit verdict are all suppressed. Telling
someone their provider's include is dead because a resolver had a bad second is
the most damaging thing a tool like this can do.

The same rule appears wherever the two could be confused: `dnsx.NotFound` and
`dnsx.Unanswered` are deliberately not each other's negation; an unrecognised
error classifies as "could not ask" rather than "does not exist"; and a walk
that stopped early reports `TermsExact = false` rather than a tidy number.

## Testing

Nothing here contacts a third party from a test. `dnsx/dnstest` provides a
static zone that can express the distinctions that matter — a name that does not
exist, a name that exists with no records of the type asked for, a nameserver
that times out — and returns an ordered query log, because for an SPF evaluator
*how many* lookups were made is the verdict, not a performance detail.
`dnsx/publicres` tests run against a nameserver started inside the test process
and bound to loopback.

```sh
go test ./...
```

## A note on the `provider` package's name

A directory named `vendor` at the root of a module belongs to the Go toolchain:
`go mod vendor` deletes and recreates it. A package living there is destroyed
the first time any contributor runs a routine command, silently and with no
error. Hence `provider`.

## Status

`v0.x`, which is not modesty: `dnsx.Resolver` will gain methods, and the seams
have so far been proven by one consumer. Pin an exact version.
