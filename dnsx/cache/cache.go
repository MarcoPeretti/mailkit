// Package cache wraps a resolver with a process-wide, TTL-aware answer cache.
//
// For a survey of many domains this is not an optimisation, it is politeness.
// SPF trees converge hard: _spf.google.com, spf.protection.outlook.com,
// sendgrid.net and servers.mcsv.net appear across a large share of all SPF
// records in existence, and spf.protection.outlook.com alone fans out to
// several sub-includes for every Microsoft 365 domain that names it. Walking a
// few thousand domains without a cache means asking Microsoft the same question
// tens of thousands of times in a few minutes, which is a denial of service
// wearing a survey's clothes.
//
// One rule governs everything here, and it is easy to get wrong in a way that
// silently corrupts the product's central number:
//
//	The cache serves the network fetch. It must NEVER reduce the lookup count.
//
// RFC 7208's limit of ten counts terms evaluated, not packets sent. A record
// that includes the same target twice spends two of its ten, even though any
// real resolver answers the second from memory. Callers therefore count before
// they ask, and this package deliberately offers no way to observe whether an
// answer was cached.
package cache

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"github.com/MarcoPeretti/mailkit/dnsx"
)

// Config tunes a Cache.
type Config struct {
	// MinTTL floors a record's own TTL. Some ESPs publish 30-second TTLs on
	// records that change a few times a year; honouring those literally would
	// re-ask constantly for no benefit to anyone.
	MinTTL time.Duration

	// MaxTTL ceilings it. A survey should not act on a view of DNS older than
	// its own run.
	MaxTTL time.Duration

	// NegativeTTL applies to NXDOMAIN and empty answers, which are cached --
	// they are answers. Failures are not cached at all; see Get.
	NegativeTTL time.Duration

	// MaxEntries bounds the map. On overflow a portion is dropped at random
	// rather than by recency: tracking recency costs a write on every read,
	// and for a run whose working set fits comfortably the eviction path is
	// never reached anyway.
	MaxEntries int
}

func (c Config) withDefaults() Config {
	if c.MinTTL <= 0 {
		c.MinTTL = 60 * time.Second
	}
	if c.MaxTTL <= 0 {
		c.MaxTTL = time.Hour
	}
	if c.NegativeTTL <= 0 {
		c.NegativeTTL = 5 * time.Minute
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = 200_000
	}
	return c
}

// Stats reports what the cache did, so that a run can log its hit rate rather
// than leave it to be assumed.
type Stats struct {
	Hits, Misses, Negative, Evictions, Collapsed int64
}

type entry struct {
	answer  *dnsx.Answer
	expires time.Time

	// hits counts how often this entry was served. Only entries that were
	// actually reused are worth carrying between processes; see WriteTo.
	hits int
}

type key struct {
	qtype uint16
	name  string
}

// Cache wraps a resolver. It implements dnsx.Resolver, and dnsx.TracingResolver
// when the wrapped resolver does.
type Cache struct {
	inner  dnsx.Resolver
	tracer dnsx.TracingResolver
	cfg    Config
	now    func() time.Time

	mu      sync.Mutex
	entries map[key]entry
	waiters map[key]chan struct{} // in-flight lookups, for collapsing
	stats   Stats
}

var _ dnsx.Resolver = (*Cache)(nil)

// New wraps r.
func New(r dnsx.Resolver, cfg Config) *Cache {
	c := &Cache{
		inner:   r,
		cfg:     cfg.withDefaults(),
		now:     time.Now,
		entries: make(map[key]entry),
		waiters: make(map[key]chan struct{}),
	}
	if t, ok := r.(dnsx.TracingResolver); ok {
		c.tracer = t
	}
	return c
}

// Stats returns a snapshot.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// Query implements dnsx.TracingResolver when the wrapped resolver can.
//
// Note there is no "was this cached" in the result. That is deliberate: the
// only caller who could act on it is the lookup counter, and it must not.
func (c *Cache) Query(ctx context.Context, name string, qtype uint16) (*dnsx.Answer, error) {
	if c.tracer == nil {
		return nil, &net.DNSError{Err: "cache: wrapped resolver cannot report response codes", Name: name}
	}
	k := key{qtype: qtype, name: dnsx.Normalize(name)}

	for {
		if a, ok := c.get(k); ok {
			return a, nil
		}
		wait, leader := c.claim(k)
		if !leader {
			// Another goroutine is already asking this exact question. Wait for
			// it rather than adding a duplicate query to the wire: on a cold
			// start every worker reaches _spf.google.com at once, and without
			// this they would all ask.
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		a, err := c.tracer.Query(ctx, k.name, qtype)
		c.release(k)
		if err != nil {
			// A failure is not stored. A lookup that did not complete says
			// nothing about the zone, and caching it would turn one bad moment
			// into a run-long blind spot for that name.
			return nil, err
		}
		c.put(k, a)
		return a, nil
	}
}

func (c *Cache) get(k key) (*dnsx.Answer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok {
		c.stats.Misses++
		return nil, false
	}
	if c.now().After(e.expires) {
		delete(c.entries, k)
		c.stats.Misses++
		return nil, false
	}
	c.stats.Hits++
	e.hits++
	c.entries[k] = e
	return e.answer, true
}

func (c *Cache) put(k key, a *dnsx.Answer) {
	ttl := time.Duration(a.TTL) * time.Second
	if a.Empty() {
		// NXDOMAIN and NODATA are answers and are cached, but for less time:
		// a name that does not exist yet is the one most likely to start
		// existing during a long run.
		ttl = c.cfg.NegativeTTL
		c.mu.Lock()
		c.stats.Negative++
		c.mu.Unlock()
	} else {
		if ttl < c.cfg.MinTTL {
			ttl = c.cfg.MinTTL
		}
		if ttl > c.cfg.MaxTTL {
			ttl = c.cfg.MaxTTL
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.cfg.MaxEntries {
		c.evictLocked()
	}
	c.entries[k] = entry{answer: a, expires: c.now().Add(ttl)}
}

// evictLocked drops expired entries, and if that was not enough, drops entries
// in map order until the cache is back under half its bound.
func (c *Cache) evictLocked() {
	now := c.now()
	for k, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, k)
			c.stats.Evictions++
		}
	}
	target := c.cfg.MaxEntries / 2
	for k := range c.entries {
		if len(c.entries) <= target {
			break
		}
		delete(c.entries, k)
		c.stats.Evictions++
	}
}

// claim returns a channel to wait on, and whether this caller is the one that
// should perform the lookup.
func (c *Cache) claim(k key) (<-chan struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok := c.waiters[k]; ok {
		c.stats.Collapsed++
		return ch, false
	}
	ch := make(chan struct{})
	c.waiters[k] = ch
	return ch, true
}

func (c *Cache) release(k key) {
	c.mu.Lock()
	ch := c.waiters[k]
	delete(c.waiters, k)
	c.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

// The dnsx.Resolver methods below go through Query when the wrapped resolver
// supports it, and fall through uncached otherwise -- a cache that cannot see
// response codes cannot tell an empty answer from a missing name, and guessing
// is worse than not caching.

func (c *Cache) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if c.tracer == nil {
		return c.inner.LookupTXT(ctx, name)
	}
	a, err := c.Query(ctx, name, dnsx.TypeTXT)
	if err != nil {
		return nil, err
	}
	if a.RCode == dnsx.RcodeNameError {
		return nil, notFound(name)
	}
	return a.TXT, nil
}

func (c *Cache) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if c.tracer == nil {
		return c.inner.LookupMX(ctx, name)
	}
	a, err := c.Query(ctx, name, dnsx.TypeMX)
	if err != nil {
		return nil, err
	}
	if a.RCode == dnsx.RcodeNameError {
		return nil, notFound(name)
	}
	return a.MX, nil
}

func (c *Cache) LookupHost(ctx context.Context, host string) ([]string, error) {
	if c.tracer == nil {
		return c.inner.LookupHost(ctx, host)
	}
	a, err := c.Query(ctx, host, dnsx.TypeA)
	if err != nil {
		return nil, err
	}
	if a.RCode == dnsx.RcodeNameError || len(a.Hosts) == 0 {
		return nil, notFound(host)
	}
	return a.Hosts, nil
}

func (c *Cache) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	// Reverse lookups are not part of any hot path here, and the arpa-name
	// construction lives in the wrapped resolver. Pass it straight through.
	return c.inner.LookupAddr(ctx, addr)
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// persisted is one cache entry on the wire.
type persisted struct {
	Qtype   uint16       `json:"qtype"`
	Name    string       `json:"name"`
	Expires time.Time    `json:"expires"`
	Hits    int          `json:"hits"`
	Answer  *dnsx.Answer `json:"answer"`
}

// WriteTo saves the reusable part of the cache.
//
// Only entries that were served at least once are written, and that is the
// whole design rather than a size optimisation. In a survey of many domains
// most names are asked about exactly once -- measured over ten thousand
// domains, four names in five -- so carrying them to the next process would
// mean writing a large file whose contents will never be read again. What is
// worth carrying is the small set that many domains share: the handful of ESP
// records that thousands of SPF trees all include.
//
// Expiry is written as an absolute time and honoured on load, so a saved cache
// cannot be used to serve records past the TTL their zone published. A cache
// that outlived its TTLs would not be a faster crawl, it would be a crawl
// reporting yesterday's DNS as today's.
func (c *Cache) WriteTo(w io.Writer) (int64, error) {
	c.mu.Lock()
	now := c.now()
	out := make([]persisted, 0, 128)
	for k, e := range c.entries {
		if e.hits == 0 || now.After(e.expires) {
			continue
		}
		out = append(out, persisted{Qtype: k.qtype, Name: k.name, Expires: e.expires, Hits: e.hits, Answer: e.answer})
	}
	c.mu.Unlock()

	cw := &countingWriter{w: w}
	err := json.NewEncoder(cw).Encode(out)
	return cw.n, err
}

// ReadFrom loads a previously saved cache, dropping anything already expired.
func (c *Cache) ReadFrom(r io.Reader) (int64, error) {
	cr := &countingReader{r: r}
	var in []persisted
	if err := json.NewDecoder(cr).Decode(&in); err != nil {
		return cr.n, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for _, p := range in {
		if now.After(p.Expires) || p.Answer == nil {
			continue
		}
		c.entries[key{qtype: p.Qtype, name: p.Name}] = entry{answer: p.Answer, expires: p.Expires, hits: p.Hits}
	}
	return cr.n, nil
}

// Len reports how many entries are held.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
