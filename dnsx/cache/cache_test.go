package cache

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MarcoPeretti/mailkit/dnsx"
	"github.com/MarcoPeretti/mailkit/dnsx/dnstest"
	"github.com/MarcoPeretti/mailkit/spf"
)

func zone() dnstest.Zone {
	return dnstest.Zone{
		TXT: map[string][]string{
			"example.com":     {"v=spf1 include:_spf.google.com -all"},
			"_spf.google.com": {"v=spf1 ip4:35.190.247.0/24 ~all"},
			"nodata.example":  {"not an spf record"},
		},
		TTL: map[string]uint32{"_spf.google.com": 300},
	}
}

func TestRepeatedLookupsHitTheCache(t *testing.T) {
	inner := dnstest.New(zone())
	c := New(inner, Config{})
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := c.LookupTXT(ctx, "_spf.google.com"); err != nil {
			t.Fatal(err)
		}
	}
	if n := inner.CountOf(dnsx.TypeTXT, "_spf.google.com"); n != 1 {
		t.Errorf("the wrapped resolver was asked %d times, want 1", n)
	}
	if s := c.Stats(); s.Hits != 4 || s.Misses != 1 {
		t.Errorf("Stats = %+v, want 4 hits and 1 miss", s)
	}
}

// The rule the whole package is built around. A cached answer must shorten the
// query log and leave the lookup count untouched, because RFC 7208 counts terms
// evaluated rather than packets sent.
func TestCacheDoesNotReduceTermCount(t *testing.T) {
	// A diamond: shared.example is reached down two branches.
	z := dnstest.Zone{TXT: map[string][]string{
		"example.com":    {"v=spf1 include:a.example include:b.example -all"},
		"a.example":      {"v=spf1 include:shared.example -all"},
		"b.example":      {"v=spf1 include:shared.example -all"},
		"shared.example": {"v=spf1 ip4:192.0.2.0/24 -all"},
	}}

	plain := dnstest.New(z)
	uncached := spf.Evaluate(context.Background(), plain, "example.com", spf.DefaultLimits())

	inner := dnstest.New(z)
	cached := spf.Evaluate(context.Background(), New(inner, Config{}), "example.com", spf.DefaultLimits())

	if cached.Terms != uncached.Terms {
		t.Fatalf("Terms with cache = %d, without = %d\n\n"+
			"Caching must never change the count. If it does, every domain whose\n"+
			"providers share infrastructure is reported as cheaper than it is.",
			cached.Terms, uncached.Terms)
	}
	if cached.Terms != 4 {
		t.Errorf("Terms = %d, want 4", cached.Terms)
	}

	// The saving shows up on the wire, which is the only place it should.
	if got := inner.CountOf(dnsx.TypeTXT, "shared.example"); got != 1 {
		t.Errorf("shared.example was queried %d times through the cache, want 1", got)
	}
	if got := plain.CountOf(dnsx.TypeTXT, "shared.example"); got != 2 {
		t.Errorf("shared.example was queried %d times without the cache, want 2", got)
	}
}

// A lookup that did not complete says nothing about the zone. Caching it would
// turn one bad moment into a run-long blind spot for that name.
func TestFailuresAreNotCached(t *testing.T) {
	z := zone()
	z.Fail = map[string]string{"flaky.example": dnstest.FailServFail}
	inner := dnstest.New(z)
	c := New(inner, Config{})

	for i := 0; i < 3; i++ {
		if _, err := c.LookupTXT(context.Background(), "flaky.example"); err == nil {
			t.Fatal("expected an error")
		}
	}
	if n := inner.CountOf(dnsx.TypeTXT, "flaky.example"); n != 3 {
		t.Errorf("a failing name was asked %d times, want 3: failures must not be cached", n)
	}
}

// NXDOMAIN and NODATA are answers, and are cached -- just for less time.
func TestNegativeAnswersAreCached(t *testing.T) {
	inner := dnstest.New(zone())
	c := New(inner, Config{})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := c.LookupTXT(ctx, "absent.example"); !dnsx.NotFound(err) {
			t.Fatalf("want NotFound, got %v", err)
		}
	}
	if n := inner.CountOf(dnsx.TypeTXT, "absent.example"); n != 1 {
		t.Errorf("NXDOMAIN was asked %d times, want 1", n)
	}
	if c.Stats().Negative == 0 {
		t.Error("a negative answer was not recorded as such")
	}
}

func TestEntriesExpire(t *testing.T) {
	inner := dnstest.New(zone())
	c := New(inner, Config{MinTTL: time.Second, MaxTTL: time.Second})

	now := time.Now()
	c.now = func() time.Time { return now }

	ctx := context.Background()
	if _, err := c.LookupTXT(ctx, "_spf.google.com"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err := c.LookupTXT(ctx, "_spf.google.com"); err != nil {
		t.Fatal(err)
	}
	if n := inner.CountOf(dnsx.TypeTXT, "_spf.google.com"); n != 2 {
		t.Errorf("asked %d times across an expiry, want 2", n)
	}
}

func TestTTLIsClampedToConfiguredRange(t *testing.T) {
	z := zone()
	z.TTL["_spf.google.com"] = 30 // shorter than MinTTL below
	inner := dnstest.New(z)
	c := New(inner, Config{MinTTL: 5 * time.Minute, MaxTTL: time.Hour})

	now := time.Now()
	c.now = func() time.Time { return now }
	ctx := context.Background()

	if _, err := c.LookupTXT(ctx, "_spf.google.com"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute) // past the record's own TTL, inside MinTTL
	if _, err := c.LookupTXT(ctx, "_spf.google.com"); err != nil {
		t.Fatal(err)
	}
	if n := inner.CountOf(dnsx.TypeTXT, "_spf.google.com"); n != 1 {
		t.Errorf("asked %d times, want 1: a 30s TTL should have been floored to MinTTL", n)
	}
}

// blocking wraps a resolver and holds the first query open until released, so
// that concurrent callers genuinely pile up behind one in-flight lookup.
//
// Without this the test would pass on caching alone: the static fake answers
// instantly, the first goroutine finishes before the rest start, and nothing
// ever collapses. A test that cannot fail for the reason it names is not
// testing that reason.
type blocking struct {
	dnsx.TracingResolver
	release chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (b *blocking) Query(ctx context.Context, name string, qtype uint16) (*dnsx.Answer, error) {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return b.TracingResolver.Query(ctx, name, qtype)
}

// On a cold start every worker reaches the same popular include at once.
// Without collapsing, they all ask -- which for _spf.google.com across a real
// run is thousands of duplicate queries in a few seconds.
func TestConcurrentLookupsCollapseToOneQuery(t *testing.T) {
	inner := dnstest.New(zone())
	b := &blocking{
		TracingResolver: inner,
		release:         make(chan struct{}),
		entered:         make(chan struct{}),
	}
	c := New(b, Config{})

	const callers = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := c.LookupTXT(context.Background(), "_spf.google.com"); err != nil {
				t.Error(err)
			}
		}()
	}
	close(start)

	// Wait until the first lookup is in flight AND every other caller has
	// queued behind it.
	//
	// Waiting for a single collapse is not enough: a caller that had not yet
	// reached the cache when the leader finished would find no entry and no
	// waiter, and become a second leader. That is a real race in the test
	// rather than in the cache, and it makes the result depend on scheduling.
	<-b.entered
	waitFor(t, func() bool { return c.Stats().Collapsed >= callers-1 })
	close(b.release)
	wg.Wait()

	if n := inner.CountOf(dnsx.TypeTXT, "_spf.google.com"); n != 1 {
		t.Errorf("%d concurrent lookups made %d queries, want 1", callers, n)
	}
	if got := c.Stats().Collapsed; got == 0 {
		t.Error("no collapsed lookups recorded, so the queries were saved by caching rather than by collapsing")
	}
}

// waitFor polls cond until it holds, failing the test if it never does.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for callers to queue behind the in-flight lookup")
}

func TestEvictionKeepsTheCacheBounded(t *testing.T) {
	z := dnstest.Zone{TXT: map[string][]string{}}
	for i := 0; i < 200; i++ {
		z.TXT[name(i)] = []string{"v=spf1 -all"}
	}
	c := New(dnstest.New(z), Config{MaxEntries: 50})

	for i := 0; i < 200; i++ {
		if _, err := c.LookupTXT(context.Background(), name(i)); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > 50 {
		t.Errorf("cache holds %d entries, want at most 50", n)
	}
	if c.Stats().Evictions == 0 {
		t.Error("no evictions recorded despite exceeding the bound")
	}
}

func name(i int) string {
	return string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26)) + ".example"
}

// A saved cache is what lets a resumed run start warm. Without it, an
// interrupted crawl re-fetches every popular ESP record from scratch.
func TestCacheSurvivesAProcess(t *testing.T) {
	first := dnstest.New(zone())
	a := New(first, Config{})
	ctx := context.Background()

	// Asked twice, so it counts as reused and is worth carrying.
	for i := 0; i < 2; i++ {
		if _, err := a.LookupTXT(ctx, "_spf.google.com"); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	if _, err := a.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("nothing was written")
	}

	// A new process: new cache, new resolver.
	second := dnstest.New(zone())
	b := New(second, Config{})
	if _, err := b.ReadFrom(&buf); err != nil {
		t.Fatal(err)
	}
	if _, err := b.LookupTXT(ctx, "_spf.google.com"); err != nil {
		t.Fatal(err)
	}
	if n := second.CountOf(dnsx.TypeTXT, "_spf.google.com"); n != 0 {
		t.Errorf("the resumed run made %d queries for a name it had already learned", n)
	}
}

// Most names in a survey are asked about exactly once. Carrying them would
// mean writing a large file whose contents are never read again.
func TestOnlyReusedEntriesArePersisted(t *testing.T) {
	inner := dnstest.New(zone())
	c := New(inner, Config{})
	ctx := context.Background()

	// Asked once: no evidence anybody will want it again.
	if _, err := c.LookupTXT(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	// Asked twice: shared, and worth keeping.
	for i := 0; i < 2; i++ {
		if _, err := c.LookupTXT(ctx, "_spf.google.com"); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	if _, err := c.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	if !strings.Contains(body, "_spf.google.com") {
		t.Error("a reused entry was not saved")
	}
	if strings.Contains(body, `"name":"example.com"`) {
		t.Error("an entry asked for exactly once was saved; it will never be read again")
	}
}

// A cache that outlived its TTLs would not be a faster crawl, it would be a
// crawl reporting yesterday's DNS as today's.
func TestExpiredEntriesAreNeitherSavedNorLoaded(t *testing.T) {
	inner := dnstest.New(zone())
	c := New(inner, Config{MinTTL: time.Second, MaxTTL: time.Second})
	now := time.Now()
	c.now = func() time.Time { return now }
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if _, err := c.LookupTXT(ctx, "_spf.google.com"); err != nil {
			t.Fatal(err)
		}
	}

	// Still live: it saves.
	var live bytes.Buffer
	if _, err := c.WriteTo(&live); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(live.String(), "_spf.google.com") {
		t.Fatal("a live entry was not saved")
	}

	// Past its TTL: it does not.
	now = now.Add(2 * time.Second)
	var stale bytes.Buffer
	if _, err := c.WriteTo(&stale); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stale.String(), "_spf.google.com") {
		t.Error("an expired entry was saved")
	}

	// And a file saved while live must not revive it later.
	later := New(dnstest.New(zone()), Config{})
	laterNow := now.Add(time.Hour)
	later.now = func() time.Time { return laterNow }
	if _, err := later.ReadFrom(&live); err != nil {
		t.Fatal(err)
	}
	if later.Len() != 0 {
		t.Error("a saved entry was loaded past the TTL its zone published")
	}
}

func TestReadFromRejectsGarbageWithoutPanicking(t *testing.T) {
	c := New(dnstest.New(zone()), Config{})
	if _, err := c.ReadFrom(strings.NewReader("not json")); err == nil {
		t.Error("expected an error on a corrupt cache file")
	}
	if c.Len() != 0 {
		t.Error("a corrupt file left entries behind")
	}
}
