package dnsx

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

type countingResolver struct {
	mu sync.Mutex
	n  int
}

func (c *countingResolver) hit() {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
}
func (c *countingResolver) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func (c *countingResolver) LookupTXT(context.Context, string) ([]string, error) {
	c.hit()
	return nil, nil
}
func (c *countingResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	c.hit()
	return nil, nil
}
func (c *countingResolver) LookupHost(context.Context, string) ([]string, error) {
	c.hit()
	return nil, nil
}
func (c *countingResolver) LookupAddr(context.Context, string) ([]string, error) {
	c.hit()
	return nil, nil
}

type tracingCounter struct{ countingResolver }

func (t *tracingCounter) Query(context.Context, string, uint16) (*Answer, error) {
	t.hit()
	return &Answer{}, nil
}

func TestRateLimitPacesQueries(t *testing.T) {
	inner := &countingResolver{}
	r := RateLimit(inner, 100) // 10ms apart

	start := time.Now()
	for i := 0; i < 40; i++ {
		if _, err := r.LookupTXT(context.Background(), "x.example"); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)

	if inner.count() != 40 {
		t.Fatalf("inner saw %d queries, want 40", inner.count())
	}
	// 40 queries at 100/s is 400ms, less the burst allowance of ~20 slots.
	if elapsed < 150*time.Millisecond {
		t.Errorf("40 queries at 100/s took %v; the limiter is not pacing", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("40 queries at 100/s took %v; far slower than the ceiling", elapsed)
	}
}

func TestRateLimitIsSharedAcrossGoroutines(t *testing.T) {
	inner := &countingResolver{}
	r := RateLimit(inner, 200)

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.LookupTXT(context.Background(), "x.example"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	// The ceiling is global: sixty workers must not each get their own budget,
	// or the limit means nothing under the concurrency it exists to bound.
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("60 concurrent queries at 200/s took %v; the ceiling is per-caller, not global", elapsed)
	}
	if inner.count() != 60 {
		t.Errorf("inner saw %d, want 60", inner.count())
	}
}

// A limiter that silently dropped the TracingResolver capability would turn the
// SPF void-lookup count into an approximation -- a correctness change wearing a
// throttle's clothes.
func TestRateLimitPreservesTracing(t *testing.T) {
	r := RateLimit(&tracingCounter{}, 1000)

	tr, ok := r.(TracingResolver)
	if !ok {
		t.Fatal("RateLimit dropped the TracingResolver capability")
	}
	if _, err := tr.Query(context.Background(), "x.example", TypeTXT); err != nil {
		t.Fatal(err)
	}

	// And it must not invent the capability where the inner resolver lacks it.
	if _, ok := RateLimit(&countingResolver{}, 1000).(TracingResolver); ok {
		t.Error("RateLimit claimed tracing on a resolver that cannot trace")
	}
}

func TestRateLimitZeroIsPassthrough(t *testing.T) {
	inner := &countingResolver{}
	if got := RateLimit(inner, 0); got != Resolver(inner) {
		t.Error("a ceiling of zero should return the resolver unwrapped")
	}
}

func TestRateLimitRespectsCancellation(t *testing.T) {
	r := RateLimit(&countingResolver{}, 1) // one per second: the second call waits

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _ = r.LookupTXT(context.Background(), "first.example")
	if _, err := r.LookupTXT(ctx, "second.example"); err == nil {
		t.Error("a query waiting for a slot must honour cancellation")
	}
}
