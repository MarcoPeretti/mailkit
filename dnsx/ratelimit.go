package dnsx

import (
	"context"
	"net"
	"sync"
	"time"
)

// RateLimit wraps a resolver with a ceiling on how fast it may query.
//
// The ceiling exists for politeness first and correctness second. A public
// recursor that decides we are asking too quickly does not refuse politely: it
// answers SERVFAIL, and under an honest reading of a failed lookup that becomes
// "we could not check this domain". So being throttled does not produce a loud
// error, it produces thousands of rows that quietly record our own impatience
// as an absence of information. A ceiling we choose is better than one somebody
// else imposes.
//
// Place it BELOW any cache, so that an answer served from memory costs no
// tokens:
//
//	cache.New(dnsx.RateLimit(base, qps), cacheCfg)
//
// Wrapping the other way round would spend the budget on queries that never
// reach the network.
func RateLimit(r Resolver, qps int) Resolver {
	if qps <= 0 {
		return r
	}
	l := &limiter{interval: time.Second / time.Duration(qps)}
	// Allow a short burst so that a run starting cold does not serialise its
	// first queries one interval apart.
	l.burst = 20 * l.interval

	if t, ok := r.(TracingResolver); ok {
		return &tracingLimited{limited{inner: r, lim: l}, t}
	}
	return &limited{inner: r, lim: l}
}

// limiter hands out evenly spaced slots.
//
// It schedules rather than counts: each caller reserves the next free moment
// and sleeps until it arrives. That spreads queries evenly instead of letting a
// refilled bucket release a thundering herd, which is what a recursor notices.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	burst    time.Duration
	next     time.Time
}

func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		// Idle time does not accumulate credit beyond the burst allowance,
		// or a pause would be followed by an unbounded rush.
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	if wait := at.Sub(now); wait > l.burst+l.interval {
		// Too far ahead: give the slot back rather than queue unboundedly.
		l.next = l.next.Add(-l.interval)
		l.mu.Unlock()
		select {
		case <-time.After(l.interval):
			return l.wait(ctx)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	l.mu.Unlock()

	d := time.Until(at)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type limited struct {
	inner Resolver
	lim   *limiter
}

func (l *limited) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := l.lim.wait(ctx); err != nil {
		return nil, err
	}
	return l.inner.LookupTXT(ctx, name)
}

func (l *limited) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	if err := l.lim.wait(ctx); err != nil {
		return nil, err
	}
	return l.inner.LookupMX(ctx, name)
}

func (l *limited) LookupHost(ctx context.Context, host string) ([]string, error) {
	if err := l.lim.wait(ctx); err != nil {
		return nil, err
	}
	return l.inner.LookupHost(ctx, host)
}

func (l *limited) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if err := l.lim.wait(ctx); err != nil {
		return nil, err
	}
	return l.inner.LookupAddr(ctx, addr)
}

// tracingLimited preserves the TracingResolver capability through the wrapper.
//
// Without this the limiter would silently downgrade the resolver to one that
// cannot report response codes, and the SPF void-lookup count would quietly
// become an approximation -- a correctness change disguised as a throttle.
type tracingLimited struct {
	limited
	tracer TracingResolver
}

func (l *tracingLimited) Query(ctx context.Context, name string, qtype uint16) (*Answer, error) {
	if err := l.lim.wait(ctx); err != nil {
		return nil, err
	}
	return l.tracer.Query(ctx, name, qtype)
}
