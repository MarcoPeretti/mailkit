package cache_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MarcoPeretti/mailkit/dnsx"
	"github.com/MarcoPeretti/mailkit/dnsx/cache"
	"github.com/MarcoPeretti/mailkit/dnsx/dnstest"
)

// The two files this package writes exist for different readers, and the
// difference is the whole point: WriteTo warms the next run of the same
// program, so it keeps only what that run reused, while Export hands the
// observations to another process, which is about to ask exactly the questions
// that were asked once.
//
// Measured on a real ten-domain crawl: the cache file held 42 entries and the
// export held 285, and not one of the ten _dmarc lookups was in the cache
// file -- they are asked once per domain and never again, which is precisely
// why they are what the other process wants.
func TestExportKeepsThePerDomainNamesTheCacheDrops(t *testing.T) {
	c := cache.New(dnstest.New(dnstest.Zone{TXT: map[string][]string{
		"_dmarc.acme.example":  {"v=DMARC1; p=none"},
		"_spf.shared.example":  {"v=spf1 -all"},
		"_dmarc.other.example": {"v=DMARC1; p=reject"},
	}}), cache.Config{})
	ctx := context.Background()

	// A per-domain name, asked once. A shared one, asked twice.
	for _, n := range []string{"_dmarc.acme.example", "_dmarc.other.example", "_spf.shared.example", "_spf.shared.example"} {
		if _, err := c.LookupTXT(ctx, n); err != nil {
			t.Fatalf("LookupTXT(%q): %v", n, err)
		}
	}

	var warm bytes.Buffer
	if _, err := c.WriteTo(&warm); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	var handoff bytes.Buffer
	if _, err := c.Export(&handoff, cache.Retention{MinHits: 0, KeepExpired: true}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if got := warm.String(); strings.Contains(got, "_dmarc.acme.example") {
		t.Errorf("WriteTo kept a name asked once; it is meant to keep only what was reused")
	}
	for _, want := range []string{"_dmarc.acme.example", "_dmarc.other.example", "_spf.shared.example"} {
		if !strings.Contains(handoff.String(), want) {
			t.Errorf("Export dropped %q; the once-asked names are what the reader is about to ask", want)
		}
	}
}

// A reader deciding whether a recorded answer is still good enough needs to
// know when we looked. That is not derivable from the expiry, which folds in
// the zone's own TTL: a record with a five-minute TTL and one with a day's
// both answer "how old is this observation" the same way, and only one of them
// says so through expires.
func TestExportRecordsWhenWeLooked(t *testing.T) {
	c := cache.New(dnstest.New(dnstest.Zone{
		TXT: map[string][]string{"acme.example": {"v=spf1 -all"}},
		TTL: map[string]uint32{"acme.example": 300},
	}), cache.Config{})
	if _, err := c.LookupTXT(context.Background(), "acme.example"); err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}

	var buf bytes.Buffer
	if _, err := c.Export(&buf, cache.Retention{}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	var got struct {
		Observed time.Time `json:"observed_at"`
		Expires  time.Time `json:"expires"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Observed.IsZero() {
		t.Fatal("no observed_at; a reader cannot judge the age of an observation it has no timestamp for")
	}
	if !got.Expires.After(got.Observed) {
		t.Errorf("expires %v is not after observed_at %v", got.Expires, got.Observed)
	}
}

// A lookup that did not complete says nothing about the zone. It must not
// reach the export, because a reader treats a name's absence as "ask this
// yourself" -- and an entry claiming an empty answer would instead be read as
// a fact about somebody's DNS.
func TestExportCarriesNoFailures(t *testing.T) {
	c := cache.New(dnstest.New(dnstest.Zone{
		TXT:  map[string][]string{"good.example": {"v=spf1 -all"}},
		Fail: map[string]string{"broken.example": dnstest.FailTimeout},
	}), cache.Config{})
	ctx := context.Background()
	_, _ = c.LookupTXT(ctx, "good.example")
	_, _ = c.LookupTXT(ctx, "broken.example")

	var buf bytes.Buffer
	if _, err := c.Export(&buf, cache.Retention{KeepExpired: true}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if strings.Contains(buf.String(), "broken.example") {
		t.Error("a failed lookup reached the export; absence must mean 'ask it yourself', not 'the answer was nothing'")
	}
	if !strings.Contains(buf.String(), "good.example") {
		t.Error("the successful lookup is missing")
	}
}

// NODATA and NXDOMAIN are both answers and both belong in the export, and they
// must stay distinguishable: "this name does not exist" and "this name exists
// and publishes no record of that type" lead to different findings.
func TestExportDistinguishesNodataFromNxdomain(t *testing.T) {
	c := cache.New(dnstest.New(dnstest.Zone{
		TXT: map[string][]string{"nodata.example": {}},
	}), cache.Config{})
	ctx := context.Background()
	_, _ = c.LookupTXT(ctx, "nodata.example")
	_, _ = c.LookupTXT(ctx, "missing.example")

	var buf bytes.Buffer
	if _, err := c.Export(&buf, cache.Retention{KeepExpired: true}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	byName := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var e struct {
			Name   string      `json:"name"`
			Answer dnsx.Answer `json:"answer"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		byName[e.Name] = e.Answer.RCode
	}
	if got, ok := byName["nodata.example"]; !ok || got != dnsx.RcodeSuccess {
		t.Errorf("nodata.example rcode = %v (present %v), want NOERROR", got, ok)
	}
	if got, ok := byName["missing.example"]; !ok || got != dnsx.RcodeNameError {
		t.Errorf("missing.example rcode = %v (present %v), want NXDOMAIN", got, ok)
	}
}
