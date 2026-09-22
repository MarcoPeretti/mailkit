package publicres

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/MarcoPeretti/mailkit/dnsx"
)

// The tests here run against a nameserver started inside the test process and
// bound to loopback. That keeps the house rule -- no test contacts a third
// party -- while still exercising the real wire format, the real client, and
// the retry and truncation paths, none of which a hand-written fake would
// cover.

type handlerFunc func(w dns.ResponseWriter, m *dns.Msg)

// serve starts a UDP and a TCP nameserver on the same loopback port and
// returns its address.
func serve(t *testing.T, h handlerFunc) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", dns.HandlerFunc(h).ServeDNS)

	ready := make(chan struct{}, 2)
	udpSrv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { ready <- struct{}{} }}
	tcpSrv := &dns.Server{Listener: ln, Handler: mux, NotifyStartedFunc: func() { ready <- struct{}{} }}
	go func() { _ = udpSrv.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	<-ready
	<-ready

	t.Cleanup(func() {
		_ = udpSrv.Shutdown()
		_ = tcpSrv.Shutdown()
	})
	return addr
}

func reply(m *dns.Msg, rcode int, rrs ...dns.RR) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(m)
	r.Rcode = rcode
	r.Answer = rrs
	return r
}

func txt(name string, ttl uint32, parts ...string) dns.RR {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
		Txt: parts,
	}
}

func TestQueryReportsRcodeAndTTL(t *testing.T) {
	addr := serve(t, func(w dns.ResponseWriter, m *dns.Msg) {
		switch m.Question[0].Name {
		case "present.example.":
			_ = w.WriteMsg(reply(m, dns.RcodeSuccess, txt("present.example", 300, "v=spf1 -all")))
		case "nodata.example.":
			// The name exists, but has no TXT. NOERROR with an empty answer.
			_ = w.WriteMsg(reply(m, dns.RcodeSuccess))
		default:
			_ = w.WriteMsg(reply(m, dns.RcodeNameError))
		}
	})
	r := New(Config{Servers: []string{addr}})
	ctx := context.Background()

	a, err := r.Query(ctx, "present.example", dnsx.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if a.RCode != dnsx.RcodeSuccess || len(a.TXT) != 1 || a.TXT[0] != "v=spf1 -all" {
		t.Fatalf("got %+v", a)
	}
	if a.TTL != 300 {
		t.Errorf("TTL = %d, want 300; without it a cache cannot honour the zone", a.TTL)
	}
	if a.Empty() {
		t.Error("an answer with a record must not be empty")
	}

	// The whole reason this package exists: these two answers are different,
	// and the standard library reports both as "no such host".
	nodata, err := r.Query(ctx, "nodata.example", dnsx.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if nodata.RCode != dnsx.RcodeSuccess {
		t.Errorf("NODATA reported RCode %d, want NOERROR", nodata.RCode)
	}
	if !nodata.Empty() {
		t.Error("NODATA must count as an empty answer")
	}

	nx, err := r.Query(ctx, "absent.example", dnsx.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if nx.RCode != dnsx.RcodeNameError {
		t.Errorf("NXDOMAIN reported RCode %d, want %d", nx.RCode, dnsx.RcodeNameError)
	}
}

// A TXT record is stored as 255-byte chunks. A long SPF record arrives split,
// and reading only the first chunk would silently truncate the policy this
// module's central number is computed from.
func TestLongTXTIsJoined(t *testing.T) {
	long := strings.Repeat("a", 255)
	addr := serve(t, func(w dns.ResponseWriter, m *dns.Msg) {
		_ = w.WriteMsg(reply(m, dns.RcodeSuccess, txt("long.example", 60, "v=spf1 ", long, " -all")))
	})
	r := New(Config{Servers: []string{addr}})

	got, err := r.LookupTXT(context.Background(), "long.example")
	if err != nil {
		t.Fatal(err)
	}
	want := "v=spf1 " + long + " -all"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("TXT chunks were not joined: got %d records, first is %d bytes, want %d", len(got), len(got[0]), len(want))
	}
}

// A server failure has not answered the question. Reporting it as an answer
// would turn one recursor's bad minute into a verdict about somebody's DNS.
func TestServFailRetriesTheNextServerAndIsTemporary(t *testing.T) {
	var badHits, goodHits atomic.Int64

	bad := serve(t, func(w dns.ResponseWriter, m *dns.Msg) {
		badHits.Add(1)
		_ = w.WriteMsg(reply(m, dns.RcodeServerFailure))
	})
	good := serve(t, func(w dns.ResponseWriter, m *dns.Msg) {
		goodHits.Add(1)
		_ = w.WriteMsg(reply(m, dns.RcodeSuccess, txt("x.example", 60, "v=spf1 -all")))
	})

	r := New(Config{Servers: []string{bad, good}, Attempts: 2})
	a, err := r.Query(context.Background(), "x.example", dnsx.TypeTXT)
	if err != nil {
		t.Fatalf("a failure on the first server should have been retried on the second: %v", err)
	}
	if a.Server != good {
		t.Errorf("answered by %q, want the healthy server", a.Server)
	}
	if badHits.Load() == 0 || goodHits.Load() == 0 {
		t.Errorf("expected both servers to be tried: bad=%d good=%d", badHits.Load(), goodHits.Load())
	}

	// With every server failing, the error must classify as "could not ask",
	// never as "no such name".
	only := New(Config{Servers: []string{bad}, Attempts: 2})
	_, err = only.Query(context.Background(), "x.example", dnsx.TypeTXT)
	if err == nil {
		t.Fatal("expected an error when every server fails")
	}
	if dnsx.NotFound(err) {
		t.Error("a server failure must not classify as NotFound")
	}
	if !dnsx.Unanswered(err) {
		t.Error("a server failure must classify as Unanswered")
	}
}

// A truncated UDP answer is incomplete, not short. Long TXT records are the
// usual cause, so the query must be retried over TCP rather than parsed.
func TestTruncatedAnswerFallsBackToTCP(t *testing.T) {
	var overTCP atomic.Bool
	addr := serve(t, func(w dns.ResponseWriter, m *dns.Msg) {
		if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
			overTCP.Store(true)
			_ = w.WriteMsg(reply(m, dns.RcodeSuccess, txt("t.example", 60, "v=spf1 include:a.example -all")))
			return
		}
		r := reply(m, dns.RcodeSuccess)
		r.Truncated = true
		_ = w.WriteMsg(r)
	})

	r := New(Config{Servers: []string{addr}})
	got, err := r.LookupTXT(context.Background(), "t.example")
	if err != nil {
		t.Fatal(err)
	}
	if !overTCP.Load() {
		t.Fatal("a truncated answer was accepted without retrying over TCP")
	}
	if len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestTimeoutIsUnansweredNotNotFound(t *testing.T) {
	addr := serve(t, func(w dns.ResponseWriter, m *dns.Msg) {
		time.Sleep(300 * time.Millisecond) // longer than the client timeout below
		_ = w.WriteMsg(reply(m, dns.RcodeSuccess))
	})
	r := New(Config{Servers: []string{addr}, Timeout: 50 * time.Millisecond, Attempts: 1})

	_, err := r.Query(context.Background(), "slow.example", dnsx.TypeTXT)
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if dnsx.NotFound(err) {
		t.Error("a timeout must never read as a definite answer")
	}
	if !dnsx.Unanswered(err) {
		t.Error("a timeout must classify as Unanswered")
	}
}

func TestServersRotate(t *testing.T) {
	var a, b atomic.Int64
	s1 := serve(t, func(w dns.ResponseWriter, m *dns.Msg) {
		a.Add(1)
		_ = w.WriteMsg(reply(m, dns.RcodeSuccess, txt("r.example", 60, "v=spf1 -all")))
	})
	s2 := serve(t, func(w dns.ResponseWriter, m *dns.Msg) {
		b.Add(1)
		_ = w.WriteMsg(reply(m, dns.RcodeSuccess, txt("r.example", 60, "v=spf1 -all")))
	})

	r := New(Config{Servers: []string{s1, s2}})
	for i := 0; i < 10; i++ {
		if _, err := r.Query(context.Background(), "r.example", dnsx.TypeTXT); err != nil {
			t.Fatal(err)
		}
	}
	if a.Load() == 0 || b.Load() == 0 {
		t.Errorf("queries did not rotate: %d vs %d", a.Load(), b.Load())
	}
}

func TestMXAndHostLookups(t *testing.T) {
	addr := serve(t, func(w dns.ResponseWriter, m *dns.Msg) {
		q := m.Question[0]
		switch {
		case q.Qtype == dns.TypeMX && q.Name == "m.example.":
			_ = w.WriteMsg(reply(m, dns.RcodeSuccess, &dns.MX{
				Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60},
				Preference: 10, Mx: "mx1.example.",
			}))
		case q.Qtype == dns.TypeA && q.Name == "h.example.":
			_ = w.WriteMsg(reply(m, dns.RcodeSuccess, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("192.0.2.1"),
			}))
		default:
			_ = w.WriteMsg(reply(m, dns.RcodeNameError))
		}
	})
	r := New(Config{Servers: []string{addr}})
	ctx := context.Background()

	mx, err := r.LookupMX(ctx, "m.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(mx) != 1 || mx[0].Host != "mx1.example" || mx[0].Pref != 10 {
		t.Fatalf("got %+v", mx[0])
	}

	hosts, err := r.LookupHost(ctx, "h.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0] != "192.0.2.1" {
		t.Fatalf("got %v", hosts)
	}

	if _, err := r.LookupMX(ctx, "absent.example"); !dnsx.NotFound(err) {
		t.Errorf("NXDOMAIN should surface as NotFound, got %v", err)
	}
}

func TestAnswerKeepsTheFirstCNAMEHop(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("s1._domainkey.acme.example.", dns.TypeTXT)
	msg.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "s1._domainkey.acme.example.", Rrtype: dns.TypeCNAME, Ttl: 300}, Target: "s1.domainkey.u1.wl.esp.example."},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "s1.domainkey.u1.wl.esp.example.", Rrtype: dns.TypeCNAME, Ttl: 300}, Target: "keys.esp.example."},
		&dns.TXT{Hdr: dns.RR_Header{Name: "keys.esp.example.", Rrtype: dns.TypeTXT, Ttl: 60}, Txt: []string{"v=DKIM1; p=MIGf"}},
	}
	a := answerFrom(msg, "s1._domainkey.acme.example", dns.TypeTXT, "test")
	if a.CNAME != "s1.domainkey.u1.wl.esp.example" {
		t.Errorf("CNAME = %q, want the first hop", a.CNAME)
	}
	if len(a.TXT) != 1 || a.TTL != 60 {
		t.Errorf("records = %v ttl=%d", a.TXT, a.TTL)
	}
}
