package dnstest

import (
	"context"
	"testing"

	"github.com/MarcoPeretti/mailkit/dnsx"
)

// A name published as a CNAME answers with the target's records and names
// the first hop, which for a DKIM selector is where the vendor is.
func TestCNAMEAnswersWithTheTargetAndNamesTheHop(t *testing.T) {
	r := New(Zone{
		CNAME: map[string]string{"s1._domainkey.acme.example": "s1.domainkey.u1.wl.esp.example", "s1.domainkey.u1.wl.esp.example": "keys.esp.example"},
		TXT:   map[string][]string{"keys.esp.example": {"v=DKIM1; k=rsa; p=MIGf"}},
	})
	a, err := r.Query(context.Background(), "s1._domainkey.acme.example", dnsx.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if a.RCode != dnsx.RcodeSuccess || len(a.TXT) != 1 || a.CNAME != "s1.domainkey.u1.wl.esp.example" || a.Name != "s1._domainkey.acme.example" {
		t.Errorf("answer = %+v", a)
	}
	// A dangling CNAME answers as a recursor does: name error for the
	// target, with the hop still named. The hop is the evidence that a
	// vendor was configured, whether or not the key still works.
	r = New(Zone{CNAME: map[string]string{"k1._domainkey.acme.example": "dkim.gone.example"}})
	a, _ = r.Query(context.Background(), "k1._domainkey.acme.example", dnsx.TypeTXT)
	if a.RCode != dnsx.RcodeNameError || a.CNAME != "dkim.gone.example" || len(a.TXT) != 0 {
		t.Errorf("dangling answer = %+v", a)
	}
}
