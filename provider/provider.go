// Package vendor names the services behind a domain's DNS records.
//
// It answers two different questions, through two separate tables, and keeping
// them separate is the point of the package rather than an implementation
// detail. An MX host says who RECEIVES mail for a domain. An SPF include says
// who is authorised to SEND as it. A single merged table would let an MX record
// answer an outbound question, and the answer would be wrong in exactly the
// cases that matter: a company on Microsoft 365 that sends its marketing
// through HubSpot has two providers, and only one of them appears in MX.
package provider

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/MarcoPeretti/mailkit/dnsx"
)

//go:embed providers.json
var providersJSON []byte

// Categories a vendor can belong to. The set is closed: an unrecognised
// category in the table is a load error, not a new category, because a typo
// that silently creates one would quietly empty whichever report filters on it.
const (
	CategoryMailbox         = "mailbox"          // receives and usually sends: M365, Google Workspace
	CategoryESP             = "esp"              // bulk/transactional sending: SendGrid, Mailchimp
	CategoryCRM             = "crm"              // sends as part of a sales platform: HubSpot, Salesforce
	CategorySupport         = "support"          // sends from a helpdesk: Zendesk, Intercom
	CategoryForwarding      = "forwarding"       // forwards only: registrar forwarding, ImprovMX
	CategorySecurityGateway = "security_gateway" // filters inbound: Proofpoint, Mimecast

	// CategoryAuthentication is for services that manage SPF and DMARC on a
	// domain's behalf: Valimail, EasyDMARC, dmarcian.
	//
	// It earns its own category because of what it implies rather than what it
	// does. A domain using one has already bought a solution to exactly the
	// problems this module detects, which makes it a different proposition
	// from one that has never looked.
	CategoryAuthentication = "authentication"
)

var categories = map[string]bool{
	CategoryMailbox: true, CategoryESP: true, CategoryCRM: true,
	CategorySupport: true, CategoryForwarding: true, CategorySecurityGateway: true,
	CategoryAuthentication: true,
}

// Provider is one identified service.
type Provider struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`

	// MXSuffixes match an MX target; SPFSuffixes match an include or redirect
	// target. Both match on label boundaries, never as bare substrings.
	MXSuffixes  []string `json:"mx,omitempty"`
	SPFSuffixes []string `json:"spf,omitempty"`

	// DKIMSuffixes match the CNAME target of a selector record: the one
	// place a DKIM key names who holds it, since the key itself is a bare
	// public key. DKIMSelectors are selector names that belong to one vendor
	// and no other -- "mandrill", "hs1" -- for keys published as TXT, where
	// there is no target to match. A selector any vendor might use, like
	// "k1" or "s1", is deliberately not listed: an attribution from a name
	// two vendors share would be a guess presented as an observation.
	DKIMSuffixes  []string `json:"dkim,omitempty"`
	DKIMSelectors []string `json:"dkim_selectors,omitempty"`

	// DKIMKeys are hashes (see KeyHash) of public keys the vendor hands
	// every customer. A key published as TXT under a shared selector such
	// as "mail" or "m1" names nobody by itself; the same key at unrelated
	// domains is the vendor's. Measured over 300 domains, Marketo's m1 key
	// was identical across a pod and Brevo's mail key across ten customers.
	DKIMKeys []string `json:"dkim_keys,omitempty"`

	// CNAMESuffixes match the target a customer's subdomain is redirected
	// to: the link-tracking, bounce and landing-page hosts a vendor's setup
	// guide dictates (pm-bounces.example.com -> pm.mtasv.net, go.example.com
	// -> 442-xlc-320.mktoweb.com). Label-boundary matching as everywhere.
	CNAMESuffixes []string `json:"cname,omitempty"`

	// MailFrom are the subdomain labels a vendor's setup guide dictates for
	// its bounce address, together with who the sub's own MX and SPF must
	// resolve to. Two vendors on Amazon SES leave no record naming
	// themselves: Resend is "send.<domain>" with an SES MX, Loops is
	// "envelope.<domain>" with the same MX. The label is the only trace.
	MailFrom []MailFromRule `json:"mailfrom,omitempty"`

	Inbound  bool `json:"inbound,omitempty"`
	Outbound bool `json:"outbound,omitempty"`
}

// MailFromRule is one label convention. On names the vendor id the
// subdomain's MX or SPF resolve to; empty means any.
type MailFromRule struct {
	Label string `json:"label"`
	On    string `json:"on,omitempty"`
}

// Matcher resolves hostnames to vendors.
type Matcher struct {
	mx        map[string]Provider
	spf       map[string]Provider
	dkim      map[string]Provider
	cname     map[string]Provider
	selectors map[string]Provider
	keys      map[string]Provider
	mailfrom  map[string]Provider // "label|on"
	all       []Provider
}

var defaultMatcher = mustLoad(providersJSON)

// Default returns the matcher built from the embedded table.
func Default() *Matcher { return defaultMatcher }

// Load builds a matcher from a JSON table in the embedded format.
func Load(data []byte) (*Matcher, error) {
	var vs []Provider
	if err := json.Unmarshal(data, &vs); err != nil {
		return nil, fmt.Errorf("vendor: parsing table: %w", err)
	}
	m := &Matcher{
		mx: map[string]Provider{}, spf: map[string]Provider{}, dkim: map[string]Provider{}, cname: map[string]Provider{},
		selectors: map[string]Provider{}, keys: map[string]Provider{}, mailfrom: map[string]Provider{}, all: vs,
	}
	for _, v := range vs {
		if v.ID == "" || v.Name == "" {
			return nil, fmt.Errorf("vendor: entry %q is missing an id or name", v.ID)
		}
		if !categories[v.Category] {
			return nil, fmt.Errorf("vendor: %q has unknown category %q", v.ID, v.Category)
		}
		for _, s := range v.MXSuffixes {
			if err := claim(m.mx, s, v, "mx"); err != nil {
				return nil, err
			}
		}
		for _, s := range v.SPFSuffixes {
			if err := claim(m.spf, s, v, "spf"); err != nil {
				return nil, err
			}
		}
		for _, s := range v.DKIMSuffixes {
			if err := claim(m.dkim, s, v, "dkim"); err != nil {
				return nil, err
			}
		}
		for _, s := range v.CNAMESuffixes {
			if err := claim(m.cname, s, v, "cname"); err != nil {
				return nil, err
			}
		}
		for _, sel := range v.DKIMSelectors {
			sel = strings.ToLower(strings.TrimSpace(sel))
			if sel == "" || strings.Contains(sel, ".") {
				return nil, fmt.Errorf("vendor: %q has an unusable DKIM selector %q", v.ID, sel)
			}
			if prev, ok := m.selectors[sel]; ok && prev.ID != v.ID {
				return nil, fmt.Errorf("vendor: DKIM selector %q is claimed by both %q and %q", sel, prev.ID, v.ID)
			}
			m.selectors[sel] = v
		}
		for _, k := range v.DKIMKeys {
			k = strings.ToLower(strings.TrimSpace(k))
			if len(k) != keyHashLen || strings.Trim(k, "0123456789abcdef") != "" {
				return nil, fmt.Errorf("vendor: %q has an unusable DKIM key hash %q (want %d hex characters)", v.ID, k, keyHashLen)
			}
			if prev, ok := m.keys[k]; ok && prev.ID != v.ID {
				return nil, fmt.Errorf("vendor: DKIM key %s is claimed by both %q and %q", k, prev.ID, v.ID)
			}
			m.keys[k] = v
		}
		for _, r := range v.MailFrom {
			label := strings.ToLower(strings.TrimSpace(r.Label))
			if label == "" || strings.Contains(label, ".") {
				return nil, fmt.Errorf("vendor: %q has an unusable MAIL FROM label %q", v.ID, r.Label)
			}
			key := label + "|" + strings.ToLower(strings.TrimSpace(r.On))
			if prev, ok := m.mailfrom[key]; ok && prev.ID != v.ID {
				return nil, fmt.Errorf("vendor: MAIL FROM label %q on %q is claimed by both %q and %q", label, r.On, prev.ID, v.ID)
			}
			m.mailfrom[key] = v
		}
	}
	return m, nil
}

// keyHashLen is the length of a KeyHash: the first eight bytes of the
// SHA-256, in hex. Long enough that a collision between two vendors' keys is
// not a concern, short enough to read in a table.
const keyHashLen = 16

// KeyHash reduces a DKIM TXT record to the hash of its public key, so that
// a key can be recognised across domains without carrying the key itself.
// It returns "" when the record has no p= tag.
func KeyHash(record string) string {
	pub := ""
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			pub = strings.Join(strings.Fields(part[2:]), "")
		}
	}
	if pub == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(pub))
	return hex.EncodeToString(sum[:keyHashLen/2])
}

func claim(into map[string]Provider, suffix string, v Provider, kind string) error {
	s := dnsx.Normalize(suffix)
	if s == "" || !strings.Contains(s, ".") {
		return fmt.Errorf("vendor: %q has an unusable %s suffix %q", v.ID, kind, suffix)
	}
	if prev, ok := into[s]; ok && prev.ID != v.ID {
		// Two vendors claiming one suffix means whichever loaded last wins,
		// silently. That is how a table rots: attributions start changing for
		// reasons nobody can see in a diff.
		return fmt.Errorf("vendor: %s suffix %q is claimed by both %q and %q", kind, s, prev.ID, v.ID)
	}
	into[s] = v
	return nil
}

func mustLoad(data []byte) *Matcher {
	m, err := Load(data)
	if err != nil {
		panic(err)
	}
	return m
}

// MatchMX identifies the provider behind an MX target.
func (m *Matcher) MatchMX(host string) (Provider, bool) { return lookup(m.mx, host) }

// MatchSPF identifies the provider behind an SPF include or redirect target.
func (m *Matcher) MatchSPF(target string) (Provider, bool) { return lookup(m.spf, target) }

// MatchDKIM identifies the provider behind a DKIM selector's CNAME target.
func (m *Matcher) MatchDKIM(cname string) (Provider, bool) { return lookup(m.dkim, cname) }

// MatchDKIMSelector identifies a provider from a selector name alone. Only
// selectors that belong to exactly one vendor are ever matched.
func (m *Matcher) MatchDKIMSelector(selector string) (Provider, bool) {
	v, ok := m.selectors[strings.ToLower(selector)]
	return v, ok
}

// MatchDKIMKey identifies the vendor that publishes this exact public key
// for all its customers. hash is a KeyHash.
func (m *Matcher) MatchDKIMKey(hash string) (Provider, bool) {
	v, ok := m.keys[strings.ToLower(hash)]
	return v, ok
}

// MatchCNAME identifies the provider behind the target a customer's
// subdomain is redirected to.
func (m *Matcher) MatchCNAME(target string) (Provider, bool) { return lookup(m.cname, target) }

// MatchMailFrom identifies the vendor whose setup guide dictates a bounce
// subdomain with this label, given who the subdomain's own MX or SPF
// resolve to (a vendor id, or "" when nothing named one). A rule with no
// "on" matches any underlying vendor.
func (m *Matcher) MatchMailFrom(label, underlying string) (Provider, bool) {
	label = strings.ToLower(strings.TrimSpace(label))
	if v, ok := m.mailfrom[label+"|"+strings.ToLower(underlying)]; ok {
		return v, true
	}
	v, ok := m.mailfrom[label+"|"]
	return v, ok
}

// lookup walks the name's labels from the left, so the longest matching suffix
// wins and matching is O(labels) rather than O(table).
//
// The walk starts at the full name and shortens by one label at a time, which
// is what makes "aspmx2.googlemail.com" match the "googlemail.com" rule while
// "notgooglemail.com" matches nothing: shortening only ever happens at a dot,
// so a rule can never match part of a label.
func lookup(table map[string]Provider, name string) (Provider, bool) {
	n := dnsx.Normalize(name)
	if n == "" {
		return Provider{}, false
	}
	for {
		if v, ok := table[n]; ok {
			return v, true
		}
		i := strings.Index(n, ".")
		if i < 0 {
			return Provider{}, false
		}
		n = n[i+1:]
	}
}

// All returns every vendor in the table, sorted by ID.
func (m *Matcher) All() []Provider {
	out := append([]Provider(nil), m.all...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns the vendor with the given ID.
func (m *Matcher) Get(id string) (Provider, bool) {
	for _, v := range m.all {
		if v.ID == id {
			return v, true
		}
	}
	return Provider{}, false
}
