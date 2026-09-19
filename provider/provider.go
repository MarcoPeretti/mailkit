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
	_ "embed"
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

	Inbound  bool `json:"inbound,omitempty"`
	Outbound bool `json:"outbound,omitempty"`
}

// Matcher resolves hostnames to vendors.
type Matcher struct {
	mx  map[string]Provider
	spf map[string]Provider
	all []Provider
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
	m := &Matcher{mx: map[string]Provider{}, spf: map[string]Provider{}, all: vs}
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
	}
	return m, nil
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
