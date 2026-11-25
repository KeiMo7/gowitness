// Package dedup provides in-process admission and grouping indexes used to
// avoid duplicate work and to group visually similar results.
package dedup

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// TargetKey is the canonical, request-semantics-preserving identity of a
// scan target.
type TargetKey struct {
	Scheme   string
	Host     string
	Port     int
	Path     string
	RawQuery string
	User     string
}

// String renders the canonical form:
//
//	scheme://[user@]host[:port]/path[?query]
func (k TargetKey) String() string {
	var b strings.Builder

	b.WriteString(k.Scheme)
	b.WriteString("://")

	if k.User != "" {
		b.WriteString(k.User)
		b.WriteByte('@')
	}

	host := k.Host
	// Be tolerant of keys built directly with an unbracketed IPv6 host.
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	b.WriteString(host)

	if k.Port != 0 && !isDefaultPort(k.Scheme, k.Port) {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(k.Port))
	}

	if k.Path == "" {
		b.WriteByte('/')
	} else {
		b.WriteString(k.Path)
	}

	if k.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(k.RawQuery)
	}

	return b.String()
}

func isDefaultPort(scheme string, port int) bool {
	switch strings.ToLower(scheme) {
	case "http":
		return port == 80
	case "https":
		return port == 443
	default:
		return false
	}
}

// CanonicalTarget parses raw and returns its canonical TargetKey.
//
// Only transformations that do not change request semantics are applied:
// scheme and host are lower-cased, fragments removed, empty paths become "/",
// default http/https ports are normalised, IPv6 hosts are normalised via
// net.ParseIP and userinfo, query ordering/encoding and path encoding are
// preserved.
func CanonicalTarget(raw string) (TargetKey, error) {
	if raw == "" {
		return TargetKey{}, errors.New("dedup: empty target")
	}

	for _, r := range raw {
		if unicode.IsControl(r) {
			return TargetKey{}, fmt.Errorf("dedup: target %q contains control characters", raw)
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return TargetKey{}, fmt.Errorf("dedup: cannot parse target %q: %w", raw, err)
	}

	hostName := u.Hostname()
	if hostName == "" {
		return TargetKey{}, fmt.Errorf("dedup: target %q is missing a host", raw)
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(hostName)

	// Normalise IPv6 addresses (and only IPv6) through net.ParseIP.
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + ip.String() + "]"
	}

	port := 0
	if rawPort := u.Port(); rawPort != "" {
		p, err := strconv.Atoi(rawPort)
		if err != nil {
			return TargetKey{}, fmt.Errorf("dedup: invalid port %q in target %q", rawPort, raw)
		}
		if p < 1 || p > 65535 {
			return TargetKey{}, fmt.Errorf("dedup: port %d out of range in target %q", p, raw)
		}
		port = p
	} else {
		switch scheme {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	}

	// EscapedPath preserves the original percent-encoding (e.g. %2f) as
	// well as duplicate slashes.
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}

	user := rawUserInfo(raw)
	if user == "" && u.User != nil {
		user = u.User.String()
	}

	return TargetKey{
		Scheme:   scheme,
		Host:     host,
		Port:     port,
		Path:     path,
		RawQuery: u.RawQuery,
		User:     user,
	}, nil
}

// rawUserInfo extracts the raw userinfo component of an absolute URL without
// touching its percent-encoding. It returns "" when no userinfo is present.
func rawUserInfo(raw string) string {
	schemeSep := strings.Index(raw, "://")
	if schemeSep < 0 {
		return ""
	}

	rest := raw[schemeSep+3:]
	authorityEnd := len(rest)
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '/', '?', '#':
			authorityEnd = i
			goto found
		}
	}
found:
	authority := rest[:authorityEnd]
	at := strings.LastIndexByte(authority, '@')
	if at < 0 {
		return ""
	}

	return authority[:at]
}

// TargetOptions configures a TargetIndex.
type TargetOptions struct {
	// MaxEntries is the maximum number of entries retained by the index.
	// It must be greater than zero.
	MaxEntries int
	// TTL, when positive, makes entries expire after that duration measured
	// from admission. Commit does not extend it.
	TTL time.Duration
	// Now optionally overrides the clock (used in tests).
	Now func() time.Time
}

// Ticket represents a successful admission. The Token disambiguates repeated
// admissions of the same key.
type Ticket struct {
	Key       TargetKey
	Canonical string
	Token     uint64
}

// TargetStats is a consistent snapshot of TargetIndex counters.
type TargetStats struct {
	Admitted   int
	Suppressed int
	Released   int
	Expired    int
	Evicted    int

	InFlight int
	Done     int
	Entries  int
}

type targetState int

const (
	targetInFlight targetState = iota
	targetDone
)

type targetEntry struct {
	token     uint64
	state     targetState
	expiresAt time.Time
}

// TargetIndex is a bounded, TTL-aware admission table for target keys.
type TargetIndex struct {
	mu  sync.Mutex
	now func() time.Time

	maxEntries int
	ttl        time.Duration

	entries map[TargetKey]*targetEntry

	nextToken uint64

	admitted   int
	suppressed int
	released   int
	expired    int
	evicted    int
}

// NewTargetIndex builds a TargetIndex from opts.
func NewTargetIndex(opts TargetOptions) (*TargetIndex, error) {
	if opts.MaxEntries <= 0 {
		return nil, errors.New("dedup: TargetOptions.MaxEntries must be greater than zero")
	}
	if opts.TTL < 0 {
		return nil, errors.New("dedup: TargetOptions.TTL must not be negative")
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &TargetIndex{
		now:        now,
		maxEntries: opts.MaxEntries,
		ttl:        opts.TTL,
		entries:    make(map[TargetKey]*targetEntry),
	}, nil
}

// Admit attempts to register a key for processing. It returns a fresh Ticket
// and true for first sightings (or after the previous entry left the table),
// and nil/false when an inflight or done entry already exists.
func (idx *TargetIndex) Admit(key TargetKey) (*Ticket, bool) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	now := idx.now()
	idx.expireLocked(now)

	if _, ok := idx.entries[key]; ok {
		idx.suppressed++
		return nil, false
	}

	if len(idx.entries) >= idx.maxEntries {
		idx.evictLocked()
	}

	idx.nextToken++
	token := idx.nextToken

	var expiresAt time.Time
	if idx.ttl > 0 {
		expiresAt = now.Add(idx.ttl)
	}

	idx.entries[key] = &targetEntry{
		token:     token,
		state:     targetInFlight,
		expiresAt: expiresAt,
	}
	idx.admitted++

	return &Ticket{
		Key:       key,
		Canonical: key.String(),
		Token:     token,
	}, true
}

// Commit marks the ticket's entry as done when the token still matches.
func (idx *TargetIndex) Commit(t *Ticket) {
	if t == nil {
		return
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	e, ok := idx.entries[t.Key]
	if !ok || e.token != t.Token {
		return
	}

	e.state = targetDone
}

// Release removes the ticket's entry only when the token matches and the
// entry is still inflight.
func (idx *TargetIndex) Release(t *Ticket) {
	if t == nil {
		return
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	e, ok := idx.entries[t.Key]
	if !ok || e.token != t.Token {
		return
	}
	if e.state != targetInFlight {
		return
	}

	delete(idx.entries, t.Key)
	idx.released++
}

// Stats returns a consistent snapshot of the index. Reading stats also
// performs lazy TTL cleanup.
func (idx *TargetIndex) Stats() TargetStats {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.expireLocked(idx.now())

	stats := TargetStats{
		Admitted:   idx.admitted,
		Suppressed: idx.suppressed,
		Released:   idx.released,
		Expired:    idx.expired,
		Evicted:    idx.evicted,
		Entries:    len(idx.entries),
	}

	for _, e := range idx.entries {
		switch e.state {
		case targetInFlight:
			stats.InFlight++
		case targetDone:
			stats.Done++
		}
	}

	return stats
}

// expireLocked removes entries whose TTL elapsed. The caller must hold idx.mu.
func (idx *TargetIndex) expireLocked(now time.Time) {
	if idx.ttl <= 0 {
		return
	}

	for key, e := range idx.entries {
		// now >= ExpiresAt
		if !now.Before(e.expiresAt) {
			delete(idx.entries, key)
			idx.expired++
		}
	}
}

// evictLocked removes the oldest done entry, or the oldest inflight entry when
// no done entry exists. Tokens order admissions monotonically. The caller
// must hold idx.mu and the table must contain at least one entry.
func (idx *TargetIndex) evictLocked() {
	var (
		victim    TargetKey
		victimTok uint64
		found     bool
	)

	// Prefer the earliest admitted done entry.
	for key, e := range idx.entries {
		if e.state != targetDone {
			continue
		}
		if !found || e.token < victimTok {
			victim = key
			victimTok = e.token
			found = true
		}
	}

	if !found {
		// Every entry is inflight: evict the earliest one, invalidating
		// its outstanding ticket.
		for key, e := range idx.entries {
			if !found || e.token < victimTok {
				victim = key
				victimTok = e.token
				found = true
			}
		}
	}

	if found {
		delete(idx.entries, victim)
		idx.evicted++
	}
}
