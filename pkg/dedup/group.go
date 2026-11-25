package dedup

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/sensepost/gowitness/internal/islazy"
)

// GroupOptions configures a GroupIndex.
type GroupOptions struct {
	// Threshold is the maximum perception-hash Hamming distance at which a
	// hash joins an existing group. Valid range is 0..64. Defaults to 10 at
	// the wiring layer (NewGroupIndex itself treats 0 as an explicit value).
	Threshold int
	// MaxGroups is the maximum number of active groups. It must be > 0.
	MaxGroups int
	// TTL, when positive, makes groups expire after that duration measured
	// from creation or seeding.
	TTL time.Duration
	// Now optionally overrides the clock (used in tests).
	Now func() time.Time
}

// GroupStats is a consistent snapshot of GroupIndex counters.
type GroupStats struct {
	Groups  int
	Entries int

	Assigned int
	Matched  int
	Expired  int
	Evicted  int
}

type groupEntry struct {
	id      uint
	hash    []byte // representative perception hash
	hasHash bool   // whether hash is a valid representative (incl. zero-length)

	members int

	persisted bool // Commit was called (result written successfully)
	seeded    bool // restored via Seed

	expiresAt time.Time
	lastUse   uint64 // monotonic LRU stamp
}

// GroupIndex assigns perception hashes to reproducible similarity groups.
type GroupIndex struct {
	mu  sync.Mutex
	now func() time.Time

	threshold int
	maxGroups int
	ttl       time.Duration

	groups map[uint]*groupEntry

	// nextGroupID is the largest group id seen so far; new groups receive
	// nextGroupID+1. It never decreases and eviction never recycles ids.
	nextGroupID uint
	useSeq      uint64

	assigned int
	matched  int
	expired  int
	evicted  int
}

// NewGroupIndex builds a GroupIndex from opts.
func NewGroupIndex(opts GroupOptions) (*GroupIndex, error) {
	if opts.Threshold < 0 || opts.Threshold > 64 {
		return nil, errors.New("dedup: GroupOptions.Threshold must be between 0 and 64")
	}
	if opts.MaxGroups <= 0 {
		return nil, errors.New("dedup: GroupOptions.MaxGroups must be greater than zero")
	}
	if opts.TTL < 0 {
		return nil, errors.New("dedup: GroupOptions.TTL must not be negative")
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &GroupIndex{
		now:       now,
		threshold: opts.Threshold,
		maxGroups: opts.MaxGroups,
		ttl:       opts.TTL,
		groups:    make(map[uint]*groupEntry),
	}, nil
}

// Assign finds the best matching active group for hash or creates a new one.
// It returns the group id and whether the group was newly created.
//
// hash must have the "p:" prefix followed by hexadecimal data as validated by
// islazy.ParsePerceptionHash.
func (idx *GroupIndex) Assign(hash string) (uint, bool, error) {
	parsed, err := islazy.ParsePerceptionHash(hash)
	if err != nil {
		return 0, false, fmt.Errorf("dedup: invalid perception hash: %w", err)
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.expireLocked(idx.now())

	bestID, found := idx.matchLocked(parsed)
	if found {
		g := idx.groups[bestID]
		g.members++
		idx.useSeq++
		g.lastUse = idx.useSeq
		idx.matched++
		return bestID, false, nil
	}

	if len(idx.groups) >= idx.maxGroups {
		idx.evictLRULocked()
	}

	idx.nextGroupID++
	id := idx.nextGroupID

	idx.useSeq++
	idx.groups[id] = &groupEntry{
		id:        id,
		hash:      append([]byte(nil), parsed...),
		hasHash:   true,
		members:   1,
		lastUse:   idx.useSeq,
		expiresAt: idx.expiryLocked(idx.now()),
	}
	idx.assigned++

	return id, true, nil
}

// matchLocked finds the smallest-distance representative within threshold.
// Ties resolve to the smaller group id. Iteration order is irrelevant because
// the comparator applies both rules explicitly. Caller holds idx.mu.
func (idx *GroupIndex) matchLocked(hash []byte) (uint, bool) {
	var bestID uint
	bestDist := math.MaxInt
	found := false

	for id, g := range idx.groups {
		if !g.hasHash {
			continue
		}

		dist, err := islazy.HammingDistance(hash, g.hash)
		if err != nil {
			// Incomparable representative (e.g. different hash length);
			// skip it rather than failing the whole assignment.
			continue
		}
		if dist > idx.threshold {
			continue
		}

		if !found || dist < bestDist || (dist == bestDist && id < bestID) {
			bestID = id
			bestDist = dist
			found = true
		}
	}

	return bestID, found
}

// Commit marks groupID as persisted. Missing/evicted groups are ignored.
func (idx *GroupIndex) Commit(groupID uint) {
	if groupID == 0 {
		return
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	if g, ok := idx.groups[groupID]; ok {
		g.persisted = true
	}
}

// Seed restores a group identity from persistent storage. A non-empty hash
// becomes the representative; an empty hash only occupies the group id.
// Seeding the same id with the same hash is ignored; seeding it with a
// different hash returns an error.
func (idx *GroupIndex) Seed(groupID uint, hash string) error {
	if groupID == 0 {
		return errors.New("dedup: seeded group id must be greater than zero")
	}

	var parsed []byte
	hasHash := false
	if hash != "" {
		p, err := islazy.ParsePerceptionHash(hash)
		if err != nil {
			return fmt.Errorf("dedup: cannot seed group %d with invalid hash: %w", groupID, err)
		}
		parsed = p
		hasHash = true
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	if g, ok := idx.groups[groupID]; ok {
		same := g.hasHash == hasHash
		if same && hasHash {
			same = bytes.Equal(g.hash, parsed)
		}
		if !same {
			return fmt.Errorf("dedup: group %d already exists with a different hash", groupID)
		}
		// Identical reseed: nothing to change.
		return nil
	}

	if groupID > idx.nextGroupID {
		idx.nextGroupID = groupID
	}

	idx.useSeq++
	g := &groupEntry{
		id:        groupID,
		hasHash:   hasHash,
		members:   0,
		seeded:    true,
		lastUse:   idx.useSeq,
		expiresAt: idx.expiryLocked(idx.now()),
	}
	if hasHash {
		g.hash = append([]byte(nil), parsed...)
	}
	idx.groups[groupID] = g

	return nil
}

// Discard records a failed write for groupID. The member count is decremented
// and the group is removed only when it was neither persisted nor seeded and
// its member count reached zero.
func (idx *GroupIndex) Discard(groupID uint, hash string) {
	if groupID == 0 {
		return
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	g, ok := idx.groups[groupID]
	if !ok {
		return
	}

	if g.members > 0 {
		g.members--
	}

	if g.members == 0 && !g.persisted && !g.seeded {
		delete(idx.groups, groupID)
	}
}

// Stats returns a consistent snapshot of the index. Reading stats also
// performs lazy TTL cleanup.
func (idx *GroupIndex) Stats() GroupStats {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.expireLocked(idx.now())

	return GroupStats{
		Groups:  len(idx.groups),
		Entries: len(idx.groups),

		Assigned: idx.assigned,
		Matched:  idx.matched,
		Expired:  idx.expired,
		Evicted:  idx.evicted,
	}
}

func (idx *GroupIndex) expiryLocked(now time.Time) time.Time {
	if idx.ttl <= 0 {
		return time.Time{}
	}
	return now.Add(idx.ttl)
}

// expireLocked removes groups whose TTL elapsed. Caller holds idx.mu.
func (idx *GroupIndex) expireLocked(now time.Time) {
	if idx.ttl <= 0 {
		return
	}

	for id, g := range idx.groups {
		if !now.Before(g.expiresAt) {
			delete(idx.groups, id)
			idx.expired++
		}
	}
}

// evictLRULocked removes the group that has not been matched for the longest
// time, breaking ties by smaller group id. Caller holds idx.mu and the map
// must be non-empty.
func (idx *GroupIndex) evictLRULocked() {
	var victim uint
	var oldestUse uint64
	found := false

	for id, g := range idx.groups {
		if !found || g.lastUse < oldestUse || (g.lastUse == oldestUse && id < victim) {
			victim = id
			oldestUse = g.lastUse
			found = true
		}
	}

	if found {
		delete(idx.groups, victim)
		idx.evicted++
	}
}
