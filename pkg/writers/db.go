package writers

import (
	"errors"
	"fmt"
	"sync"

	"github.com/sensepost/gowitness/internal/islazy"
	"github.com/sensepost/gowitness/pkg/database"
	"github.com/sensepost/gowitness/pkg/dedup"
	"github.com/sensepost/gowitness/pkg/log"
	"github.com/sensepost/gowitness/pkg/models"
	"gorm.io/gorm"
)

const (
	defaultHammingThreshold = 10
	defaultGroupMaxGroups   = 100000
)

// groupIndexes shares one GroupIndex per database URI across DbWriter
// instances. Tests reset this map to simulate a process restart and exercise
// database seeding.
var groupIndexes sync.Map // map[string]*dedup.GroupIndex

// dbWriteLocks serializes writes to the same URI across DbWriter instances,
// which is especially helpful for file backed SQLite databases.
var dbWriteLocks sync.Map // map[string]*sync.Mutex

func defaultGroupOptions() dedup.GroupOptions {
	return dedup.GroupOptions{
		Threshold: defaultHammingThreshold,
		MaxGroups: defaultGroupMaxGroups,
	}
}

func uriWriteLock(uri string) *sync.Mutex {
	if v, ok := dbWriteLocks.Load(uri); ok {
		return v.(*sync.Mutex)
	}

	mu := &sync.Mutex{}
	actual, _ := dbWriteLocks.LoadOrStore(uri, mu)
	return actual.(*sync.Mutex)
}

// sharedGroupIndex returns the GroupIndex shared for uri, creating one and
// seeding it from conn on first use. Options only matter for the first
// creation; later callers reuse the existing instance regardless of the
// options they pass.
func sharedGroupIndex(uri string, opts dedup.GroupOptions, conn *gorm.DB) (*dedup.GroupIndex, error) {
	if v, ok := groupIndexes.Load(uri); ok {
		return v.(*dedup.GroupIndex), nil
	}

	idx, err := dedup.NewGroupIndex(opts)
	if err != nil {
		return nil, err
	}

	if err := seedGroupIndex(idx, conn); err != nil {
		return nil, err
	}

	actual, _ := groupIndexes.LoadOrStore(uri, idx)
	return actual.(*dedup.GroupIndex), nil
}

// seedGroupIndex restores group identities from existing Result rows. It is
// read-only and never alters the schema.
func seedGroupIndex(idx *dedup.GroupIndex, conn *gorm.DB) error {
	var results []models.Result
	if err := conn.
		Select([]string{"id", "perception_hash_group_id", "perception_hash"}).
		Where("perception_hash_group_id > 0").
		Order("perception_hash_group_id ASC").
		Order("id ASC").
		Find(&results).Error; err != nil {
		return fmt.Errorf("writers: cannot seed perception hash groups: %w", err)
	}

	// Rows are ordered by group id then primary key. Record the first
	// non-empty hash encountered for each group. Illegal hashes are later
	// treated as empty, and groups without any representative are seeded
	// with "".
	firstHashByGroup := make(map[uint]string)
	seen := make(map[uint]bool)
	groupIDs := make([]uint, 0)

	for _, r := range results {
		groupID := r.PerceptionHashGroupId
		if groupID == 0 {
			continue
		}

		if !seen[groupID] {
			seen[groupID] = true
			groupIDs = append(groupIDs, groupID)
		}

		if r.PerceptionHash != "" {
			if _, exists := firstHashByGroup[groupID]; !exists {
				firstHashByGroup[groupID] = r.PerceptionHash
			}
		}
	}

	for _, groupID := range groupIDs {
		hash := firstHashByGroup[groupID]
		if hash != "" {
			if _, err := islazy.ParsePerceptionHash(hash); err != nil {
				// Illegal hash is handled as an empty representative.
				hash = ""
			}
		}
		if err := idx.Seed(groupID, hash); err != nil {
			return err
		}
	}

	return nil
}

// DbWriter is a Database writer
type DbWriter struct {
	URI        string
	conn       *gorm.DB
	mutex      sync.Mutex
	groupIndex *dedup.GroupIndex

	closed bool
}

// NewDbWriter initialises a database writer. When groupOpts is omitted,
// default grouping options are used; at most one option value is considered.
// The GroupIndex for a URI is shared between DbWriter instances.
func NewDbWriter(uri string, debug bool, groupOpts ...dedup.GroupOptions) (*DbWriter, error) {
	c, err := database.Connection(uri, false, debug)
	if err != nil {
		return nil, err
	}

	opts := defaultGroupOptions()
	if len(groupOpts) > 0 {
		opts = groupOpts[0]
		// A zero/negative capacity is never valid; treat it as unset and
		// apply the default. Threshold 0 is an explicit, valid value, so it
		// is left untouched.
		if opts.MaxGroups <= 0 {
			opts.MaxGroups = defaultGroupMaxGroups
		}
	}

	groupIndex, err := sharedGroupIndex(uri, opts, c)
	if err != nil {
		if sqlDB, dbErr := c.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
		return nil, err
	}

	return &DbWriter{
		URI:        uri,
		conn:       c,
		mutex:      sync.Mutex{},
		groupIndex: groupIndex,
	}, nil
}

// Write results to the database
func (dw *DbWriter) Write(result *models.Result) error {
	// Serialize within this instance and across instances sharing the URI.
	uriMu := uriWriteLock(dw.URI)
	uriMu.Lock()
	defer uriMu.Unlock()

	dw.mutex.Lock()
	defer dw.mutex.Unlock()

	if dw.closed {
		return errors.New("writers: database writer is closed")
	}

	// Assign Group ID based on PerceptionHash. Invalid or empty hashes leave
	// the group id at 0; the result is still written.
	var groupID uint
	if id, _, err := dw.groupIndex.Assign(result.PerceptionHash); err != nil {
		log.Debug("could not get group id for perception hash", "hash", result.PerceptionHash, "err", err)
	} else {
		groupID = id
		result.PerceptionHashGroupId = groupID
	}

	if err := dw.conn.Create(result).Error; err != nil {
		// The row is not persisted: roll back the group bookkeeping so a
		// brand new, unpublished group does not linger as an orphan.
		if groupID != 0 {
			dw.groupIndex.Discard(groupID, result.PerceptionHash)
		}
		return err
	}

	if groupID != 0 {
		dw.groupIndex.Commit(groupID)
	}

	return nil
}

// Close releases the underlying database connection. It does not destroy the
// shared GroupIndex, and calling Close more than once is not an error.
func (dw *DbWriter) Close() error {
	dw.mutex.Lock()
	defer dw.mutex.Unlock()

	if dw.closed {
		return nil
	}
	dw.closed = true

	if dw.conn != nil {
		if sqlDB, err := dw.conn.DB(); err == nil {
			return sqlDB.Close()
		}
	}

	return nil
}

// AssignGroupID assigns a PerceptionHashGroupId based on Hamming distance.
//
// It is retained as a compatibility wrapper around the shared dedup
// GroupIndex.
func (dw *DbWriter) AssignGroupID(perceptionHashStr string) (uint, error) {
	groupID, _, err := dw.groupIndex.Assign(perceptionHashStr)
	if err != nil {
		return 0, err
	}

	return groupID, nil
}
