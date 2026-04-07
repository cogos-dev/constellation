// gitstore.go — In-process git repository for event storage.
//
// Uses go-git/v5 to manage a bare git repo where events are committed as
// individual JSON files under events/{seq:08d}.json. The tree hash of the
// events/ directory serves as the node's state fingerprint for mutual verification.
package constellation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// GitStore wraps an on-disk git repository for event storage.
type GitStore struct {
	mu       sync.Mutex
	repoPath string
	repo     *git.Repository
}

// NewGitStore initializes a new git repository at the given path.
func NewGitStore(path string) (*GitStore, error) {
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, fmt.Errorf("create repo dir: %w", err)
	}

	eventsDir := filepath.Join(path, "events")
	if err := os.MkdirAll(eventsDir, 0755); err != nil {
		return nil, fmt.Errorf("create events dir: %w", err)
	}

	repo, err := git.PlainInit(path, false)
	if err != nil {
		// Already initialized — open it.
		repo, err = git.PlainOpen(path)
		if err != nil {
			return nil, fmt.Errorf("open repo: %w", err)
		}
	}

	return &GitStore{repoPath: path, repo: repo}, nil
}

// AppendEvent writes an event to events/{seq:08d}.json and commits it.
func (gs *GitStore) AppendEvent(envelope *EventEnvelope) error {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	filename := fmt.Sprintf("%08d.json", envelope.Metadata.Seq)
	eventPath := filepath.Join(gs.repoPath, "events", filename)

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	if err := os.WriteFile(eventPath, data, 0644); err != nil {
		return fmt.Errorf("write event: %w", err)
	}

	wt, err := gs.repo.Worktree()
	if err != nil {
		return fmt.Errorf("worktree: %w", err)
	}

	if _, err := wt.Add(filepath.Join("events", filename)); err != nil {
		return fmt.Errorf("git add: %w", err)
	}

	msg := fmt.Sprintf("event %d: %s", envelope.Metadata.Seq, envelope.HashedPayload.Type)
	_, err = wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{
			Name:  envelope.HashedPayload.NodeID,
			Email: "node@constellation",
			When:  time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("git commit: %w", err)
	}

	return nil
}

// TreeHash computes the hash of the current HEAD tree's events/ subtree.
// This is the state fingerprint used for mutual verification.
func (gs *GitStore) TreeHash() (string, error) {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	ref, err := gs.repo.Head()
	if err != nil {
		return "", fmt.Errorf("head: %w", err)
	}

	commit, err := gs.repo.CommitObject(ref.Hash())
	if err != nil {
		return "", fmt.Errorf("commit: %w", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return "", fmt.Errorf("tree: %w", err)
	}

	for _, entry := range tree.Entries {
		if entry.Name == "events" {
			return entry.Hash.String(), nil
		}
	}

	return "", fmt.Errorf("events directory not found in tree")
}

// ReadEventRange returns events from startSeq to endSeq (inclusive).
func (gs *GitStore) ReadEventRange(startSeq, endSeq int64) ([]*EventEnvelope, error) {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	var events []*EventEnvelope
	eventsDir := filepath.Join(gs.repoPath, "events")

	entries, err := os.ReadDir(eventsDir)
	if err != nil {
		return nil, fmt.Errorf("read events dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		seqStr := strings.TrimSuffix(entry.Name(), ".json")
		seq, err := strconv.ParseInt(seqStr, 10, 64)
		if err != nil {
			continue
		}

		if seq < startSeq || seq > endSeq {
			continue
		}

		data, err := os.ReadFile(filepath.Join(eventsDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read event %d: %w", seq, err)
		}

		var env EventEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, fmt.Errorf("unmarshal event %d: %w", seq, err)
		}

		events = append(events, &env)
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Metadata.Seq < events[j].Metadata.Seq
	})

	return events, nil
}

// LastEvent returns the most recent event, or nil if none.
func (gs *GitStore) LastEvent() (*EventEnvelope, error) {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	eventsDir := filepath.Join(gs.repoPath, "events")
	entries, err := os.ReadDir(eventsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var maxSeq int64 = -1
	var maxFile string

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		seqStr := strings.TrimSuffix(entry.Name(), ".json")
		seq, err := strconv.ParseInt(seqStr, 10, 64)
		if err != nil {
			continue
		}
		if seq > maxSeq {
			maxSeq = seq
			maxFile = entry.Name()
		}
	}

	if maxSeq < 0 {
		return nil, nil
	}

	data, err := os.ReadFile(filepath.Join(eventsDir, maxFile))
	if err != nil {
		return nil, err
	}

	var env EventEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// CorruptEvent overwrites an event file with tampered data (for testing).
func (gs *GitStore) CorruptEvent(seq int64) error {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	filename := fmt.Sprintf("%08d.json", seq)
	eventPath := filepath.Join(gs.repoPath, "events", filename)

	data, err := os.ReadFile(eventPath)
	if err != nil {
		return fmt.Errorf("read event: %w", err)
	}

	var env EventEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	// Tamper: change the data
	env.HashedPayload.Data = map[string]interface{}{"tampered": true}

	tampered, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	return os.WriteFile(eventPath, tampered, 0644)
}

// CommitHash returns the current HEAD commit hash.
func (gs *GitStore) CommitHash() (string, error) {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	ref, err := gs.repo.Head()
	if err != nil {
		if err == plumbing.ErrReferenceNotFound {
			return "", nil
		}
		return "", err
	}
	return ref.Hash().String(), nil
}
