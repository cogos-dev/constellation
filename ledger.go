// ledger.go — Hash-chained event ledger for constellation nodes.
//
// Adapted from apps/cogos-v3/ledger.go. Events are canonicalized (RFC 8785),
// hashed (SHA-256), and chained via prior_hash fields.
package constellation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// EventEnvelope is the on-disk event shape committed to the git store.
type EventEnvelope struct {
	HashedPayload EventPayload  `json:"hashed_payload"`
	Metadata      EventMetadata `json:"metadata"`
}

// EventPayload is the content that gets canonicalized and hashed.
type EventPayload struct {
	Type      string                 `json:"type"`
	Timestamp string                 `json:"timestamp"`
	NodeID    string                 `json:"node_id"`
	PriorHash string                 `json:"prior_hash,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// EventMetadata is NOT included in the hash.
type EventMetadata struct {
	Hash string `json:"hash"`
	Seq  int64  `json:"seq"`
}

// CanonicalizeEvent produces RFC 8785 canonical JSON for an event payload.
func CanonicalizeEvent(payload *EventPayload) ([]byte, error) {
	data := map[string]interface{}{
		"type":      payload.Type,
		"timestamp": payload.Timestamp,
		"node_id":   payload.NodeID,
	}
	if payload.PriorHash != "" {
		data["prior_hash"] = payload.PriorHash
	}
	if len(payload.Data) > 0 {
		data["data"] = payload.Data
	}
	return canonicalJSON(data)
}

// canonicalJSON is a minimal RFC 8785 implementation (sorted keys, no whitespace).
func canonicalJSON(v interface{}) ([]byte, error) {
	switch value := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(value))
		for k := range value {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			kj, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			vj, err := canonicalJSON(value[k])
			if err != nil {
				return nil, err
			}
			parts = append(parts, string(kj)+":"+string(vj))
		}
		return []byte("{" + strings.Join(parts, ",") + "}"), nil
	case []interface{}:
		var parts []string
		for _, item := range value {
			ij, err := canonicalJSON(item)
			if err != nil {
				return nil, err
			}
			parts = append(parts, string(ij))
		}
		return []byte("[" + strings.Join(parts, ",") + "]"), nil
	default:
		return json.Marshal(v)
	}
}

// HashEvent computes the SHA-256 hash of canonical bytes.
func HashEvent(canonicalBytes []byte) string {
	h := sha256.Sum256(canonicalBytes)
	return hex.EncodeToString(h[:])
}

// NewEvent creates a new event envelope with hash chaining.
func NewEvent(nodeID, eventType string, seq int64, priorHash string, data map[string]interface{}) (*EventEnvelope, error) {
	payload := EventPayload{
		Type:      eventType,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		NodeID:    nodeID,
		PriorHash: priorHash,
		Data:      data,
	}

	canonical, err := CanonicalizeEvent(&payload)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}

	return &EventEnvelope{
		HashedPayload: payload,
		Metadata: EventMetadata{
			Hash: HashEvent(canonical),
			Seq:  seq,
		},
	}, nil
}
