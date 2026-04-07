// coherence.go — 3-layer coherence validation for constellation nodes.
//
// Validates the integrity of a node's event ledger:
//   1. Hash chain integrity (event[i].prior_hash == hash(event[i-1]))
//   2. Schema validation (required fields present, valid timestamps)
//   3. Temporal monotonicity (timestamps non-decreasing, sequences contiguous)
package constellation

import (
	"fmt"
	"time"
)

// CoherenceReport is the result of validating a node's ledger.
type CoherenceReport struct {
	Pass       bool              `json:"pass"`
	Checks    []CoherenceCheck  `json:"checks"`
	Timestamp  string            `json:"timestamp"`
}

// CoherenceCheck is the result of a single validation layer.
type CoherenceCheck struct {
	Layer   string `json:"layer"`
	Pass    bool   `json:"pass"`
	Detail  string `json:"detail,omitempty"`
}

// ValidateCoherence runs all 3 validation layers on a set of events.
func ValidateCoherence(events []*EventEnvelope) *CoherenceReport {
	report := &CoherenceReport{
		Pass:      true,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}

	checks := []func([]*EventEnvelope) CoherenceCheck{
		validateHashChain,
		validateSchema,
		validateTemporalMonotonicity,
	}

	for _, check := range checks {
		result := check(events)
		report.Checks = append(report.Checks, result)
		if !result.Pass {
			report.Pass = false
		}
	}

	return report
}

// validateHashChain verifies that each event's prior_hash matches the hash of the previous event.
func validateHashChain(events []*EventEnvelope) CoherenceCheck {
	if len(events) == 0 {
		return CoherenceCheck{Layer: "hash_chain", Pass: true, Detail: "empty ledger"}
	}

	for i := 1; i < len(events); i++ {
		prev := events[i-1]
		curr := events[i]

		if curr.HashedPayload.PriorHash != prev.Metadata.Hash {
			return CoherenceCheck{
				Layer:  "hash_chain",
				Pass:   false,
				Detail: fmt.Sprintf("break at seq %d: prior_hash %s != prev hash %s", curr.Metadata.Seq, curr.HashedPayload.PriorHash, prev.Metadata.Hash),
			}
		}

		// Re-hash the previous event to verify its stored hash is correct.
		canonical, err := CanonicalizeEvent(&prev.HashedPayload)
		if err != nil {
			return CoherenceCheck{
				Layer:  "hash_chain",
				Pass:   false,
				Detail: fmt.Sprintf("cannot canonicalize seq %d: %v", prev.Metadata.Seq, err),
			}
		}

		computed := HashEvent(canonical)
		if computed != prev.Metadata.Hash {
			return CoherenceCheck{
				Layer:  "hash_chain",
				Pass:   false,
				Detail: fmt.Sprintf("tampered at seq %d: computed %s != stored %s", prev.Metadata.Seq, computed, prev.Metadata.Hash),
			}
		}
	}

	// Also verify the last event's hash.
	last := events[len(events)-1]
	canonical, err := CanonicalizeEvent(&last.HashedPayload)
	if err != nil {
		return CoherenceCheck{
			Layer:  "hash_chain",
			Pass:   false,
			Detail: fmt.Sprintf("cannot canonicalize last event seq %d: %v", last.Metadata.Seq, err),
		}
	}
	computed := HashEvent(canonical)
	if computed != last.Metadata.Hash {
		return CoherenceCheck{
			Layer:  "hash_chain",
			Pass:   false,
			Detail: fmt.Sprintf("tampered at seq %d: computed %s != stored %s", last.Metadata.Seq, computed, last.Metadata.Hash),
		}
	}

	return CoherenceCheck{Layer: "hash_chain", Pass: true, Detail: fmt.Sprintf("%d events verified", len(events))}
}

// validateSchema checks that required fields are present and timestamps are valid RFC3339.
func validateSchema(events []*EventEnvelope) CoherenceCheck {
	for _, env := range events {
		p := env.HashedPayload
		if p.Type == "" {
			return CoherenceCheck{Layer: "schema", Pass: false, Detail: fmt.Sprintf("seq %d: missing type", env.Metadata.Seq)}
		}
		if p.NodeID == "" {
			return CoherenceCheck{Layer: "schema", Pass: false, Detail: fmt.Sprintf("seq %d: missing node_id", env.Metadata.Seq)}
		}
		if p.Timestamp == "" {
			return CoherenceCheck{Layer: "schema", Pass: false, Detail: fmt.Sprintf("seq %d: missing timestamp", env.Metadata.Seq)}
		}
		if _, err := time.Parse(time.RFC3339Nano, p.Timestamp); err != nil {
			if _, err2 := time.Parse(time.RFC3339, p.Timestamp); err2 != nil {
				return CoherenceCheck{Layer: "schema", Pass: false, Detail: fmt.Sprintf("seq %d: invalid timestamp: %s", env.Metadata.Seq, p.Timestamp)}
			}
		}
		if env.Metadata.Hash == "" {
			return CoherenceCheck{Layer: "schema", Pass: false, Detail: fmt.Sprintf("seq %d: missing hash", env.Metadata.Seq)}
		}
	}
	return CoherenceCheck{Layer: "schema", Pass: true, Detail: fmt.Sprintf("%d events valid", len(events))}
}

// validateTemporalMonotonicity checks that timestamps are non-decreasing and sequences are contiguous.
func validateTemporalMonotonicity(events []*EventEnvelope) CoherenceCheck {
	if len(events) == 0 {
		return CoherenceCheck{Layer: "temporal", Pass: true, Detail: "empty ledger"}
	}

	for i := 1; i < len(events); i++ {
		prev := events[i-1]
		curr := events[i]

		// Check sequence contiguity.
		if curr.Metadata.Seq != prev.Metadata.Seq+1 {
			return CoherenceCheck{
				Layer:  "temporal",
				Pass:   false,
				Detail: fmt.Sprintf("seq gap: %d -> %d", prev.Metadata.Seq, curr.Metadata.Seq),
			}
		}

		// Check timestamp monotonicity.
		prevTime, _ := time.Parse(time.RFC3339Nano, prev.HashedPayload.Timestamp)
		currTime, _ := time.Parse(time.RFC3339Nano, curr.HashedPayload.Timestamp)
		if currTime.Before(prevTime) {
			return CoherenceCheck{
				Layer:  "temporal",
				Pass:   false,
				Detail: fmt.Sprintf("time reversal at seq %d: %s < %s", curr.Metadata.Seq, curr.HashedPayload.Timestamp, prev.HashedPayload.Timestamp),
			}
		}
	}

	return CoherenceCheck{Layer: "temporal", Pass: true, Detail: fmt.Sprintf("%d events monotonic", len(events))}
}
