#!/usr/bin/env bash
# scenario_join.sh — Start delta, verify it becomes trusted by all 4 nodes.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose"
TIMEOUT=60
POLL_INTERVAL=2

echo "=== Dynamic Join: delta joins existing constellation ==="

# Start the base 3-node constellation.
$COMPOSE up -d --build 2>&1 | tail -3

echo "Waiting for initial 3-node trust convergence..."
elapsed=0
while [[ $elapsed -lt 30 ]]; do
    trusted=$(curl -sf "http://localhost:8102/peers" 2>/dev/null | jq '[.[] | select(.trust >= 0.7)] | length' 2>/dev/null) || true
    if [[ "${trusted:-0}" -ge 2 ]]; then
        echo "Initial trust established after ${elapsed}s"
        break
    fi
    sleep $POLL_INTERVAL
    elapsed=$((elapsed + POLL_INTERVAL))
done

# Start delta.
echo "Starting delta (joining via alpha)..."
$COMPOSE -f docker-compose.yml -f docker-compose.test.yml --profile join-test up -d delta 2>&1 | tail -3

# Wait for delta to become trusted by all nodes.
echo "Waiting for delta to become trusted (timeout ${TIMEOUT}s)..."
elapsed=0
while [[ $elapsed -lt $TIMEOUT ]]; do
    all_see_delta=true

    # Check delta can see peers.
    delta_peers=$(curl -sf "http://localhost:8104/peers" 2>/dev/null | jq '[.[] | select(.trust >= 0.7)] | length' 2>/dev/null) || true
    if [[ "${delta_peers:-0}" -lt 1 ]]; then
        all_see_delta=false
    fi

    # Check that at least one original node sees delta as trusted.
    for port in 8101 8102 8103; do
        total_trusted=$(curl -sf "http://localhost:${port}/peers" 2>/dev/null | jq '[.[] | select(.trust >= 0.7)] | length' 2>/dev/null) || true
        if [[ "${total_trusted:-0}" -lt 3 ]]; then
            all_see_delta=false
        fi
    done

    if $all_see_delta; then
        echo "[PASS] Delta is trusted by all nodes after ${elapsed}s"
        for port in 8101 8102 8103 8104; do
            echo "--- Port $port ---"
            curl -sf "http://localhost:${port}/peers" | jq -c '.[] | {node_id, trust: (.trust * 100 | round / 100), trust_level}'
        done
        $COMPOSE -f docker-compose.yml -f docker-compose.test.yml --profile join-test down -v --remove-orphans 2>/dev/null
        exit 0
    fi

    sleep $POLL_INTERVAL
    elapsed=$((elapsed + POLL_INTERVAL))
done

echo "[FAIL] Delta did not become trusted within ${TIMEOUT}s"
for port in 8101 8102 8103 8104; do
    echo "--- Port $port ---"
    curl -sf "http://localhost:${port}/peers" 2>/dev/null | jq '.' || echo "(unreachable)"
done
$COMPOSE -f docker-compose.yml -f docker-compose.test.yml --profile join-test down -v --remove-orphans 2>/dev/null
exit 1
