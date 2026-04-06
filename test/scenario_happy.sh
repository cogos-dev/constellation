#!/usr/bin/env bash
# scenario_happy.sh — Start 3 nodes, wait 6 heartbeat cycles, assert all peers trusted.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose"
TIMEOUT=45
POLL_INTERVAL=2

echo "=== Happy Path: 3-node trust convergence ==="

# Start the 3-node constellation.
$COMPOSE up -d --build 2>&1 | tail -3

# Poll until all nodes show all peers as trusted (trust >= 0.7).
check_trust() {
    local node=$1
    local port=$2
    local peers_json
    peers_json=$(curl -sf "http://localhost:${port}/peers" 2>/dev/null) || return 1

    # Count peers with trust >= 0.7
    local trusted
    trusted=$(echo "$peers_json" | jq '[.[] | select(.trust >= 0.7)] | length' 2>/dev/null) || return 1

    # Each node should see 2 trusted peers.
    [[ "$trusted" -ge 2 ]]
}

echo "Waiting for trust convergence (timeout ${TIMEOUT}s)..."
elapsed=0
while [[ $elapsed -lt $TIMEOUT ]]; do
    all_good=true
    for port in 8101 8102 8103; do
        if ! check_trust "node" "$port"; then
            all_good=false
            break
        fi
    done

    if $all_good; then
        echo "[PASS] All 3 nodes show 2+ trusted peers after ${elapsed}s"
        # Print final state.
        for port in 8101 8102 8103; do
            echo "--- Port $port ---"
            curl -sf "http://localhost:${port}/peers" | jq -c '.[] | {node_id, trust: (.trust * 100 | round / 100), trust_level}'
        done
        $COMPOSE down -v --remove-orphans 2>/dev/null
        exit 0
    fi

    sleep $POLL_INTERVAL
    elapsed=$((elapsed + POLL_INTERVAL))
done

echo "[FAIL] Trust did not converge within ${TIMEOUT}s"
for port in 8101 8102 8103; do
    echo "--- Port $port ---"
    curl -sf "http://localhost:${port}/peers" 2>/dev/null | jq '.' || echo "(unreachable)"
done
$COMPOSE down -v --remove-orphans 2>/dev/null
exit 1
