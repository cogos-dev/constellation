#!/usr/bin/env bash
# scenario_theft.sh — Start attacker with alpha's stolen key, verify rejection.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose"
TIMEOUT=45
POLL_INTERVAL=2

echo "=== Key Theft: stolen key insufficient for impersonation ==="

# Start the base constellation and wait for trust.
$COMPOSE up -d --build 2>&1 | tail -3

echo "Waiting for initial trust convergence..."
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

# Start the attacker with alpha's stolen key.
echo "Starting attacker with alpha's stolen key..."
$COMPOSE -f docker-compose.yml -f docker-compose.test.yml --profile theft-test up -d attacker 2>&1 | tail -3

# Wait for identity conflict detection.
echo "Waiting for identity conflict detection..."
elapsed=0
while [[ $elapsed -lt $TIMEOUT ]]; do
    # Check if beta or gamma have rejected any peer.
    for port in 8102 8103; do
        peers=$(curl -sf "http://localhost:${port}/peers" 2>/dev/null) || continue
        rejected=$(echo "$peers" | jq '[.[] | select(.rejected == true)] | length' 2>/dev/null) || continue

        if [[ "${rejected:-0}" -ge 1 ]]; then
            echo "[PASS] Port $port detected identity conflict and rejected peer after ${elapsed}s"
            echo "$peers" | jq -c '.[] | select(.rejected == true) | {node_id, addr, trust, rejected}'

            # Clean up.
            $COMPOSE -f docker-compose.yml -f docker-compose.test.yml --profile theft-test down -v --remove-orphans 2>/dev/null
            exit 0
        fi
    done

    sleep $POLL_INTERVAL
    elapsed=$((elapsed + POLL_INTERVAL))
done

echo "[FAIL] Identity conflict not detected within ${TIMEOUT}s"
for port in 8102 8103; do
    echo "--- Port $port ---"
    curl -sf "http://localhost:${port}/peers" 2>/dev/null | jq '.' || echo "(unreachable)"
done
$COMPOSE -f docker-compose.yml -f docker-compose.test.yml --profile theft-test down -v --remove-orphans 2>/dev/null
exit 1
