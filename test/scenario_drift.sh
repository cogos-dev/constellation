#!/usr/bin/env bash
# scenario_drift.sh — Corrupt an event in alpha's git repo, verify detection.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose"
TIMEOUT=45
POLL_INTERVAL=2

echo "=== Drift Detection: tamper with alpha's ledger ==="

# Start the 3-node constellation and wait for initial trust.
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

# Corrupt an event in alpha's repo.
echo "Tampering with alpha's event file..."
docker exec alpha sh -c '
    # Find the most recent event file
    EVENT_FILE=$(ls -1 /data/repo/events/*.json 2>/dev/null | tail -1)
    if [ -z "$EVENT_FILE" ]; then
        echo "No event files found"
        exit 1
    fi
    # Corrupt it by modifying the data
    sed -i "s/heartbeat/TAMPERED/g" "$EVENT_FILE"
    echo "Tampered: $EVENT_FILE"
'

# Wait for alpha's health check to fail.
echo "Waiting for alpha to detect self-incoherence..."
elapsed=0
while [[ $elapsed -lt $TIMEOUT ]]; do
    health=$(curl -sf "http://localhost:8101/health" 2>/dev/null) || true
    pass=$(echo "$health" | jq -r '.pass' 2>/dev/null) || true

    if [[ "$pass" == "false" ]]; then
        echo "[PASS] Alpha's /health reports pass: false after ${elapsed}s"
        echo "$health" | jq -c '{pass, checks: [.checks[] | select(.pass == false)]}'

        # Check if beta/gamma detect alpha as suspect.
        for port in 8102 8103; do
            alpha_trust=$(curl -sf "http://localhost:${port}/peers" 2>/dev/null | jq '[.[] | select(.trust < 0.7)] | length' 2>/dev/null) || true
            if [[ "${alpha_trust:-0}" -ge 1 ]]; then
                echo "[PASS] Port $port sees a peer with reduced trust"
            fi
        done

        $COMPOSE down -v --remove-orphans 2>/dev/null
        exit 0
    fi

    sleep $POLL_INTERVAL
    elapsed=$((elapsed + POLL_INTERVAL))
done

echo "[FAIL] Alpha's health check did not detect tampering within ${TIMEOUT}s"
curl -sf "http://localhost:8101/health" 2>/dev/null | jq '.' || echo "(unreachable)"
$COMPOSE down -v --remove-orphans 2>/dev/null
exit 1
