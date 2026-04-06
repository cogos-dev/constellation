#!/usr/bin/env bash
# run_scenarios.sh — Run all test scenarios and report results.
set -uo pipefail
cd "$(dirname "$0")"

SCENARIOS=(
    "scenario_happy.sh"
    "scenario_drift.sh"
    "scenario_theft.sh"
    "scenario_join.sh"
)

PASSED=0
FAILED=0
RESULTS=()

for scenario in "${SCENARIOS[@]}"; do
    echo ""
    echo "================================================================"
    echo "Running: $scenario"
    echo "================================================================"
    echo ""

    if bash "$scenario"; then
        RESULTS+=("[PASS] $scenario")
        PASSED=$((PASSED + 1))
    else
        RESULTS+=("[FAIL] $scenario")
        FAILED=$((FAILED + 1))
    fi

    # Clean up between scenarios.
    cd "$(dirname "$0")/.."
    docker compose down -v --remove-orphans 2>/dev/null || true
    docker compose -f docker-compose.yml -f docker-compose.test.yml --profile join-test --profile theft-test down -v --remove-orphans 2>/dev/null || true
    cd "$(dirname "$0")"
    echo ""
done

echo ""
echo "================================================================"
echo "RESULTS"
echo "================================================================"
for result in "${RESULTS[@]}"; do
    echo "  $result"
done
echo ""
echo "Total: $((PASSED + FAILED))  Passed: $PASSED  Failed: $FAILED"
echo "================================================================"

[[ $FAILED -eq 0 ]]
