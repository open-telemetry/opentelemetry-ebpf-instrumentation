#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Three-process Go chain (a -> b -> c). One process per port so OBI's
# port-based discovery resolves each leg as a distinct service name.
set -eu

/usr/local/bin/tpclient-go c 8002 &
PID_C=$!
/usr/local/bin/tpclient-go b 8001 http://localhost:8002 &
PID_B=$!
/usr/local/bin/tpclient-go a 8000 http://localhost:8001 &
PID_A=$!

# Forward signals so docker stop terminates all three.
trap 'kill ${PID_A} ${PID_B} ${PID_C} 2>/dev/null || true' INT TERM
# Wait for the first process to exit (bash 4.3+ wait -n).
# If any one crashes the container exits immediately with its status,
# rather than hanging until the surviving processes are stopped externally.
wait -n $PID_A $PID_B $PID_C
status=$?
kill $PID_A $PID_B $PID_C 2>/dev/null || true
wait $PID_A $PID_B $PID_C 2>/dev/null || true
exit $status
