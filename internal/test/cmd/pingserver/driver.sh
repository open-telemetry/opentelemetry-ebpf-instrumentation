# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

RATE=${1:-100}
echo Running benchmark with request rate of ${RATE} QPS
wrk -R${RATE} -d60s -c10 -t10 --latency http://localhost:3090/greeting
