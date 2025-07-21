# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

wrk -R1 -d60s -c1 -t1 --latency http://localhost:8090/smoke
