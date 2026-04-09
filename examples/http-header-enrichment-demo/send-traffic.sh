#!/usr/bin/env sh
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -eu

count="${1:-50}"

i=1
while [ "$i" -le "$count" ]; do
	tenant="tenant-$((i % 3 + 1))"
	segment="gold"
	if [ $((i % 2)) -eq 0 ]; then
		segment="free"
	fi

	curl -sS "http://localhost:8080/checkout" \
		-H "x-tenant-id: ${tenant}" \
		-H "x-user-segment: ${segment}" \
		-H "authorization: Bearer demo-secret-token-${i}" \
		-H "x-request-id: req-${i}" >/dev/null

	i=$((i + 1))
done

echo "sent ${count} requests"
