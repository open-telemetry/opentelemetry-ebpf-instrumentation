# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

while true; do
	echo grpcurl -plaintext $TARGET_URL grpc.health.v1.Health/Check
	grpcurl -plaintext $TARGET_URL grpc.health.v1.Health/Check
	sleep 1
done
