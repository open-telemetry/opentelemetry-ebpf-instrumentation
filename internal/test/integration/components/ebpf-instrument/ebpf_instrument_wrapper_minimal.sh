#!/bin/bash

# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Start OBI
./ebpf-instrument "$@" &

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
