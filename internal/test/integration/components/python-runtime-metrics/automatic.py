# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import time


while True:
    for _ in range(5000):
        cycle = []
        cycle.append(cycle)
    print("allocation batch complete", flush=True)
    time.sleep(0.1)
