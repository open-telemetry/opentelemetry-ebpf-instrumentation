# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import gc
import json
import os
import signal
import sys


def allocate_cycles():
    cycles = []
    for _ in range(100):
        cycle = []
        cycle.append(cycle)
        cycles.append(cycle)
    del cycles


gc.disable()
start_read_fd = int(sys.argv[1])
stats_write_fd = int(sys.argv[2])
os.read(start_read_fd, 1)
os.close(start_read_fd)
for generation in range(3):
    allocate_cycles()
    gc.collect(generation)
os.write(stats_write_fd, json.dumps(gc.get_stats()).encode())
os.close(stats_write_fd)
signal.pause()
