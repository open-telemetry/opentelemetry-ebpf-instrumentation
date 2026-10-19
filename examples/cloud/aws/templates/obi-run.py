#!/usr/bin/python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import json
import os

with open("/etc/obi/environment.json", encoding="utf-8") as file:
    environment = os.environ | json.load(file)

environment["OTEL_EBPF_CONFIG_PATH"] = "/etc/obi/config.yaml"
os.execve("/opt/obi/obi", ["/opt/obi/obi"], environment)
