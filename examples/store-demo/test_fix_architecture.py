#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for fix_architecture.py.

These run against synthetic fixtures in a temp directory (not the real
manifests), so they exercise the parsing/rendering logic in isolation. The
`--check` CI job covers the real manifests; this covers the pure logic.

Run: python3 examples/store-demo/test_fix_architecture.py
"""

import importlib.util
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "fix_architecture", Path(__file__).resolve().parent / "fix_architecture.py"
)
fa = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(fa)

ALPHA = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: alpha
spec:
  template:
    spec:
      containers:
      - name: alpha
        env:
        - name: BETA_ADDR
          value: "beta:2222"
        - name: REDIS_ADDR
          value: "redis-cache:6379"
---
apiVersion: v1
kind: Service
metadata:
  name: alpha
spec:
  ports:
  - name: grpc
    port: 1111
    targetPort: 1111
    appProtocol: grpc
"""

BETA = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: beta
spec: {}
---
apiVersion: v1
kind: Service
metadata:
  name: beta
spec:
  ports:
  - name: http
    port: 2222
    targetPort: 2222
    appProtocol: http
"""

REDIS = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-cache
spec: {}
---
apiVersion: v1
kind: Service
metadata:
  name: redis-cache
spec:
  ports:
  - name: tcp-redis
    port: 6379
    targetPort: 6379
    appProtocol: redis
"""

# An OBI-authored service under services/ with its datastore bundled in the
# same manifest, mirroring the real recentlyviewed.yaml + aerospike layout.
GAMMA = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gamma
spec:
  template:
    spec:
      containers:
      - name: server
        env:
        - name: AEROSPIKE_ADDR
          value: "aerospike:3000"
---
apiVersion: v1
kind: Service
metadata:
  name: gamma
spec:
  ports:
  - name: http
    port: 4444
    targetPort: 4444
    appProtocol: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aerospike
spec: {}
---
apiVersion: v1
kind: Service
metadata:
  name: aerospike
spec:
  ports:
  - name: tcp-aerospike
    port: 3000
    targetPort: 3000
    appProtocol: aerospike
"""

# Numbered infra manifest that also declares a Deployment: must be filtered out.
INFRA = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lgtm
"""


class FixArchitectureTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        k8s = root / "k8s"
        k8s.mkdir()
        (k8s / "alpha.yaml").write_text(ALPHA)
        (k8s / "beta.yaml").write_text(BETA)
        (k8s / "redis-cache.yaml").write_text(REDIS)
        (k8s / "gamma.yaml").write_text(GAMMA)
        (k8s / "00-observability.yaml").write_text(INFRA)
        (k8s / "kustomization.yaml").write_text("resources:\n- alpha.yaml\n")

        src = root / "app" / "src"
        (src / "alpha").mkdir(parents=True)
        (src / "alpha" / "go.mod").write_text("module alpha\n")
        (src / "beta").mkdir(parents=True)
        (src / "beta" / "package.json").write_text("{}\n")

        # OBI-authored services live outside the vendored app/src tree.
        services_src = root / "services"
        (services_src / "gamma").mkdir(parents=True)
        (services_src / "gamma" / "pom.xml").write_text("<project/>\n")

        # Point the module at the fixture tree.
        fa.K8S = k8s
        fa.APP_SRC = src
        fa.SERVICES_SRC = services_src

    def tearDown(self):
        self._tmp.cleanup()

    def test_services_exclude_numbered_infra(self):
        # lgtm lives in 00-observability.yaml and must be filtered out.
        self.assertEqual(
            fa.manifest_services(),
            {"alpha", "beta", "redis-cache", "gamma", "aerospike"},
        )

    def test_edges(self):
        self.assertEqual(
            fa.manifest_edges(),
            {
                ("alpha", "beta", "2222"),
                ("alpha", "redis-cache", "6379"),
                ("gamma", "aerospike", "3000"),
            },
        )

    def test_protocols_from_appprotocol(self):
        self.assertEqual(
            fa.manifest_protocols(),
            {
                "alpha": "grpc",
                "beta": "http",
                "redis-cache": "redis",
                "gamma": "http",
                "aerospike": "aerospike",
            },
        )

    def test_language_detection(self):
        self.assertEqual(fa.detect_language("alpha")[0], "Go")
        self.assertEqual(fa.detect_language("beta")[0], "Node.js")
        # No source dir + "redis" in the name -> datastore fallback.
        self.assertEqual(fa.detect_language("redis-cache")[0], "Redis (datastore)")
        # Resolved from services/ rather than app/src/, and via pom.xml.
        self.assertEqual(fa.detect_language("gamma"), ("Java", "`pom.xml`"))
        self.assertEqual(
            fa.detect_language("aerospike")[0], "Aerospike (datastore)"
        )

    def test_render_regions_content(self):
        regions = fa.render_regions()
        # Hyphen becomes an underscore in the mermaid node id.
        self.assertIn('redis_cache["redis-cache<br/>:6379 Redis"]', regions["graph"])
        self.assertIn("alpha -->|Redis| redis_cache", regions["graph"])
        self.assertIn("alpha -->|HTTP| beta", regions["graph"])
        self.assertIn("| alpha | beta | `beta:2222` | HTTP |", regions["connections"])
        self.assertIn(
            "| alpha | redis-cache | `redis-cache:6379` | Redis |", regions["connections"]
        )
        # appProtocol: aerospike must render through PROTOCOL_DISPLAY, not raw.
        self.assertIn('aerospike["aerospike<br/>:3000 Aerospike"]', regions["graph"])
        self.assertIn("gamma -->|Aerospike| aerospike", regions["graph"])
        self.assertIn(
            "| gamma | aerospike | `aerospike:3000` | Aerospike |",
            regions["connections"],
        )
        self.assertIn("Aerospike (datastore)", regions["legend"])
        self.assertIn("| gamma | Java | `pom.xml` |", regions["languages"])

    def test_missing_appprotocol_is_fatal(self):
        # Drop beta's appProtocol; beta is a callee, so generation must fail.
        beta = fa.K8S / "beta.yaml"
        beta.write_text(BETA.replace("    appProtocol: http\n", ""))
        with self.assertRaises(SystemExit):
            fa.render_regions()

    def test_apply_replaces_only_marked_region(self):
        doc = (
            "intro\n<!-- generated:x -->\nOLD CONTENT\n<!-- /generated:x -->\noutro\n"
        )
        out = fa.apply(doc, {"x": "NEW"})
        self.assertEqual(
            out, "intro\n<!-- generated:x -->\nNEW\n<!-- /generated:x -->\noutro\n"
        )
        self.assertIn("intro", out)
        self.assertIn("outro", out)

    def test_apply_missing_marker_is_fatal(self):
        with self.assertRaises(SystemExit):
            fa.apply("no markers here", {"x": "NEW"})


if __name__ == "__main__":
    unittest.main()
