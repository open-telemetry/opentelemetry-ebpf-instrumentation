# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from rust_context import load_versions, prepare, prepare_dependencies, scenarios

spec = importlib.util.spec_from_file_location("update_rust_offsets", Path(__file__).with_name("update-rust-offsets.py"))
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class RustOffsetWorkflowTests(unittest.TestCase):
    def test_latest_four_minors(self):
        tags = "\n".join("hash refs/tags/"+version for version in ("1.96.9","1.97.0","1.97.1","1.98.1","1.99.0","1.99.1","1.100.0","1.101.0-beta.1"))
        self.assertEqual(["1.97.1","1.98.1","1.99.1","1.100.0"],updater.latest_toolchains(tags))

    def test_legacy_manifest_has_no_missing_hyper_dependency(self):
        case = next(case for case in load_versions()["cases"] if case["name"]=="reqwest-0.10")
        with tempfile.TemporaryDirectory() as work:
            manifest = prepare(case,Path(work)).read_text()
        self.assertNotIn('"hyper/http2"',manifest)
        self.assertIn('tokio02 = ',manifest)

    def test_dependencies_are_generated_and_reused_in_work_directory(self):
        case = load_versions()["cases"][0]
        with tempfile.TemporaryDirectory() as work:
            project = Path(work)
            lock = project / "Cargo.lock"
            def generate(command, **kwargs):
                self.assertIn("generate-lockfile", command)
                self.assertIn("--offline", command)
                lock.write_text("resolved dependency graph")
            with mock.patch("rust_context.subprocess.run", side_effect=generate) as cargo:
                prepare_dependencies(case, project, "1.100.0", offline=True)
                prepare_dependencies(case, project, "1.100.0", offline=True)
                self.assertEqual(1, cargo.call_count)
                prepare_dependencies(case, project, "1.100.0", offline=True, refresh_lock=True)
                self.assertEqual(2, cargo.call_count)
            self.assertEqual("resolved dependency graph", lock.read_text())

    def test_manifest_changes_discard_stale_work_directory_lock(self):
        case = load_versions()["cases"][0]
        with tempfile.TemporaryDirectory() as work:
            project = Path(work)
            prepare(case, project)
            lock = project / "Cargo.lock"
            lock.write_text("cached dependency graph")
            prepare(case, project)
            self.assertEqual("cached dependency graph", lock.read_text())
            prepare(dict(case, tokio="1.53.3"), project)
            self.assertFalse(lock.exists())

    def test_measurements_include_generated_dependency_graph(self):
        case = load_versions()["cases"][0]
        with tempfile.TemporaryDirectory() as work:
            lock = Path(work) / "Cargo.lock"
            lock.write_text("first dependency graph")
            first = updater.fixture_digest(case, lock)
            lock.write_text("changed dependency graph")
            self.assertNotEqual(first, updater.fixture_digest(case, lock))

    def test_protocol_scenarios(self):
        cases = load_versions()["cases"]
        matrix = {name:env for name,_,env in scenarios(cases)}
        self.assertEqual("1",matrix["rustls-server-http1"]["SERVER_HTTP1"])
        self.assertEqual("1",matrix["rustls-server-http1-trailers"]["TRAILERS"])
        self.assertEqual("1",matrix["rustls-server-http1-trailers-socket"]["NO_USER_WRITE"])
        self.assertEqual("1",matrix["latest-grouped-worker"]["SHARED_EXECUTABLE"])
        for sampler, parent_flags, sampled in (("always_off", "01", "0"),
                                                ("always_on", "00", "1"),
                                                ("parentbased_always_off", "01", "1"),
                                                ("parentbased_always_on", "00", "0")):
            env = matrix["rustls-server-"+sampler]
            self.assertEqual(sampler, env["SAMPLER"])
            self.assertEqual(parent_flags, env["PARENT_FLAGS"])
            self.assertEqual(sampled, env["EXPECTED_SAMPLED"])
        for version in ("0.20","0.21","0.22","0.23"):
            self.assertEqual("1",matrix["rustls-direct-client-"+version+"-http2"]["H2"])
            self.assertEqual("1",matrix["rustls-server-"+version]["SERVER"])
        self.assertEqual(len(matrix), len(list(scenarios(cases))))
        for name in ("latest", "reqwest-0.12", "reqwest-0.11", "reqwest-0.10"):
            for protocol in ("http1", "http2"):
                env = matrix[name+"-socket-"+protocol]
                self.assertEqual("1", env["NO_USER_WRITE"])
                self.assertEqual("1", env["INJECT"])
        for name in ("latest-http1", "latest-http2", "rustls-client-http1", "rustls-client-http2"):
            env = matrix[name+"-otel-exporter"]
            self.assertEqual("1", env["OTEL_EXPORTER"])
            self.assertEqual("1", env["INJECT"])
        for protocol in ("http1", "http2"):
            env = matrix["latest-"+protocol+"-otel-exporter-app-header"]
            self.assertEqual("1", env["APP_HEADER"])
            self.assertEqual("1", env["FORWARDED_APP_HEADER"])


if __name__ == "__main__":
    unittest.main()
