# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from check_mise_versions import check_versions


class MiseVersionParityTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "internal/tools").mkdir(parents=True)
        (self.root / "mise.toml").write_text(
            '[tools]\ngo = "1.27.2"\ngolangci-lint = "2.13.2"\n'
        )
        (self.root / "go.mod").write_text("toolchain go1.27.2\n")
        (self.root / "dependencies.Dockerfile").write_text(
            "FROM golang:1.27.2@sha256:abcd AS golang\n"
        )
        (self.root / "internal/tools/go.mod").write_text(
            "\tgithub.com/golangci/golangci-lint/v2 v2.13.2 // indirect\n"
        )
        (self.root / "mise.lock").write_text(
            '[[tools.go]]\nversion = "1.27.2"\n\n'
            '[[tools.golangci-lint]]\nversion = "2.13.2"\n'
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_matching_versions_pass(self):
        check_versions(self.root)

    def test_go_mismatch_fails(self):
        (self.root / "mise.toml").write_text(
            '[tools]\ngo = "1.27.3"\ngolangci-lint = "2.13.2"\n'
        )
        with self.assertRaisesRegex(ValueError, "Mise Go"):
            check_versions(self.root)

    def test_docker_go_mismatch_fails(self):
        (self.root / "dependencies.Dockerfile").write_text(
            "FROM golang:1.27.3@sha256:abcd AS golang\n"
        )
        with self.assertRaisesRegex(ValueError, "dependencies.Dockerfile"):
            check_versions(self.root)

    def test_linter_mismatch_fails(self):
        (self.root / "internal/tools/go.mod").write_text(
            "\tgithub.com/golangci/golangci-lint/v2 v2.14.0 // indirect\n"
        )
        with self.assertRaisesRegex(ValueError, "Mise golangci-lint"):
            check_versions(self.root)

    def test_lock_mismatch_fails(self):
        (self.root / "mise.lock").write_text(
            '[[tools.go]]\nversion = "1.27.2"\n\n'
            '[[tools.golangci-lint]]\nversion = "2.14.0"\n'
        )
        with self.assertRaisesRegex(ValueError, "mise.lock golangci-lint"):
            check_versions(self.root)

    def test_missing_go_tool_fails(self):
        (self.root / "mise.toml").write_text('[tools]\ngolangci-lint = "2.13.2"\n')
        with self.assertRaisesRegex(TypeError, r"\[tools\].go"):
            check_versions(self.root)

    def test_env_lookalikes_do_not_count_as_tool_pins(self):
        (self.root / "mise.toml").write_text(
            '[env]\ngo = "1.27.2"\ngolangci-lint = "2.13.2"\n'
        )
        with self.assertRaisesRegex(ValueError, r"\[tools\] table"):
            check_versions(self.root)

    def test_malformed_duplicate_tool_fails(self):
        (self.root / "mise.toml").write_text(
            '[tools]\ngo = "1.27.2"\ngo = "1.27.3"\ngolangci-lint = "2.13.2"\n'
        )
        with self.assertRaisesRegex(ValueError, "Cannot overwrite a value"):
            check_versions(self.root)

    def test_missing_declaration_fails(self):
        (self.root / "go.mod").write_text("go 1.26.0\n")
        with self.assertRaisesRegex(ValueError, "Go toolchain"):
            check_versions(self.root)


if __name__ == "__main__":
    unittest.main()
