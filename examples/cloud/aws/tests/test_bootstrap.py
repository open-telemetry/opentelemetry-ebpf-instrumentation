# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class BootstrapTest(unittest.TestCase):
    def test_compile_without_home(self):
        aws = Path(__file__).resolve().parents[1]
        template = (aws / "templates/user-data.sh.tftpl").read_text()
        build = next(line for line in template.splitlines() if "go build " in line)
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"HOME", "XDG_CACHE_HOME", "GOCACHE"}
        }

        for service in ("frontend", "backend"):
            with self.subTest(service=service), tempfile.TemporaryDirectory() as directory:
                source = aws.parent.parent / "http-header-enrichment-demo/app/cmd" / service / "main.go"
                (Path(directory) / "main.go").write_text(source.read_text())
                command = build.replace("${service}", service).replace("/opt/demo", directory)
                result = subprocess.run(
                    ["bash", "-c", command],
                    cwd=directory,
                    env=environment,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((Path(directory) / service).is_file())


if __name__ == "__main__":
    unittest.main()
