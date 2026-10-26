# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Exercise HTTPS with the startup agent but no OBI kernel control path."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--image", default="hatest-java-httpclient-traceparent")
    args = parser.parse_args()
    root = args.repo.resolve()
    jar = root / "pkg/internal/java/embedded/obi-java-agent.jar"
    compose = root / "internal/test/integration/docker-compose-java-httpclient-traceparent.yml"
    env = dict(os.environ, COMPOSE_PROJECT_NAME="obi-httpclient-no-kernel",
               JAVA_HTTPCLIENT_FIXTURE_IMAGE=args.image)
    with tempfile.TemporaryDirectory() as directory:
        override = Path(directory) / "override.json"
        override.write_text(json.dumps({"services": {"testserver": {
            "volumes": [str(jar) + ":/fixture/obi-agent.jar:ro"],
            "environment": {"JAVA_TOOL_OPTIONS": "-javaagent:/fixture/obi-agent.jar=httpHeaders=true"}
        }}}))
        command = ["docker", "compose", "-f", str(compose), "-f", str(override)]
        try:
            subprocess.run(command + ["up", "-d", "--no-build", "testserver", "proxy", "downstream"],
                           env=env, check=True)
            for attempt in range(60):
                try:
                    if urllib.request.urlopen("http://localhost:18080/health", timeout=2).read():
                        break
                except OSError:
                    pass
                time.sleep(1)
            else:
                raise RuntimeError("startup agent did not initialize")
            for mode in ["generated", "connect-failure", "generated"]:
                identity = "no-kernel-" + mode + "-" + str(time.time_ns())
                request = urllib.request.Request("http://localhost:18080/call/" + identity, headers={
                    "X-Async": "true", "X-Test-Mode": mode,
                    "traceparent": "00-11111111111111111111111111111111-2222222222222222-01"})
                with urllib.request.urlopen(request, timeout=30) as response:
                    body = response.read().decode()
                    assert response.status == 200, body
                    assert body == ("expected failure" if mode == "connect-failure" else "downstream"), body
                if mode == "generated":
                    with urllib.request.urlopen("http://localhost:18082/records/" + identity) as response:
                        records = json.load(response)
                    assert len(records) == 1 and not records[0]["headers"], records
                    assert records[0]["protocol"] == 1, records
            with urllib.request.urlopen("http://localhost:18080/propagation-state") as response:
                assert response.read() == b"0:0"
            print("PASS: startup agent without kernel control preserves HTTPS, exceptions, and cleanup")
        finally:
            subprocess.run(command + ["down", "--timeout", "10"], env=env, check=True)


if __name__ == "__main__":
    main()
