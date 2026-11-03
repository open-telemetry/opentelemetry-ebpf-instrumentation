import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.check_java_agent_jar import check_jars


class CheckJavaAgentJarTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.built = Path(self.temp_dir.name) / "built.jar"
        self.embedded = Path(self.temp_dir.name) / "embedded.jar"

    def write_jar(self, path, entries, date_time=(2024, 1, 1, 0, 0, 0)):
        with zipfile.ZipFile(path, "w") as jar:
            for name, content in entries.items():
                jar.writestr(zipfile.ZipInfo(name, date_time), content)

    def test_identical_project_entries_pass_ignoring_archive_order_and_timestamps(self):
        self.write_jar(
            self.built,
            {
                "io/opentelemetry/obi/java/Agent.class": b"agent",
                "obi-java-agent-version.properties": b"version=1\n",
                "native/linux-amd64/libobijni.so": b"native-built",
            },
        )
        self.write_jar(
            self.embedded,
            {
                "native/linux-amd64/libobijni.so": b"native-embedded",
                "obi-java-agent-version.properties": b"version=1\n",
                "io/opentelemetry/obi/java/Agent.class": b"agent",
            },
            date_time=(2025, 1, 1, 0, 0, 0),
        )

        self.assertEqual([], check_jars(self.built, self.embedded))

    def test_added_class_is_reported(self):
        self.write_jar(
            self.built,
            {
                "io/opentelemetry/obi/java/Agent.class": b"agent",
                "io/opentelemetry/obi/java/New.class": b"new",
                "obi-java-agent-version.properties": b"version=1\n",
            },
        )
        self.write_jar(
            self.embedded,
            {
                "io/opentelemetry/obi/java/Agent.class": b"agent",
                "obi-java-agent-version.properties": b"version=1\n",
            },
        )

        self.assertEqual(
            ["missing from embedded JAR: io/opentelemetry/obi/java/New.class"],
            check_jars(self.built, self.embedded),
        )

    def test_removed_class_is_reported(self):
        self.write_jar(
            self.built,
            {
                "io/opentelemetry/obi/java/Agent.class": b"agent",
                "obi-java-agent-version.properties": b"version=1\n",
            },
        )
        self.write_jar(
            self.embedded,
            {
                "io/opentelemetry/obi/java/Agent.class": b"agent",
                "io/opentelemetry/obi/java/Old.class": b"old",
                "obi-java-agent-version.properties": b"version=1\n",
            },
        )

        self.assertEqual(
            ["unexpected in embedded JAR: io/opentelemetry/obi/java/Old.class"],
            check_jars(self.built, self.embedded),
        )

    def test_changed_class_and_resource_are_reported(self):
        self.write_jar(
            self.built,
            {
                "io/opentelemetry/obi/java/Agent.class": b"new",
                "obi-java-agent-version.properties": b"version=2\n",
            },
        )
        self.write_jar(
            self.embedded,
            {
                "io/opentelemetry/obi/java/Agent.class": b"old",
                "obi-java-agent-version.properties": b"version=1\n",
            },
        )

        self.assertEqual(
            [
                "content differs: io/opentelemetry/obi/java/Agent.class",
                "content differs: obi-java-agent-version.properties",
            ],
            check_jars(self.built, self.embedded),
        )

    def test_jars_without_project_classes_fail(self):
        self.write_jar(self.built, {"native/linux-amd64/libobijni.so": b"native"})
        self.write_jar(self.embedded, {"native/linux-amd64/libobijni.so": b"native"})

        self.assertEqual(
            [
                f"built JAR {self.built}: contains no project class files",
                f"embedded JAR {self.embedded}: contains no project class files",
            ],
            check_jars(self.built, self.embedded),
        )

    def test_jars_without_version_resource_fail(self):
        entries = {"io/opentelemetry/obi/java/Agent.class": b"agent"}
        self.write_jar(self.built, entries)
        self.write_jar(self.embedded, entries)

        self.assertEqual(
            [
                f"built JAR {self.built}: missing required project resource: obi-java-agent-version.properties",
                f"embedded JAR {self.embedded}: missing required project resource: obi-java-agent-version.properties",
            ],
            check_jars(self.built, self.embedded),
        )


if __name__ == "__main__":
    unittest.main()
