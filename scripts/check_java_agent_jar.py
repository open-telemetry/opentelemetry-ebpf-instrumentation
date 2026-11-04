#!/usr/bin/env python3
"""Check that the embedded Java agent contains the current project classes."""

import argparse
import sys
import zipfile


PROJECT_ENTRY_PREFIX = "io/opentelemetry/obi/java/"
PROJECT_RESOURCES = {"obi-java-agent-version.properties"}


def project_entries(jar_path):
    with zipfile.ZipFile(jar_path) as jar:
        entries = {
            name: jar.read(name)
            for name in jar.namelist()
            if (name.startswith(PROJECT_ENTRY_PREFIX) and name.endswith(".class"))
            or name in PROJECT_RESOURCES
        }

    class_entries = [name for name in entries if name.endswith(".class")]
    if not class_entries:
        raise ValueError(f"{jar_path}: contains no project class files")

    for resource in PROJECT_RESOURCES:
        if resource not in entries:
            raise ValueError(f"{jar_path}: missing required project resource: {resource}")

    return entries


def check_jars(built_jar, embedded_jar):
    differences = []
    jars = []
    for label, jar_path in (("built", built_jar), ("embedded", embedded_jar)):
        try:
            jars.append(project_entries(jar_path))
        except ValueError as error:
            differences.append(f"{label} JAR {error}")
    if differences:
        return differences

    built, embedded = jars

    for name in sorted(built.keys() - embedded.keys()):
        differences.append(f"missing from embedded JAR: {name}")
    for name in sorted(embedded.keys() - built.keys()):
        differences.append(f"unexpected in embedded JAR: {name}")
    for name in sorted(built.keys() & embedded.keys()):
        if built[name] != embedded[name]:
            differences.append(f"content differs: {name}")

    return differences


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("built_jar", help="JAR produced by the current Gradle build")
    parser.add_argument("embedded_jar", help="JAR checked into pkg/internal/java/embedded")
    args = parser.parse_args()

    try:
        differences = check_jars(args.built_jar, args.embedded_jar)
    except (OSError, zipfile.BadZipFile) as error:
        print(f"Unable to compare Java agent JARs: {error}", file=sys.stderr)
        return 1

    if differences:
        print("Embedded Java agent is stale; run `make java-build` to refresh it:", file=sys.stderr)
        for difference in differences:
            print(f"  {difference}", file=sys.stderr)
        return 1

    print("Embedded Java agent project classes are up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
