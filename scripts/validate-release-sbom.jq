# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Check semantic content before checksumming and signing the release inventory.
def check($condition; $message):
  if $condition then . else error($message) end;

. as $archive
| $java_sbom[0] as $java
| INDEX(.components[]; .["bom-ref"]) as $components
| INDEX(($java.metadata.component, $java.components[]); .["bom-ref"]) as $java_components
| [.components[] | select(.name == "go.opentelemetry.io/obi")] as $obi
| check(.metadata.component.version == $version; "archive version does not match release tag")
| check(($obi | length) > 0; "OBI module is missing")
| check(all($obi[];
    .version == $version and .purl == ("pkg:golang/go.opentelemetry.io/obi@" + ($version | @uri)));
    "OBI module version does not match release tag")
| check($java.metadata.component.version == $version; "Java agent version does not match release tag")
| check(($java.components | length) > 0; "Java dependency inventory is empty")
| check(all(($java.metadata.component, $java.components[]);
    . as $expected
    | any($archive.components[]; .purl == $expected.purl and .version == $expected.version));
    "Java component is missing or has the wrong version")
| check(all(.components[] | select(.name == "obi-java-agent"); .version == $version);
    "Java agent version does not match release tag")
| check(all($java.dependencies[] | select((.dependsOn | length) > 0);
    . as $expected
    | [$expected.dependsOn[] | $java_components[.].purl] as $expected_purls
    | any($archive.dependencies[];
        $components[.ref].purl == $java_components[$expected.ref].purl
        and (($expected_purls - [.dependsOn[] | $components[.].purl]) | length) == 0));
    "Java dependency graph is incomplete")
| check((([.metadata.component["bom-ref"], .components[]["bom-ref"]] | length)
    == ([.metadata.component["bom-ref"], .components[]["bom-ref"]] | unique | length));
    "duplicate component references")
| check(all(.dependencies[];
    (.ref == $archive.metadata.component["bom-ref"] or $components[.ref] != null)
    and all(.dependsOn[]; . == $archive.metadata.component["bom-ref"] or $components[.] != null));
    "unresolved dependency reference")
| true
