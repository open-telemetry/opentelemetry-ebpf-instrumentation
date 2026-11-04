# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Syft infers the main Go module version from linker flags and can truncate RC
# suffixes. The release tag is authoritative; keep dependency references aligned.
def obi_component:
  .name == "go.opentelemetry.io/obi";

def versioned_ref:
  "pkg:golang/go.opentelemetry.io/obi@" + ($version | @uri)
  + (if contains("?") then "?" + (split("?")[1:] | join("?")) else "" end);

([.components[] | select(obi_component)
  | {key: .["bom-ref"], value: (.["bom-ref"] | versioned_ref)}] | from_entries) as $refs
| .components |= map(
    if obi_component then
      .version = $version
      | .purl = ("pkg:golang/go.opentelemetry.io/obi@" + ($version | @uri))
      | .["bom-ref"] = $refs[.["bom-ref"]]
    else . end
  )
| .dependencies |= map(
    .ref = ($refs[.ref] // .ref)
    | .dependsOn |= map($refs[.] // .)
  )
