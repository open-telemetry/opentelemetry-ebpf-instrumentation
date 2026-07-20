# Filters `weaver registry check` JSON diagnostics down to the ones that must
# fail `make lint-schema`, removing only the expected findings below. Weaver
# has no first-class override mechanism between a registry and its
# dependencies yet, nor a CLI flag to suppress the duplicate checks, while
# `registry live-check` resolves each duplicate in the local group's favor.
# Tracked in https://github.com/open-telemetry/weaver/issues/1578; when
# weaver defines override semantics this filter (and the override groups
# documented in schemas/obi/README.md) can be dropped.
#
# 1. DuplicateMetricName for `dns.lookup.duration` between the upstream
#    semconv dependency (under `.deps/`) and `schemas/obi/groups/dns.yaml`.
#    That file deliberately re-declares the upstream metric (via `extends`
#    under a distinct group id) to relax `dns.question.name` from required to
#    opt_in.
#
# 2. DuplicateAttributeId for the attribute overrides in
#    `schemas/obi/groups/` (see schemas/obi/README.md): each re-declares an
#    upstream attribute (from group `registry.<ns>`, under the distinct group
#    id `x.obi.<ns>`) — either an enum extended with the values OBI
#    intentionally emits, or an open-ended enum re-typed as string.
#
# Any other diagnostic — including duplicates for other metrics/attributes,
# or the expected ones with unexpected provenances/groups — is kept and fails
# the lint. Covered by scripts/lint_schema_filter_test.go.
map(select(
  (
    (
      (.error.DuplicateMetricName? // null) as $dup
      | $dup != null
        and $dup.metric_name == "dns.lookup.duration"
        and (($dup.provenances // []) | length) == 2
        and ([$dup.provenances[].path] | sort
             | (.[0] | startswith(".deps/"))
               and (.[1] | endswith("groups/dns.yaml")))
    )
    or
    (
      (.error.DuplicateAttributeId? // null) as $dup
      | $dup != null
        and ($dup.attribute_id
             | IN("messaging.system", "gen_ai.provider.name", "gen_ai.operation.name",
                  "openai.api.type", "telemetry.sdk.language", "db.system.name",
                  "rpc.system.name", "error.type"))
        and ((($dup.group_ids // []) | sort) as $groups
             | ($groups | length) == 2
               and ($groups[0] | startswith("registry."))
               and $groups[1] == ("x.obi." + ($groups[0] | ltrimstr("registry."))))
    )
  ) | not
))
