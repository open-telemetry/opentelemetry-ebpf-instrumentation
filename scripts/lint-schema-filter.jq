# Filters `weaver registry check` JSON diagnostics down to the ones that must
# fail `make lint-schema`, removing only the single expected finding:
#
# DuplicateMetricName for `dns.lookup.duration` between the upstream semconv
# dependency (under `.deps/`) and `schemas/obi/groups/dns.yaml`. That file
# deliberately re-declares the upstream metric (via `extends` under a distinct
# group id) to relax `dns.question.name` from required to opt_in — weaver has
# no first-class override mechanism between a registry and its dependencies
# yet, nor a CLI flag to suppress the duplicate check, while `registry
# live-check` resolves the duplicate in the local group's favor. Tracked in
# https://github.com/open-telemetry/weaver/issues/1578; when weaver defines
# override semantics this filter (and the comment in groups/dns.yaml) can be
# dropped.
#
# Any other diagnostic — including a DuplicateMetricName for a different
# metric, or for dns.lookup.duration with unexpected provenances — is kept and
# fails the lint. Covered by scripts/lint_schema_filter_test.go.
map(select(
  (
    (.error.DuplicateMetricName? // null) as $dup
    | $dup != null
      and $dup.metric_name == "dns.lookup.duration"
      and (($dup.provenances // []) | length) == 2
      and ([$dup.provenances[].path] | sort
           | (.[0] | startswith(".deps/"))
             and (.[1] | endswith("groups/dns.yaml")))
  ) | not
))
