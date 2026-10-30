# Filters `weaver registry check` JSON diagnostics down to the ones that must
# fail `make lint-schema`, removing only the expected findings below.
#
# 1. UnstableFileFormat we accept UnstableFileFormat for "definition/2" due to the migration process.
#
# 2. DeprecatedIncludeUnreferencedWarning: weaver 0.25 deprecated the
#    `--include-unreferenced` flag. OBI no longer relies on it — the emitted
#    metrics, spans, and resource entities now reference every override and
#    marker group, so nothing drops from resolution and live-check runs
#    without the flag. `--future` can still surface the deprecation notice, so
#    it is filtered defensively.
#
# Any other diagnostic — including a duplicate attribute or metric, which the
# definition/2 registry no longer produces for its overrides — is kept and fails
# the lint. Covered by scripts/lint_schema_filter_test.go.
map(select(
  (
    (
      (.error.FailToResolveDefinition? // null) as $fail
      | $fail != null
        and ($fail.UnstableFileFormat? // null) as $unstable
        | $unstable != null
          and $unstable.file_format == "definition/2"
    )
    or
    (
      (.error.DeprecatedIncludeUnreferencedWarning? // null) != null
    )
  ) | not
))
