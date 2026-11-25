# OATS test matrix

`oats-matrix` builds the JSON matrix used by the OATS integration-test
workflow. It splits selected suites into two shards while keeping cases that
need the same fixture together, so each shard can run independently.

## How sharding works

The command reads each suite's `oats-config.yaml` and the case YAML files
matched by its `cases` patterns. Cases are grouped by their `fixture` value;
fixture mappings are compared independent of key order. Cases without an
explicit fixture share OATS's implicit fixture. Relative fixture paths are
scoped to the case directory, so equal relative paths in different directories
are not treated as the same fixture.

The `ai`, `http`, `kafka`, and `sql` suites are split into two shards when they
have more than one distinct fixture group. Whole groups are assigned
deterministically, largest first, to the shard with the fewest cases so far.
Other suites, and suites with only one group, remain a single shard. Each case
appears once in the resulting matrix.

## Run it

From the repository root, generate the workflow matrix with:

```sh
make oats-integration-test-matrix-json
```

This invokes `go run ./scripts/oats-matrix --suite-root internal/test/oats`.
To use another suite root, pass it with `--suite-root` or as the sole
positional argument:

```sh
go run ./scripts/oats-matrix --suite-root /path/to/oats
go run ./scripts/oats-matrix /path/to/oats
```

The default suite root is `internal/test/oats`. The command writes JSON to
standard output in the shape below; `id` is a zero-based matrix-row index,
`basename` identifies the shard, and `cases` contains case-file basenames.

```json
{
  "include": [
    {
      "id": 0,
      "suite": "http",
      "basename": "http-1",
      "cases": ["oats_example.yaml"]
    }
  ]
}
```

The OATS GitHub Actions workflow consumes this `include` list, sets
`MATRIX_SUITE` and `OATS_CASES` from each row, and runs the corresponding
`make oats-test-<suite>` target. To test the generator locally, run:

```sh
go test ./scripts/oats-matrix
```

## Why Go?

Go is the repository's primary implementation language, and Go commands are
already used for repository tooling—for example, `scripts/python-offsets`,
`scripts/ci-analysis`, and `scripts/run-integration-shard`. Using Go here lets
the generator use the repository's Go YAML dependency to parse OATS case files
and makes its grouping and deterministic output behavior directly testable
with `go test`. The repository also uses shell scripts for simpler tasks; this
tool is Go because it parses structured YAML and produces a tested JSON matrix.
