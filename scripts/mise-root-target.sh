#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

target="${1:?usage: mise-root-target.sh TARGET}"
tools_modfile='-modfile=internal/tools/go.mod'
cmd="${CMD:-obi}"
main_go_file="${MAIN_GO_FILE:-cmd/${cmd}/main.go}"
buildinfo_pkg="${BUILDINFO_PKG:-go.opentelemetry.io/obi/pkg/buildinfo}"
release_version="${RELEASE_VERSION:-$(git describe --all | cut -d/ -f2-)}"
release_revision="${RELEASE_REVISION:-$(git rev-parse --short HEAD)}"
test_output="${TEST_OUTPUT:-./testoutput}"
release_dir="${RELEASE_DIR:-./dist}"
goos="${GOOS:-linux}"
goarch="${GOARCH:-$(go env GOARCH || echo amd64)}"
java_agent='pkg/internal/java'
java_agent_name="${JAVA_AGENT:-obi-java-agent.jar}"
java_agent_embed="${java_agent}/embedded/${java_agent_name}"

run_bpf() { python3 ./scripts/mise-bpf-generate.py "$@"; }
run_coverage_clean() {
  grep -vE '(_bpfel.go)|(.pb.go)|$|(/cmd/generate-port-lookup/)|$|(/cmd/obi-schema/)|$|(/obi/configs/)|$|(/obi/examples/)|$|(/obi/internal/test/)|$|(/obi/scripts/)|$|(/pkg/export/otel/metric/)' \
    "${test_output}/cover.all.txt" > "${test_output}/cover.txt"
}
java_gradle() {
  local version java_home
  version="$(tr -d '[:space:]' < "${java_agent}/.java-version")"
  java_home="${JAVA_AGENT_JAVA_HOME:-}"
  if [[ -z "$java_home" ]]; then
    for candidate in "/usr/lib/jvm/java-${version}-openjdk" "/usr/lib/jvm/java-${version}-openjdk-amd64"; do
      if [[ -d "$candidate" ]]; then java_home="$candidate"; break; fi
    done
  fi
  if [[ -n "$java_home" ]]; then
    (cd "$java_agent" && JAVA_HOME="$java_home" PATH="$java_home/bin:$PATH" gradle "$@")
  else
    (cd "$java_agent" && gradle "$@")
  fi
}

case "$target" in
  install-hooks)
    if [[ ! -f .git/hooks/pre-commit ]]; then
      echo 'Installing pre-commit hook...'
      cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
      echo 'Pre-commit hook installed.'
    fi
    ;;
  prereqs) mise run install-hooks; mise run fetch-upstream-semconv; mkdir -p "${test_output}/run" ;;
  fetch-upstream-semconv) ./scripts/fetch-upstream-semconv.sh ;;
  fmt) echo '### Formatting code and fixing imports'; golangci-lint fmt ;;
  clang-tidy)
    (cd bpf && find . -type f \( -name '*.c' -o -name '*.h' \) ! -path './bpfcore/*' ! -path './NOTICES/*' ! -path './tests/*' -print0 | xargs -0 -r "${CLANG_TIDY:-clang-tidy}")
    ;;
  docker-clang-tidy) mise run clang-tidy ;;
  lint-clean-cache) golangci-lint cache clean ;;
  lint|lint-run)
    mise run vanity-import-check
    mise run lint-dependency-policy
    mise run lint-collectt
    mise run lint-preempt-guard
    echo '### Linting code'
    golangci-lint run ./... --timeout=6m
    ;;
  lint-fix|lint-fix-run)
    mise run vanity-import-fix-check
    mise run lint-dependency-policy
    mise run lint-collectt-fix
    mise run lint-preempt-guard
    echo '### Linting code'
    golangci-lint run ./... --timeout=6m --fix
    ;;
  lint-schema) mise run fetch-upstream-semconv; ./scripts/lint-schema.sh "$PWD/schemas/obi" ;;
  test-schema) mise run fetch-upstream-semconv; go test -race -count=1 ./internal/schemacheck/... ;;
  check-schema-files) ./scripts/check-schema-files.sh "$PWD/site/schemas/obi" ;;
  generate-schema-next) ./scripts/generate-schema-next.sh ;;
  generate-schema-docs) mise run fetch-upstream-semconv; ./scripts/generate-schema-docs.sh "$PWD/schemas/obi" ;;
  check-schema-docs)
    mise run fetch-upstream-semconv
    ./scripts/generate-schema-docs.sh "$PWD/schemas/obi"
    if [[ -n "$(git status --porcelain -- site/docs)" ]]; then
      echo "site/docs is stale: run 'mise run generate-schema-docs' and commit the result" >&2
      git --no-pager diff -- site/docs
      exit 1
    fi
    ;;
  lint-dependency-policy)
    echo '### Linting dependency integrity policy'
    if [[ -n "${CI:-}" ]]; then ./scripts/lint-dependency-policy.sh --verbose; else ./scripts/lint-dependency-policy.sh; fi
    ;;
  lint-preempt-guard) ./scripts/lint-preempt-guard.sh ;;
  lint-collectt) go run ./internal/test/analyzer/collectt/cmd/collecttlint ./... ;;
  lint-collectt-fix)
    go run ./internal/test/analyzer/collectt/cmd/collecttlint -fix ./...
    go run ./internal/test/analyzer/collectt/cmd/collecttlint ./...
    ;;
  lint-markdown) markdownlint-cli2 --config .markdownlint-cli2.yaml '**/*.md' ;;
  lint-markdown-fix) markdownlint-cli2 --config .markdownlint-cli2.yaml --fix '**/*.md' ;;
  update-offsets) go run ./internal/gooffsets -i configs/offsets/tracker_input.json -abi configs/offsets/go_abi_input.json pkg/internal/goexec/offsets.json ;;
  update-python-offsets) go run ./scripts/python-offsets ;;
  generate) run_bpf ;;
  generate-all) run_bpf --all ;;
  docker-generate) run_bpf ;;
  compile|debug|compile-for-coverage|compile-cache|compile-cache-for-coverage)
    local_cmd="$cmd"; local_main="$main_go_file"; extra=()
    case "$target" in
      compile-cache|compile-cache-for-coverage) local_cmd="${CACHE_CMD:-k8s-cache}"; local_main="${CACHE_MAIN_GO_FILE:-cmd/${local_cmd}/main.go}" ;;
      debug) extra=(-gcflags '-N -l') ;;
      compile-for-coverage|compile-cache-for-coverage) extra=(-cover) ;;
    esac
    ldflags="-X '${buildinfo_pkg}.Version=${release_version}' -X '${buildinfo_pkg}.Revision=${release_revision}'"
    mkdir -p bin
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build "${extra[@]}" -ldflags="$ldflags" -o "bin/${local_cmd}" "$local_main"
    ;;
  test|testoutput) mkdir -p "$test_output"; if [[ "$target" == test ]]; then KUBEBUILDER_ASSETS="$(go tool "$tools_modfile" setup-envtest use "${ENVTEST_K8S_VERSION:-1.30.0}" -p path)" go test -short -race ./... -coverpkg=./... -coverprofile "${test_output}/cover.all.txt"; fi ;;
  test-nodejs) (cd pkg/internal/nodejs/spanbridge_test && npm ci && node --test) ;;
  test-rerun-flaky) ./scripts/rerun-flaky_test.sh ;;
  test-privileged)
    mkdir -p "$test_output"
    assets="$(go tool "$tools_modfile" setup-envtest use "${ENVTEST_K8S_VERSION:-1.30.0}" -p path)"
    packages="$(grep -rl '//go:build.*privileged_tests' . --include='*.go' | xargs -r -I{} dirname {} | sort -u | tr '\n' ' ')"
    KUBEBUILDER_ASSETS="$assets" go test -short -race -tags=privileged_tests $packages -coverpkg=./... -coverprofile "${test_output}/cover.all.txt"
    ;;
  run-bpf-verifier-vm) go test -count=1 -timeout 55m -parallel 8 -tags=bpf_verifier_tests ./pkg/internal/ebpf/verifier/... ;;
  cov-exclude-generated) mkdir -p "$test_output"; run_coverage_clean ;;
  coverage-report) run_coverage_clean; go tool cover --func="${test_output}/cover.txt" ;;
  coverage-report-html) run_coverage_clean; go tool cover --html="${test_output}/cover.txt" ;;
  java-build)
    echo '### Building Java agent'; java_gradle build; mkdir -p "${java_agent}/embedded"; cp "${java_agent}/build/${java_agent_name}" "$java_agent_embed"
    ;;
  java-docker-build)
    mkdir -p "${java_agent}/embedded"
    "$oci_bin" build --output "type=local,dest=${java_agent}/embedded" --target=export -f javaagent.Dockerfile .
    ;;
  java-docker-sbom)
    mkdir -p "$release_dir"
    (cd "$java_agent" && HOME=/tmp GRADLE_USER_HOME=/tmp/.gradle OBI_JAVA_AGENT_SBOM_VERSION="$release_version" gradle :agent:cyclonedxDirectBom --no-daemon)
    cp pkg/internal/java/agent/build/reports/cyclonedx-direct/bom.json "$release_dir/obi-java-agent-${release_version}.cyclonedx.json"
    ;;
  java-test) java_gradle test -PnativeOnly=true ;;
  java-spotless-check) java_gradle spotlessCheck -PnativeOnly=true ;;
  java-spotless-apply) java_gradle spotlessApply -PnativeOnly=true ;;
  java-clean) java_gradle clean ;;
  java-verify) mise run java-spotless-check; mise run java-test; mise run java-build ;;
  image-build)
    [[ -n "${IMG_ORG:-}" ]] || { echo 'IMG_ORG must be set (Docker repository user name)' >&2; exit 1; }
    "$oci_bin" buildx build --load -t "${IMG:-${IMG_REGISTRY:-docker.io}/${IMG_ORG}/${IMG_NAME:-ebpf-instrument}:${VERSION:-dev}}" --build-arg "RELEASE_VERSION=$release_version" --build-arg "RELEASE_REVISION=$release_revision" .
    ;;
  generator-image-build) "$oci_bin" buildx build --load -t "$gen_img" -f generator.Dockerfile . ;;
  prepare-integration-test)
    mkdir -p "$test_output"; rm -rf "$test_output"/* || true
    mise run cleanup-integration-test
    ;;
  cleanup-integration-test)
    go tool "$tools_modfile" kind delete cluster -n test-kind-cluster || true
    containers="$("$oci_bin" ps --format '{{.Names}}' | grep 'integration-' || true)"
    if [[ -n "$containers" ]]; then "$oci_bin" rm -f $containers; else echo 'No integration test containers to remove'; fi
    images="$("$oci_bin" images --format '{{.Repository}}:{{.Tag}}' | grep 'hatest-' || true)"
    if [[ -n "$images" ]]; then "$oci_bin" rmi -f $images; else echo 'No integration test images to remove'; fi
    ;;
  run-integration-test|run-integration-test-k8s)
    go clean -testcache
    test_path=./internal/test/integration
    [[ "$target" != run-integration-test-k8s ]] || test_path=./internal/test/integration/k8s/...
    go test -p 1 -failfast -v -timeout 60m "$test_path"
    ;;
  run-integration-test-vm)
    export TEST_TIMEOUT=60m TEST_PARALLEL=1
    pattern="${TEST_PATTERN:-.*}"
    if [[ -f "${PRECOMPILED_TESTS_DIR:-/precompiled-tests}/integration.test" && -f "${PRECOMPILED_TESTS_DIR:-/precompiled-tests}/gotestsum" ]]; then
      dir="${PRECOMPILED_TESTS_DIR:-/precompiled-tests}"
      chmod +x "$dir/integration.test" "$dir/gotestsum"
      "$dir/gotestsum" --rerun-fails=2 --rerun-fails-max-failures=2 --raw-command -ftestname --jsonfile="testoutput/vm-test-run-${RUN_NUMBER:-}.log" -- go tool test2json -t -p integration "$dir/integration.test" -test.parallel=1 -test.timeout="$TEST_TIMEOUT" -test.v -test.run="^(${pattern})$"
    elif [[ -f "${PRECOMPILED_TESTS_DIR:-/precompiled-tests}/integration.test" ]]; then
      dir="${PRECOMPILED_TESTS_DIR:-/precompiled-tests}"; chmod +x "$dir/integration.test"
      "$dir/integration.test" -test.parallel=1 -test.timeout="$TEST_TIMEOUT" -test.v -test.run="^(${pattern})$"
    else
      go tool "$tools_modfile" gotestsum --rerun-fails=2 --rerun-fails-max-failures=2 -ftestname --jsonfile="testoutput/vm-test-run-${RUN_NUMBER:-}.log" -- -p 1 -timeout "$TEST_TIMEOUT" -v -run="^(${pattern})$" ./internal/test/integration
    fi
    ;;
  unit-test-matrix-json) go list ./... | go tool "$tools_modfile" gotestsum tool ci-matrix --partitions "${PARTITIONS:-3}" --timing-files="${test_output}/unit-test-shard-*.log" ;;
  run-unit-test-shard)
    assets="$(go tool "$tools_modfile" setup-envtest use "${ENVTEST_K8S_VERSION:-1.30.0}" -p path)"
    KUBEBUILDER_ASSETS="$assets" go tool "$tools_modfile" gotestsum --jsonfile="${test_output}/unit-test-shard-${SHARD_ID:?SHARD_ID must be set}.log" -- -short -race -coverpkg=./... -coverprofile "${test_output}/cover.all.txt" ${UNIT_TEST_PACKAGES:-}
    ;;
  integration-test-matrix-json) ./scripts/generate-integration-matrix.sh internal/test/integration "${PARTITIONS:-5}" ;;
  multiprocess-integration-test-matrix-json) ./scripts/generate-integration-matrix.sh internal/test/integration "${PARTITIONS:-5}" '(TestMultiProcess|TestSuite_LogEnricherHTTP|TestSuite_LargeHTTPRequest)' ;;
  k8s-integration-test-matrix-json) ./scripts/generate-dir-matrix.sh internal/test/integration/k8s common ;;
  oats-integration-test-matrix-json) ./scripts/generate-dir-matrix.sh internal/test/oats ;;
  integration-test|integration-test-k8s)
    mise run prereqs
    mise run prepare-integration-test
    test_target=run-integration-test; [[ "$target" != integration-test-k8s ]] || test_target=run-integration-test-k8s
    if ! mise run "$test_target"; then mise run cleanup-integration-test; exit 1; fi
    mise run itest-coverage-data
    mise run cleanup-integration-test
    ;;
  itest-coverage-data)
    mkdir -p "${test_output}/merge"
    go tool covdata merge -i="$test_output" -o="$test_output/merge"
    go tool covdata textfmt -i="$test_output/merge" -o="$test_output/itest-covdata.raw.txt"
    sed 's|^/src/cmd/|go.opentelemetry.io/obi/cmd/|' "$test_output/itest-covdata.raw.txt" > "$test_output/itest-covdata.all.txt"
    grep -vE '(_bpfel.go)|(.pb.go)|$|(/cmd/generate-port-lookup/)|$|(/cmd/obi-schema/)|$|(/obi/configs/)|$|(/obi/examples/)|$|(/obi/internal/test/)|$|(/obi/scripts/)|$|(/pkg/export/otel/metric/)' "$test_output/itest-covdata.all.txt" > "$test_output/itest-covdata.txt" || true
    ;;
  oats-prereq) mise run docker-generate; mise run fetch-upstream-semconv; mkdir -p "$test_output/run" ;;
  oats-test-*)
    component="${target#oats-test-}"
    dir="internal/test/oats/${component}"
    mkdir -p "$dir/$test_output/run"
    (cd "$dir" && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml go tool "$tools_modfile" ginkgo -v -r)
    ;;
  oats-test) for component in sql mongo redis kafka http memcached ai nats amqp; do mise run oats-prereq; mise run "oats-test-${component}"; done; mise run itest-coverage-data ;;
  oats-test-debug) (cd internal/test/oats/kafka && TESTCASE_BASE_PATH=./yaml TESTCASE_MANUAL_DEBUG=true TESTCASE_TIMEOUT=1h go tool "$tools_modfile" ginkgo -v -r) ;;
  license-header-check)
    bad="$(find . -type f \( -iname '*.go' -o -iname '*.sh' -o -iname '*.c' -o -iname '*.h' \) ! -path './.git/*' ! -path './.tmp/*' ! -path './NOTICES/*' ! -path './examples/store-demo/app/*' -print0 | xargs -0 awk '/Copyright The OpenTelemetry Authors|generated|GENERATED/ && NR<=4 { found=1; next } END { if (!found) print FILENAME }')"
    if [[ -n "$bad" ]]; then echo 'license header checking failed:'; echo "$bad"; exit 1; fi
    ;;
  artifact)
    mise run docker-generate; mise run java-docker-build; mise run compile
    staging="$(mktemp -d)"; trap 'rm -rf "$staging"' EXIT
    cp "bin/$cmd" "$staging/"; cp LICENSE NOTICE "$staging/"
    mkdir -p "$staging/NOTICES"
    [[ ! -d NOTICES/bpf ]] || cp -R NOTICES/bpf "$staging/NOTICES/"
    [[ ! -d NOTICES/java ]] || cp -R NOTICES/java "$staging/NOTICES/"
    [[ -d "NOTICES/$goarch" ]] || { echo "ERROR: NOTICES/$goarch missing; run 'mise run go-notices-update'" >&2; exit 1; }
    cp -R "NOTICES/$goarch/." "$staging/NOTICES/"
    tar -C "$staging" -czf "bin/obi-${release_version}-${goos}-${goarch}.tar.gz" "$cmd" LICENSE NOTICE NOTICES
    ;;
  release)
    mise run artifact
    mkdir -p "$release_dir" "$release_dir/verify-$goarch"
    archive="bin/obi-${release_version}-${goos}-${goarch}.tar.gz"
    mv "$archive" "$release_dir/"
    tar -xzf "$release_dir/$(basename "$archive")" -C "$release_dir/verify-$goarch"
    for required in "$cmd" LICENSE NOTICE; do [[ -f "$release_dir/verify-$goarch/$required" ]] || { echo "ERROR: $required missing in archive"; exit 1; }; done
    [[ -d "$release_dir/verify-$goarch/NOTICES" ]] || { echo 'ERROR: NOTICES directory missing in archive'; exit 1; }
    for other in amd64 arm64; do [[ "$other" == "$goarch" || ! -d "$release_dir/verify-$goarch/NOTICES/$other" ]] || { echo "ERROR: NOTICES/$other leaked into archive"; exit 1; }; done
    [[ -x "$release_dir/verify-$goarch/$cmd" ]] || { echo "ERROR: $cmd binary not executable in archive"; exit 1; }
    rm -rf "$release_dir/verify-$goarch"
    mise run release-checksums
    ls -lh "$release_dir/"
    ;;
  release-source)
    mise run docker-generate; mise run java-docker-build
    source_version="${RELEASE_SOURCE_VERSION:-$(git describe --tags --exact-match 2>/dev/null || git symbolic-ref --short -q HEAD || echo main)}"
    ./scripts/release-source.sh --release-version "$source_version" --release-dir "$release_dir"
    RELEASE_VERSION="$source_version" mise run release-checksums
    ;;
  release-checksums)
    mkdir -p "$release_dir"
    (cd "$release_dir"
      files="$(find . -maxdepth 1 \( -name "obi-${release_version}-*.tar.gz" -o -name "obi-${release_version}-*.cyclonedx.json" -o -name "obi-java-agent-${release_version}.cyclonedx.json" \) | sed 's|^\./||' | sort)"
      [[ -n "$files" ]] || { echo "ERROR: No release artifacts found for obi-${release_version} in $release_dir"; exit 1; }
      if command -v sha256sum >/dev/null 2>&1; then printf '%s\n' "$files" | xargs sha256sum > SHA256SUMS
      elif command -v shasum >/dev/null 2>&1; then printf '%s\n' "$files" | xargs shasum -a 256 > SHA256SUMS
      else echo 'ERROR: Neither sha256sum nor shasum found.'; exit 1; fi)
    ;;
  clean-release-dir) rm -rf "$release_dir/"; rm -f bin/obi-*.tar.gz; rm -rf bin/LICENSE bin/NOTICE bin/NOTICES ;;
  java-notices-update)
    mkdir -p "${NOTICES_DIR:-./NOTICES}/java/agent"
    java_gradle :agent:generateLicenseReport --no-daemon
    awk '{ if ($0 ~ /^This report was generated at /) print "This report was generated at <normalized>."; else print }' "$java_agent/agent/build/reports/dependency-license/THIRD_PARTY_LICENSES.txt" > "${NOTICES_DIR:-./NOTICES}/java/agent/THIRD_PARTY_LICENSES.txt"
    cp "$java_agent/agent/build/reports/dependency-license/THIRD_PARTY_LICENSES.csv" "${NOTICES_DIR:-./NOTICES}/java/agent/"
    ;;
  go-notices-update)
    notices="${NOTICES_DIR:-./NOTICES}"
    find "$notices" -mindepth 1 -maxdepth 1 ! -name bpf ! -name java ! -name amd64 ! -name arm64 -exec rm -rf {} +
    for arch in amd64 arm64; do
      rm -rf "$notices/$arch"
      GOOS=linux GOARCH="$arch" go tool "$tools_modfile" github.com/google/go-licenses/v2 save ./... --save_path="/tmp/notices-$arch" --force
      mv "/tmp/notices-$arch" "$notices/$arch"
    done
    ;;
  notices-update)
    mise run docker-generate; mise run go-notices-update; mise run java-notices-update
    notices="${NOTICES_DIR:-./NOTICES}"
    while IFS= read -r -d '' file; do dest="$notices/${file#./}"; mkdir -p "$(dirname "$dest")"; cp "$file" "$dest"; done < <(find ./bpf -type f -name 'LICENSE*' -print0)
    while IFS= read -r -d '' file; do dest="$notices/${file#./}"; mkdir -p "$(dirname "$dest")"; cp "$file" "$dest"; done < <(find ./bpf/bpfcore -type f -print0)
    ;;
  python-requirements-update)
    while IFS= read -r -d '' file; do
      file_dir="$(dirname "$file")"; file_name="$(basename "$file")"
      command="$(sed -n 's/^#    //p' "$file" | head -n 1)"
      python_version="$(sed -n '2s/^# This file is autogenerated by pip-compile with Python //p' "$file")"
      if [[ -z "$python_version" ]]; then case "$file_name" in requirements-3.9.txt) python_version=3.9;; requirements-3.14.txt|requirements.txt) python_version=3.14;; *) echo "Unable to determine Python version for $file"; exit 1;; esac; fi
      [[ -n "$command" ]] || continue
      flags=(--generate-hashes); [[ "$command" != *--allow-unsafe* ]] || flags+=(--allow-unsafe)
      if [[ "$command" == *--no-strip-extras* ]]; then flags+=(--no-strip-extras); else flags+=(--strip-extras); fi
      python="${python_version}"; (cd "$file_dir" && uv python pin "$python" >/dev/null 2>&1 || true; uv pip compile --quiet "${flags[@]}" -o "$file_name" requirements.in)
    done < <(find internal/test/integration/components -type f \( -name 'requirements.txt' -o -name 'requirements-*.txt' \) -print0 2>/dev/null)
    ;;
  go-mod-tidy)
    while IFS= read -r file; do dir="$(dirname "$file")"; echo "### Running go mod tidy in $dir"; if [[ "$dir" == *testserver_1.17 ]]; then (cd "$dir" && go mod tidy -go=1.17 -compat=1.17); else (cd "$dir" && go mod tidy); fi; done < <(find . -type f -name go.mod ! -path './NOTICES/*' | sort)
    ;;
  check-go-mod)
    mise run go-mod-tidy
    if ! git diff --quiet -- ':(glob)**/go.mod' ':(glob)**/go.sum' ':(exclude,glob)NOTICES/**'; then echo 'go.mod/go.sum files are not clean, did you forget to run "mise run go-mod-tidy"?' >&2; git --no-pager diff -- ':(glob)**/go.mod' ':(glob)**/go.sum' ':(exclude,glob)NOTICES/**'; exit 1; fi
    ;;
  verify-mods) go tool "$tools_modfile" multimod verify ;;
  verify)
    mise run prereqs
    mise run go-mod-tidy
    mise run lint
    mise run test
    mise run license-header-check
    ;;
  build)
    mise run docker-generate
    mise run verify
    mise run compile
    ;;
  all)
    mise run docker-generate
    mise run notices-update
    mise run build
    ;;
  dev)
    mise run prereqs
    mise run generate
    mise run compile-for-coverage
    ;;
  prerelease)
    go tool "$tools_modfile" multimod verify
    [[ -n "${MODSET:-}" ]] || { echo '>> env var MODSET is not set'; exit 1; }
    mise run generate-schema-next; mise run generate-schema-docs
    go tool "$tools_modfile" multimod prerelease -m "$MODSET"
    ;;
  add-tags)
    go tool "$tools_modfile" multimod verify
    [[ -n "${MODSET:-}" ]] || { echo '>> env var MODSET is not set'; exit 1; }
    go tool "$tools_modfile" multimod tag -m "$MODSET" -c "${COMMIT:-HEAD}"
    ;;
  check-ebpf-ver-synced)
    version="${CILIUM_EBPF_VER:-v0.22.0}"
    if grep -Fq "github.com/cilium/ebpf $version" go.mod && grep -Fq "github.com/cilium/ebpf $version" bpf/bpfcore/placeholder.go; then echo 'ebpf lib version in sync'; else echo 'ebpf lib version out of sync between go.mod and bpf/bpfcore/placeholder.go!' >&2; exit 1; fi
    ;;
  vanity-import-check) go tool "$tools_modfile" porto --include-internal --skip-dirs '^NOTICES$' -l . || { echo '(run: mise run vanity-import-fix)' >&2; exit 1; } ;;
  vanity-import-fix-check) mise run vanity-import-fix; go tool "$tools_modfile" porto --include-internal --skip-dirs '^NOTICES$' -l . ;;
  vanity-import-fix) go tool "$tools_modfile" porto --include-internal --skip-dirs '^NOTICES$' -w . ;;
  regenerate-port-lookup) go run cmd/generate-port-lookup/main.go -dst pkg/internal/netolly/flow/transport/protocol.go; mise run fmt ;;
  generate-config-schema)
    schema="${CONFIG_SCHEMA_FILE:-devdocs/config/config-schema.json}"; docs="${CONFIG_DOCS_FILE:-devdocs/config/CONFIG.md}"
    mkdir -p "$(dirname "$schema")"; go run ./cmd/obi-schema -output "$schema"; go run ./cmd/config-docs -schema "$schema" -output "$docs"
    ;;
  check-config-schema)
    schema="${CONFIG_SCHEMA_FILE:-devdocs/config/config-schema.json}"; docs="${CONFIG_DOCS_FILE:-devdocs/config/CONFIG.md}"
    mkdir -p "$(dirname "$schema")"; go run ./cmd/obi-schema -output "${schema}.tmp"
    if ! diff -q "$schema" "${schema}.tmp" >/dev/null 2>&1; then echo "JSON schema is out of date. Run 'mise run generate-config-schema' to update it."; diff "$schema" "${schema}.tmp" || true; rm -f "${schema}.tmp"; exit 1; fi
    rm -f "${schema}.tmp"; go run ./cmd/config-docs -schema "$schema" -output "${docs}.tmp"
    if ! diff -q "$docs" "${docs}.tmp" >/dev/null 2>&1; then echo "Configuration docs are out of date. Run 'mise run generate-config-schema' to update."; diff "$docs" "${docs}.tmp" || true; rm -f "${docs}.tmp"; exit 1; fi
    rm -f "${docs}.tmp"
    ;;
  check-config-v2-parity) go run ./cmd/check-config-v2-parity -v2-default "${CONFIG_V2_DEFAULT_REFERENCE_FILE:-devdocs/config/version-2.0/examples/default-values-reference.fragment.yaml}" ;;
  check-config-v2-artifacts)
    mise run check-config-v2-parity
    dir="${CONFIG_V2_DIR:-devdocs/config/version-2.0}"
    go run ./cmd/check-config-v2-artifacts -schema "${CONFIG_V2_SCHEMA_FILE:-$dir/obi-extension.schema.json}" -default-reference "${CONFIG_V2_DEFAULT_REFERENCE_FILE:-$dir/examples/default-values-reference.fragment.yaml}" -runnable-example "${CONFIG_V2_RUNNABLE_EXAMPLE_FILE:-$dir/examples/default-configuration.yaml}"
    ;;
  fix-store-demo-architecture) python3 examples/store-demo/fix_architecture.py ;;
  check-store-demo-architecture) python3 examples/store-demo/fix_architecture.py --check ;;
  test-store-demo-architecture) python3 examples/store-demo/test_fix_architecture.py ;;
  check-clean-work-tree)
    if [[ -n "$(git status --porcelain)" ]]; then git status; git --no-pager diff; echo "Working tree is not clean, did you forget to run 'mise run'?"; exit 1; fi
    ;;
  testoutput) mkdir -p "$test_output" ;;
  clean-testoutput) mkdir -p "$test_output"; echo "### Cleaning ${test_output} folder"; rm -rf "${test_output}"/* ;;
  protoc-gen) "$oci_bin" run --rm -v "$PWD:/src" -w /src --entrypoint protoc "$gen_img" --go_out=pkg/kube/kubecache --go-grpc_out=pkg/kube/kubecache proto/informer.proto ;;
  clang-format)
    find ./bpf -type f \( -name '*.c' -o -name '*.h' \) ! -path './bpf/bpfcore/*' -print0 | xargs -0 -r -P 0 "${CLANG_FORMAT:-clang-format}" -i
    ;;
  docker-clang-format)
    mapfile -d '' files < <(find ./bpf -type f \( -name '*.c' -o -name '*.h' \) ! -path './bpf/bpfcore/*' -print0)
    "$oci_bin" run --rm "${container_user_args[@]}" -v "$PWD:/src:z" -w /src --entrypoint /usr/lib/llvm22/bin/clang-format "$gen_img" -i "${files[@]}"
    ;;
  clean-ebpf-generated-files) find . -name '*_bpfel*' -print0 | xargs -0 -r rm ;;
  *) echo "Unknown root task: $target" >&2; exit 2 ;;
esac
