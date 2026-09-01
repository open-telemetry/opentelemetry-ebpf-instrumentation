#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Verifies a (draft) release's artifacts as described in RELEASING.md:
# checksums, Cosign signatures for every archive/SBOM/checksum file, archive
# contents, and the container image signatures on Docker Hub and GHCR.
set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

PROGNAME="$(basename "$0")"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    green=$'\033[32m'
    red=$'\033[31m'
    reset=$'\033[0m'
else
    green=""
    red=""
    reset=""
fi

step() {
    echo
    echo "=== $* ==="
}

ok() { echo "${green}$*${reset}"; }
err() { echo "${red}$*${reset}" >&2; }

# highlight per-line verification verdicts from external tools
colorize_status() {
    sed -e "s/Verified OK/${green}Verified OK${reset}/" \
        -e "s/OK\$/${green}OK${reset}/" \
        -e "s/FAILED/${red}FAILED${reset}/"
}

usage() {
    echo "usage: ${PROGNAME} <tag>" >&2
    echo "  e.g. ${PROGNAME} v0.12.2" >&2
    exit 2
}

[ $# -eq 1 ] || usage
release_tag="$1"
case "${release_tag}" in
v[0-9]*.[0-9]*.[0-9]*) ;;
*)
    err "FATAL: tag must look like vX.Y.Z or vX.Y.Z-suffix, got '${release_tag}'"
    exit 2
    ;;
esac

repository=open-telemetry/opentelemetry-ebpf-instrumentation
release_identity="https://github.com/${repository}/.github/workflows/release.yml@refs/tags/${release_tag}"
image_identity="https://github.com/${repository}/.github/workflows/publish_dockerhub_main.yml@refs/tags/${release_tag}"
oidc_issuer='https://token.actions.githubusercontent.com'

for tool in gh cosign tar; do
    command -v "${tool}" >/dev/null || {
        err "FATAL: missing required tool: ${tool}"
        exit 1
    }
done

# GNU coreutils (Linux) ships sha256sum; macOS and the BSDs ship shasum
if command -v sha256sum >/dev/null; then
    sha_check() { sha256sum -c --ignore-missing SHA256SUMS; }
elif command -v shasum >/dev/null; then
    sha_check() { shasum -a 256 -c --ignore-missing SHA256SUMS; }
else
    err "FATAL: neither sha256sum nor shasum is available"
    exit 1
fi

release_dir="$(mktemp -d)"

# keep the artifacts for inspection when verification fails, clean up on success
keep_artifacts=1
cleanup() {
    if [ "${keep_artifacts}" -eq 1 ]; then
        echo
        echo "artifacts left in ${release_dir} for inspection (remove when done)"
    else
        rm -rf "${release_dir}"
    fi
}
trap cleanup EXIT

step "1/5 download release assets for ${release_tag}"
gh release download "${release_tag}" \
    --repo "${repository}" \
    --dir "${release_dir}" \
    --pattern '*.tar.gz' \
    --pattern '*.cyclonedx.json' \
    --pattern SHA256SUMS \
    --pattern '*.bundle.json'
ls -1 "${release_dir}"

# every expected asset must exist: globs and --ignore-missing silently skip
# absent files, so a partially-populated release would otherwise pass
expected_assets="obi-${release_tag}-linux-amd64.tar.gz
obi-${release_tag}-linux-arm64.tar.gz
obi-${release_tag}-source-generated.tar.gz
obi-${release_tag}-linux-amd64.cyclonedx.json
obi-${release_tag}-linux-arm64.cyclonedx.json
obi-${release_tag}-source-generated.cyclonedx.json
obi-java-agent-${release_tag}.cyclonedx.json
SHA256SUMS"
missing=0
for asset in ${expected_assets}; do
    [ -s "${release_dir}/${asset}" ] || {
        err "MISSING asset: ${asset}"
        missing=1
    }
    [ -s "${release_dir}/${asset}.bundle.json" ] || {
        err "MISSING signature bundle: ${asset}.bundle.json"
        missing=1
    }
done
[ "${missing}" -eq 0 ] || {
    err "FATAL: release is missing assets"
    exit 1
}
ok "all $(echo "${expected_assets}" | wc -l | tr -d ' ') expected assets present, each with a signature bundle"

step "2/5 checksums (every line must report OK)"
while read -r asset; do
    case "${asset}" in SHA256SUMS) continue ;; esac
    grep -q "[[:space:]]${asset}\$" "${release_dir}/SHA256SUMS" || {
        err "FATAL: SHA256SUMS has no entry for ${asset}"
        exit 1
    }
done <<< "${expected_assets}"
(
    cd "${release_dir}"
    sha_check
) | colorize_status

step "3/5 Cosign signatures (every artifact must report Verified OK)"
for artifact in "${release_dir}"/*.tar.gz "${release_dir}"/*.cyclonedx.json "${release_dir}"/SHA256SUMS; do
    echo "--- $(basename "${artifact}")"
    cosign verify-blob "${artifact}" \
        --bundle "${artifact}.bundle.json" \
        --certificate-identity "${release_identity}" \
        --certificate-oidc-issuer "${oidc_issuer}" 2>&1 | colorize_status
done

step "4/5 archive contents"
for arch in amd64 arm64; do
    archive="${release_dir}/obi-${release_tag}-linux-${arch}.tar.gz"
    echo "--- $(basename "${archive}")"
    listing="$(tar -tzf "${archive}")"
    for entry in '^obi$' '^LICENSE$' '^NOTICE$' '^NOTICES/'; do
        grep -q "${entry}" <<< "${listing}" || {
            err "FATAL: archive is missing an entry matching ${entry}"
            exit 1
        }
    done
    ok "contains obi, LICENSE, NOTICE, and $(echo "${listing}" | grep -c '^NOTICES/') NOTICES/ entries"
    extract_dir="${release_dir}/extract-${arch}"
    mkdir -p "${extract_dir}"
    tar -xzf "${archive}" -C "${extract_dir}"
    [ -s "${extract_dir}/obi" ] || {
        err "FATAL: extracted obi binary is missing or empty"
        exit 1
    }
    if command -v file >/dev/null; then
        file "${extract_dir}/obi"
    fi
done
tar -tzf "${release_dir}/obi-${release_tag}-source-generated.tar.gz" >/dev/null
ok "source-generated archive: readable"

step "5/5 container image signatures (Docker Hub + GHCR)"
# docker/metadata-action publishes the semver {{version}} tag, which drops any
# +build metadata the git tag carries (see publish_dockerhub_main.yml)
image_tag="${release_tag%%+*}"
for image in \
    "otel/ebpf-instrument:${image_tag}" \
    "ghcr.io/${repository}/ebpf-instrument:${image_tag}"; do
    cosign verify \
        --certificate-identity "${image_identity}" \
        --certificate-oidc-issuer "${oidc_issuer}" \
        "${image}" >/dev/null
    ok "${image}: Verified OK"
done

keep_artifacts=0
echo
ok "ALL CHECKS PASSED for ${release_tag}"
