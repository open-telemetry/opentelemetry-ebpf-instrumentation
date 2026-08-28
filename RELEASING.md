# Release Process

For the project's versioning and stability policy, including how OBI versions unstable surfaces today and stable surfaces in the future, see [VERSIONING.md](./VERSIONING.md).

## Pre-Release

First, decide which module sets will be released and update their versions in `versions.yaml`.
Commit this change to a new branch (i.e. `release-vX.X.X`).

Update all crosslink dependencies and any version references in code.

1. Run the `prerelease` make target.

   ```console
   make prerelease MODSET=<module set>
   ```

   For example, to prepare a release for the `obi` module set, run:

   ```console
   make prerelease MODSET=obi
   ```

   This will create a branch `prerelease_<module set>_<new tag>` that will contain all release changes.

2. Verify the changes.

    ```console
    git diff ...prerelease_<module set>_<new tag>
    ```

    This should have changed the version for all modules to be `<new tag>`, if there are any crosslink dependencies.

    If these changes look correct, merge them into your pre-release branch:

    ```console
    git merge prerelease_<module set>_<new tag>
    ```

3. Push the changes to upstream and create a Pull Request on GitHub.

## Tag

Once the Pull Request with all the version changes has been approved and merged it is time to tag the merged commit.

<!-- markdownlint-disable MD028 -->
> [!CAUTION]
> It is critical you use the same tag that you used in the Pre-Release step!
> Failure to do so will leave things in a broken state.
> As long as you do not change `versions.yaml` between pre-release and this step, things should be fine.

> [!CAUTION]
> [There is currently no way to remove an incorrectly tagged version of a Go module](https://github.com/golang/go/issues/34189).
> It is critical you make sure the version you push upstream is correct.
> [Failure to do so will lead to minor emergencies and tough to work around](https://github.com/open-telemetry/opentelemetry-go/issues/331).

> [!NOTE]
> The tag must follow the format `vX.Y.Z` or `vX.Y.Z-suffix` (e.g., `v1.2.3` or `v1.2.3-rc1`), where X, Y, and Z are numbers. The release workflow will only trigger on tags matching this pattern.
> When the tag is pushed, the release workflow will automatically run the full test suite as composed workflows before creating a draft release.
> If any tests fail or don't complete, the release will not be created.
<!-- markdownlint-enable MD028 -->

1. For each module set that will be released, run the `add-tags` make target using the `<commit-hash>` of the commit on the main branch for the merged Pull Request.

   ```console
   make add-tags MODSET=<module set> COMMIT=<commit hash>
   ```

   For example, to add tags for the `obi` module set for the latest commit, run:

   ```console
   make add-tags MODSET=obi
   ```

   It should only be necessary to provide an explicit `COMMIT` value if the
   current `HEAD` of your working directory is not the correct commit.

2. Push tags to the upstream remote (not your fork: `github.com/open-telemetry/opentelemetry-go.git`).
   Make sure you push all sub-modules as well.

   ```console
   git push upstream <new tag>
   git push upstream <submodules-path/new tag>
   ...
   ```

## Release

### Automatic Release Workflow

When you push a tag matching the pattern `vX.Y.Z` (e.g., `v1.2.3`) or `vX.Y.Z-suffix` (e.g., `v1.2.3-rc1`), where X, Y, and Z are numbers, the release workflow will automatically:

1. **Validate Tag Format**: Ensures the tag follows the required format (`v*.*.*` with optional pre-release suffix).

2. **Run Full Test Suite**: The workflow runs all required CI checks in parallel as composed workflows:
   - Unit tests and verification checks
   - Integration tests
   - K8s integration tests
   - OATS tests
   - VM integration tests
   - ARM integration tests
   - Java agent tests
   - Docker build tests
   - Clang format checking
   - Clang tidy linting

   If any of these checks fail or don't complete, the release workflow will fail and no draft release will be created.

3. **Build Release Artifacts**: Once all checks pass, the workflow builds multi-architecture release artifacts:
   - Runs `make release` to generate versioned tarballs for amd64 and arm64
   - Archives contain: `obi`, LICENSE, NOTICE, and NOTICES/ directory
   - Builds a custom source archive from the exact tagged source snapshot plus generated artifacts (including bpf2go outputs)
   - Generates one CycloneDX SBOM per release archive
   - Generates a dedicated CycloneDX SBOM for the embedded Java agent to capture its Java dependency graph
   - Generates SHA256 checksums for all uploaded release archives and SBOM assets
   - Verifies archive contents, binary executability, and SBOM structure

4. **Create Draft Release**: A draft release is automatically created with:
   - Auto-generated release notes from GitHub
   - Multi-architecture tarballs: `obi-v<version>-linux-amd64.tar.gz` and `obi-v<version>-linux-arm64.tar.gz`
   - Source+generated archive: `obi-v<version>-source-generated.tar.gz`
   - CycloneDX SBOMs for each archive:
     `obi-v<version>-linux-amd64.cyclonedx.json`,
     `obi-v<version>-linux-arm64.cyclonedx.json`,
     and `obi-v<version>-source-generated.cyclonedx.json`
   - Java agent CycloneDX SBOM:
     `obi-java-agent-v<version>.cyclonedx.json`
   - Checksum file: `SHA256SUMS` covering the release archives and SBOM assets

   The draft release allows maintainers to review artifacts before publication.

### Reviewing, Editing, and Publishing the Draft Release

Once the workflow completes successfully, a draft release is automatically created with auto-generated release notes from GitHub, which includes a list of changes since the previous release.

1. Locate the draft release on the [GitHub Releases page](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases)
2. Verify the artifacts, signatures, and container images (requires `gh` and `cosign`); the script must end with `ALL CHECKS PASSED`:

   ```console
   ./scripts/verify-draft-release.sh vX.Y.Z
   ```

3. Review and edit the auto-generated release notes for accuracy and clarity.
   When the supported configuration contract changes, link the
   [Config v1 to v2 migration guide](devdocs/config/version-2.0/migration.md),
   state the first release that can load the new version in standalone and
   Collector receiver modes, whether the previous configuration version remains
   supported, and any migration limitations; link the notes back from the
   [Config v2 release gate](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2251)
   and the
   [stable v1.0 release epic](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1133).
4. Click "Publish release" to make it immutable and publicly available

> [!IMPORTANT]
> Once published, GitHub releases are immutable. Artifacts and checksums cannot be modified or replaced. Review carefully before publishing.

### User Documentation To Keep In Sync

When release artifact names, verification commands, or installation steps change,
update the user-facing docs in both places before or alongside the release:

- Repository quick-start guide: [README.md](README.md)
- Repository [Config v1 to v2 migration guide](devdocs/config/version-2.0/migration.md)
- OpenTelemetry [docs for standalone installs](https://opentelemetry.io/docs/zero-code/obi/setup/standalone/)
- OpenTelemetry [docs for container installs](https://opentelemetry.io/docs/zero-code/obi/setup/docker/)

### Archive Contents

Each release archive (`obi-v<version>-linux-<arch>.tar.gz`) contains:

- `obi`: Main OBI binary
- `LICENSE`: Apache 2.0 license file
- `NOTICE`: Legal notices
- `NOTICES/`: Directory with third-party licenses and attributions

The release also includes a custom source archive, `obi-v<version>-source-generated.tar.gz`, which contains:

- Source files from the exact tagged revision
- Generated artifacts produced by the release generation pipeline (including bpf2go-generated `.go` and `.o` outputs and the Java agent JAR `obi-java-agent.jar`)

### Building Release Artifacts Locally

To test the release artifact generation locally before tagging:

```console
make release GOARCH=amd64
make release GOARCH=arm64
make release-source
```

This will:

1. Build artifacts for both amd64 and arm64 architectures
2. Build a source+generated archive from the current release version ref
3. Verify archive contents
4. Generate a single `SHA256SUMS` file for all `obi-v<version>-*.tar.gz` release archives and SBOM assets

The `dist/` directory will contain:

- `obi-v<version>-linux-amd64.tar.gz`
- `obi-v<version>-linux-arm64.tar.gz`
- `obi-v<version>-source-generated.tar.gz`
- `obi-v<version>-linux-amd64.cyclonedx.json`
- `obi-v<version>-linux-arm64.cyclonedx.json`
- `obi-v<version>-source-generated.cyclonedx.json`
- `obi-java-agent-v<version>.cyclonedx.json`
- `SHA256SUMS`

### Manual Release Trigger

If you need to re-trigger the release workflow (for example, if the workflow previously failed due to a temporary issue), dispatch it from the release tag:

```console
release_tag=vX.Y.Z
gh workflow run release.yml \
  --repo open-telemetry/opentelemetry-ebpf-instrumentation \
  --ref "${release_tag}" \
  --raw-field tag="${release_tag}" \
  --raw-field latest=false
```

Using the release tag for `--ref` is required. Dispatching from the default branch would give the signed artifacts a `refs/heads/main` certificate identity instead of the `refs/tags/${release_tag}` identity required by the verification command above.

The manual trigger will validate the tag format, run the full test suite, and create a draft release with the same requirements as the automatic trigger.

## Post-Release

The Helm chart version is automatically updated by CI.

The releaser must update the OBI version references in the
[OpenTelemetry documentation](https://opentelemetry.io/docs/zero-code/obi/).
