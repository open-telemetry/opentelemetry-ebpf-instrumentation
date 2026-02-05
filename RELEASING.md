# Release Process

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
   Be sure to include the curated changes from the [Changelog](./CHANGELOG.md) in the description.

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

3. **Create Draft Release**: Once all checks pass, a draft release is automatically created with auto-generated release notes.

   You can then review and publish the draft release from the [GitHub Releases page](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases).

### Manual Release Trigger

If you need to re-trigger the release workflow (for example, if the workflow previously failed due to a temporary issue), you can use the manual trigger:

1. Go to the [Release workflow](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/workflows/release.yml)
2. Click "Run workflow"
3. Enter the tag name (e.g., `v1.2.3`) in the required input field
4. Click "Run workflow"

The manual trigger will validate the tag format, run the full test suite, and create a draft release with the same requirements as the automatic trigger.

### Release Notes

The draft release is automatically created with auto-generated release notes from GitHub, which includes a list of changes since the previous release.
Review the draft release on the [GitHub Releases page](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases), and if the generated notes look good, publish the release.

## Post-Release

**TODO**: bump versions in Helm charts and other places.
