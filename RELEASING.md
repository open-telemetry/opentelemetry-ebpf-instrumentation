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
> The tag must follow the format `v*.*.*` (e.g., `v1.2.3`). The release workflow will only trigger on tags matching this pattern.
> Additionally, the commit being tagged must have passed all required CI checks. If CI has not completed or has failed, the release workflow will fail.
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

Finally create a Release for the new `<new tag>` on GitHub.

### Automatic Release Workflow

When you push a tag matching the pattern `v*.*.*` (e.g., `v1.2.3`), the release workflow will automatically:

1. **Verify CI Status**: The workflow checks that all required CI checks have passed on the tagged commit:
   - Unit tests and verification checks (the `test` job from `pull_request.yml`)
   - Integration tests (Go integration test shards; jobs with `shard-` in the name from `pull_request_integration_tests.yml` and `workflow_integration_tests_vm.yml`)
   - VM integration tests (kernel variants; jobs with `kernel` in the name from `workflow_integration_tests_vm.yml`)
   - Kubernetes integration tests (`daemonset` and `netolly` variants from `pull_request_k8s_integration_tests.yml`)
   - OATS tests (`http`, `kafka`, `mongo`, `redis`, `sql` jobs from `pull_request_oats_test.yml`)

   If any required checks have not passed or are missing, the release workflow will fail and no draft release will be created.

2. **Create Draft Release**: Once CI verification passes, a draft release is automatically created with auto-generated release notes.

   You can then review and publish the draft release from the [GitHub Releases page](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases).

### Manual Release Trigger

If you need to re-trigger the release workflow for a commit that already has passing CI (for example, if the workflow previously failed), you can use the manual trigger:

1. Go to the [Release workflow](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/workflows/release.yml)
2. Click "Run workflow"
3. Enter the tag name (e.g., `v1.2.3`) in the required input field
4. Click "Run workflow"

The manual trigger will validate the tag format, verify CI status, and create a draft release with the same requirements as the automatic trigger.

### Release Notes

Currently we do not have a curated changelog.
Use the Github automated changelog generation to create the release notes.

## Post-Release

**TODO**: bump versions in Helm charts and other places.
