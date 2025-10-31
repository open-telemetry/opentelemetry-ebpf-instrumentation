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

Currently we do not have a curated changelog.
Use the Github automated changelog generation to create the release notes.

## Post-Release

**TODO**: bump versions in Helm charts and other places.
