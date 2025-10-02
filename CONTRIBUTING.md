# Contributing to opentelemetry-ebpf-instrumentation (OBI)

The eBPF Instrumentation special interest group (SIG) meets regularly. See the
OpenTelemetry
[community](https://github.com/open-telemetry/community)
repo for information on this and other language SIGs.

See the [public meeting
notes](https://docs.google.com/document/d/1ZkmUT2EHKfgtLqrgx3WI8aBy2QNyZeTwSKXxe3DI6Pw/edit)
for a summary description of past meetings. To request edit access,
join the meeting or get in touch on
[Slack](https://cloud-native.slack.com/archives/C08P9L4FPKJ).

## Scope

It is important to note what this project is and is not intended to achieve.
This helps focus development to these intended areas and defines clear
functional boundaries for the project.

### What this project is

This project aims to provide auto-instrumentation functionality for applications using eBPF and other process-external technologies. It conforms to
OpenTelemetry standards and strives to be compatible with that ecosystem.

### What this project is not

* **A replacement for manual instrumentation**: Manual or SDK-based instrumentation can achieve a level of granularity that is beyond the scope of this project. For example, SDK instrumentation enables you to instrument the _inner machinery_ of a service, capturing highly detailed span information. In contrast, this project focuses on instrumenting incoming (server) and outgoing (client) service requests, without necessarily reporting internal spans.

## Development

### Compiling the project

#### Requirements

- OBI requires Linux with Kernel 5.8 or higher with BPF Type Format [(BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html) enabled. BTF became enabled by default on most Linux distributions with kernel 5.14 or higher. You can check if your kernel has BTF enabled by verifying if `/sys/kernel/btf/vmlinux` exists on your system. If you need to recompile your kernel to enable BTF, the configuration option `CONFIG_DEBUG_INFO_BTF=y` must be set.
- It also supports RedHat-based distributions: RHEL8, CentOS 8, Rocky8, AlmaLinux8, and others, which ship a Kernel 4.18 that backports eBPF-related patches.
- eBPF enabled in the host.
- For instrumenting Go programs, compile with at least Go 1.17. OBI support Go applications built with a major **Go version no earlier than 3 versions** behind the current stable major release.

In addition, use the latest versions of the following components:

- `go`
- `clang`
- `docker`
- `make`
- `clang-format`
- `clang-tidy`

#### Compilation steps

Compiling OBI is a two-tier process: first, we need to build the eBPF code (written in C) and generate the Go bindings. There are two `Makefile` targets for that, `generate` and `docker-generate`. The difference between them is that `generate` will attempt to use the local clang/LLVM toolchain, whereas `docker-generate` pulls a Docker image containing all of the tooling required - this is also the target used by OBI's GitHub CI.
Once the eBPF files have been generated, we can use the `compile` `Makefile` target to build the main binary.

```
make docker-generate # or make generate
make compile
```

A convenience `Makefile` target called `dev` which invokes both the generation and compilation step is also provided:

```
make dev
```

#### Installing `clang-format` hooks

OBI relies on `clang-format` for linting the C code, and as such, ships a convenience _pre-commit_ git hook that formats the code during the commit process. To enable/install this hook, simply do:

```
make install-hooks
```

#### Manually formatting the C code

```
make clang-format
```

#### Linting the C code

```
make clang-tidy
```

#### Formatting the Go code

```
make fmt
```

#### Linting the Go code

```
make lint
```

#### Running unit tests

```
make test
```

#### Running integration tests

```
make integration-test
```

#### Running k8s integration tests

```
make integration-tests-k8s
```

### Issues

Questions, bug reports, and feature requests can all be submitted as [issues](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/new) to this repository.

## Pull Requests

### How to Send Pull Requests

Everyone is welcome to contribute code to `opentelemetry-ebpf-instrumentation` via
GitHub pull requests (PRs).

To create a new PR, fork the project in GitHub and clone the upstream
repo:

```sh
git clone https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation
```

This would put the project in the `opentelemetry-ebpf-instrumentation` directory in
current working directory.

Enter the newly created directory and add your fork as a new remote:

```sh
git remote add <YOUR_FORK> git@github.com:<YOUR_GITHUB_USERNAME>/opentelemetry-ebpf-instrumentation
```

Check out a new branch, make modifications, run linters and tests, update
`CHANGELOG.md`, and push the branch to your fork:

```sh
git checkout -b <YOUR_BRANCH_NAME>
# edit files
make fmt
make lint
git add -p
git commit
git push <YOUR_FORK> <YOUR_BRANCH_NAME>
```

Open a pull request against the main `opentelemetry-ebpf-instrumentation` repo.

### How to Receive Comments

* If the PR is not ready for review, please put `[WIP]` in the title or mark it as
  [`draft`](https://github.blog/2019-02-14-introducing-draft-pull-requests/).
* Make sure CLA is signed and CI is clear.

### How to Get PRs Merged

> [!IMPORTANT]
> In order to facilitate PR reviews, PRs should be made of atomic commits that can be individually reviewed, even if they end up being squashed at the time of merge.

A PR is considered **ready to merge** when:

* It has received at least one qualified approval[^2].

  For complex or sensitive PRs maintainers may require more than one qualified
  approval.

* All feedback has been addressed.
  * All PR comments and suggestions are resolved.
  * All GitHub Pull Request reviews with a status of "Request changes" have
    been addressed. Another review by the objecting reviewer with a different
    status can be submitted to clear the original review, or the review can be
    dismissed by a [Maintainer] when the issues from the original review have
    been addressed.
  * Any comments or reviews that cannot be resolved between the PR author and
    reviewers can be submitted to the community [Approver]s and [Maintainer]s
    during the weekly SIG meeting. If consensus is reached among the
    [Approver]s and [Maintainer]s during the SIG meeting the objections to the
    PR may be dismissed or resolved or the PR closed by a [Maintainer].
  * Any substantive changes to the PR require existing Approval reviews be
    cleared unless the approver explicitly states that their approval persists
    across changes. This includes changes resulting from other feedback.
    [Approver]s and [Maintainer]s can help in clearing reviews and they should
    be consulted if there are any questions.

>[!NOTE]
It’s often helpful to let the reporter resolve a comment or issue themselves, rather than resolving it on their behalf. This reduces back-and-forth and makes it easier to track which feedback is still pending.

* The PR branch is up to date with the base branch it is merging into.
  * To ensure this does not block the PR, it should be configured to allow
    maintainers to update it.

* All required GitHub workflows have succeeded.
* Urgent fix can take exception as long as it has been actively communicated
  among [Maintainer]s.

Any [Maintainer] can merge the PR once the above criteria have been met.

[^2]: A qualified approval is a GitHub Pull Request review with "Approve"
  status from an OpenTelemetry eBPF Instrumentation [Approver] or [Maintainer].

## Appovers and Maintainers

### Maintainers

* [Mario Macias](https://github.com/mariomac), Grafana
* [Mike Dame](https://github.com/damemi), Odigos
* [Nikola Grcevski](https://github.com/grcevski), Grafana
* [Tyler Yahn](https://github.com/MrAlias), Splunk

For more information about the maintainer role, see the [community repository](https://github.com/open-telemetry/community/blob/main/guides/contributor/membership.md#maintainer).

### Approvers

* [Marc Tudurí](https://github.com/marctc), Grafana
* [Mattia Meleleo](https://github.com/mmat11), Coralogix
* [Nimrod Avni](https://github.com/NimrodAvni78), Coralogix
* [Rafael Roquetto](https://github.com/rafaelroquetto), Grafana
* [Stephen Lang](https://github.com/skl), Grafana

For more information about the approver role, see the [community repository](https://github.com/open-telemetry/community/blob/main/guides/contributor/membership.md#approver).

### Become an Approver or a Maintainer

See the [community membership document in OpenTelemetry community
repo](https://github.com/open-telemetry/community/blob/main/guides/contributor/membership.md).

[Approver]: #approvers
[Maintainer]: #maintainers
