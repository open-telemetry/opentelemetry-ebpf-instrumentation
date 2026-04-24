# Main binary configuration
# CMD: Default binary name is now "obi" (OpenTelemetry eBPF Instrumentation)
CMD ?= obi
JAVA_AGENT ?= obi-java-agent.jar
MAIN_GO_FILE ?= cmd/$(CMD)/main.go

CACHE_CMD ?= k8s-cache
CACHE_MAIN_GO_FILE ?= cmd/$(CACHE_CMD)/main.go

GOOS ?= linux
GOARCH ?= $(shell go env GOARCH || echo amd64)

# RELEASE_VERSION will contain the tag name, or the branch name if current commit is not a tag
RELEASE_VERSION := $(shell git describe --all | cut -d/ -f2)
RELEASE_REVISION := $(shell git rev-parse --short HEAD )
BUILDINFO_PKG ?= go.opentelemetry.io/obi/pkg/buildinfo
TEST_OUTPUT ?= ./testoutput
RELEASE_DIR ?= ./dist

IMG_REGISTRY ?= docker.io
# Set your registry username. CI will set 'otel' but you mustn't use it for manual pushing.
IMG_ORG ?=
IMG_NAME ?= ebpf-instrument

# Container image creation creation
VERSION ?= dev
IMG ?= $(IMG_REGISTRY)/$(IMG_ORG)/$(IMG_NAME):$(VERSION)

# The generator is a container image that provides a reproducible environment for
# building eBPF binaries
GEN_IMG ?= ghcr.io/open-telemetry/obi-generator:0.2.11

OCI_BIN ?= docker

# User to run as in docker images.
DOCKER_USER=$(shell id -u):$(shell id -g)
DEPENDENCIES_DOCKERFILE=./dependencies.Dockerfile
GRADLE_IMAGE := $(shell awk '$$4=="gradle-java" {print $$2}' $(DEPENDENCIES_DOCKERFILE))
PYTHON39_IMAGE := $(shell awk '$$4=="python39" {print $$2}' $(DEPENDENCIES_DOCKERFILE))
PYTHON314_IMAGE := $(shell awk '$$4=="python314" {print $$2}' $(DEPENDENCIES_DOCKERFILE))

# BPF code generator dependencies
CLANG ?= clang
CFLAGS := -std=gnu17 -O2 -g -Wunaligned-access -Wpacked -Wpadded -Wall -Werror $(CFLAGS)

CLANG_TIDY ?= clang-tidy

CILIUM_EBPF_VER ?= v0.20.0
CILIUM_EBPF_PKG := github.com/cilium/ebpf

# regular expressions for excluded file patterns
EXCLUDE_COVERAGE_FILES := "(_bpfel.go)|(.pb.go)|$\
(/cmd/generate-port-lookup/)|$\
(/cmd/obi-schema/)|$\
(/obi/configs/)|$\
(/obi/examples/)|$\
(/obi/internal/test/)|$\
(/obi/scripts/)|$\
(/pkg/export/otel/metric/)"

.DEFAULT_GOAL := all

# go-install-tool will 'go install' any package $2 and install it locally to $1.
# This will prevent that they are installed in the $USER/go/bin folder and different
# projects ca have different versions of the tools
PROJECT_DIR := $(shell dirname $(abspath $(firstword $(MAKEFILE_LIST))))

# BPF2GO_MAKEBASE tells bpf2go to generate Make-compatible dependency files (.d files)
# relative to the project root. These .d files track dependencies between generated
# Go code and source .c/.h files, enabling smart incremental builds.
# See: https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go
export BPF2GO_MAKEBASE := $(PROJECT_DIR)

# Check that given variables are set and all have non-empty values,
# die with an error otherwise.
#
# Params:
#   1. Variable name(s) to test.
#   2. (optional) Error message to print.
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
	$(if $(value $1),, \
	  $(error Undefined $1$(if $2, ($2))))

### Development Tools #######################################################

# Tools module where tool versions are defined.
TOOLS_MODFILE := -modfile=$(CURDIR)/internal/tools/go.mod

BPF2GO_WRAPPER := $(CURDIR)/.tools/bpf2go
$(BPF2GO_WRAPPER):
	@mkdir -p $(dir $@)
	@printf '#!/bin/sh\nexec go tool $(TOOLS_MODFILE) bpf2go "$$@"\n' > $@
	@chmod +x $@

BPF2GO ?= $(BPF2GO_WRAPPER)

# Required for k8s-cache unit tests
ENVTEST_K8S_VERSION ?= 1.30.0

### Development Tools (end) #################################################

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: install-hooks
install-hooks:
	@if [ ! -f .git/hooks/pre-commit ]; then \
		echo "Installing pre-commit hook..."; \
		cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit; \
		echo "Pre-commit hook installed."; \
	fi

.PHONY: prereqs
prereqs: install-hooks
	@echo "### Check if prerequisites are met, and installing missing dependencies"
	mkdir -p $(TEST_OUTPUT)/run

.PHONY: fmt
fmt:
	@echo "### Formatting code and fixing imports"
	go tool $(TOOLS_MODFILE) golangci-lint fmt

.PHONY: clang-tidy
clang-tidy:
	cd bpf && find . -type f \( -name '*.c' -o -name '*.h' \) ! -path "./bpfcore/*" ! -path "./NOTICES/*" ! -path "./tests/*" | xargs clang-tidy

.PHONY: lint
lint: LINT_EXTRA_ARGS =
lint: lint-run

.PHONY: lint-fix
lint-fix: LINT_EXTRA_ARGS = --fix
lint-fix: lint-run

.PHONY: lint-run
lint-run: vanity-import-check lint-dependency-policy lint-collectt
	@echo "### Linting code"
	go tool $(TOOLS_MODFILE) golangci-lint run ./... --timeout=6m $(LINT_EXTRA_ARGS)

.PHONY: lint-dependency-policy
lint-dependency-policy:
	@echo "### Linting dependency integrity policy"
	@if [ -n "$$CI" ]; then \
		echo "### CI detected: enabling verbose dependency-policy lint logging"; \
		./scripts/lint-dependency-policy.sh --verbose; \
	else \
		./scripts/lint-dependency-policy.sh; \
	fi

.PHONY: lint-collectt
lint-collectt:
	@echo "### Checking EventuallyWithT callbacks use CollectT"
	go run ./internal/test/analyzer/collectt/cmd/collecttlint ./...

MARKDOWNIMAGE := $(shell awk '$$4=="markdown" {print $$2}' $(DEPENDENCIES_DOCKERFILE))
.PHONY: lint-markdown
lint-markdown:
	@echo "### Linting markdown"
	@docker run --rm -v "$(CURDIR):/workdir" $(MARKDOWNIMAGE) "{*.md,!(NOTICES)/**/*.md}"

.PHONY: lint-markdown-fix
lint-markdown-fix:
	@echo "### Formatting markdown"
	@docker run --rm -v "$(CURDIR):/workdir" $(MARKDOWNIMAGE) --fix "{*.md,!(NOTICES)/**/*.md}"

.PHONY: update-offsets
update-offsets:
	@echo "### Updating pkg/internal/goexec/offsets.json"
	go tool $(TOOLS_MODFILE) go-offsets-tracker -i configs/offsets/tracker_input.json pkg/internal/goexec/offsets.json

### eBPF Code Generation ###########################################################
#
# This section handles generation of Go code from eBPF C sources using bpf2go.
# The system supports smart incremental builds via Make's dependency tracking.
#
# Developer Guide:
#
#   make generate      - Smart incremental build (recommended for development)
#                        Only regenerates files that are missing or out-of-date.
#                        Takes ~0.05s when nothing needs rebuilding.
#
#   make generate/all  - Force regeneration of everything (use after git clean)
#                        Always regenerates all eBPF code (~60s).
#                        Use after: git clean -dxf, initial clone, or when in doubt.
#
#   make docker-generate - Generate in Docker container (for reproducible builds)
#                          Mounts workspace and runs 'make generate' inside container.
#                          Image: $(GEN_IMG)
#
# How it works:
#   - bpf2go generates .d files (thanks to BPF2GO_MAKEBASE) that track dependencies
#   - Make reads these .d files to know when source .c/.h files have changed
#   - Only affected packages are rebuilt when sources change
#   - Pattern rule runs go generate for each out-of-date file's directory
#
# Generated files (gitignored):
#   - *_bpfel.go, *_bpfeb.go  - Go bindings for eBPF programs
#   - *_bpfel.o, *_bpfeb.o    - Compiled eBPF bytecode
#   - *_bpfel.go.d, *_bpfeb.go.d - Dependency files for Make
#
# NOTE on parallel builds:
#   Using 'make -j' with the 'generate' target may result in a race condition.
#   Each go generate invocation produces multiple files, and parallel execution
#   can cause bpf2go to simultaneously be run on the same directory. This
#   command should be idempotent, but it may cause redundant generation and
#   potential conflicts.
#
################################################################################

BPF_ROOT = pkg/

# Find all generated Go and object files (used as Make targets)
BPF_GEN_GO := $(shell find $(BPF_ROOT) -type f \( -name 'bpf_*_bpfe[lb].go' -o -name 'net_*_bpfe[lb].go' -o -name 'netsk_*_bpfe[lb].go' \))
BPF_GEN_OBJ := $(BPF_GEN_GO:.go=.o)
BPF_GEN_ALL := $(if $(BPF_GEN_GO),$(BPF_GEN_GO) $(BPF_GEN_OBJ))

# Include dependency files generated by bpf2go for smart incremental builds.
# These .d files contain Make rules like:
#   pkg/internal/ebpf/logger/bpf_x86_bpfel.go: bpf/logger/logger.c bpf/bpfcore/vmlinux.h ...
-include $(shell find $(BPF_ROOT) -type f -name '*_bpfe[lb].go.d' 2>/dev/null)

.PHONY: generate generate/all
# Smart incremental build - only regenerates what's needed
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: export BPF2GO := $(BPF2GO)
generate: $(BPF2GO) $(if $(BPF_GEN_ALL),$(BPF_GEN_ALL),generate/all)

# Pattern rule: regenerate specific eBPF files when dependencies change
$(BPF_GEN_ALL):
	@echo "Generating $(dir $@)..."
	@go generate ./$(dir $@)

# Force regeneration of all eBPF code (use after git clean or initial clone)
generate/all: export BPF_CLANG := $(CLANG)
generate/all: export BPF_CFLAGS := $(CFLAGS)
generate/all: export BPF2GO := $(BPF2GO)
generate/all: $(BPF2GO)
	@echo "### Generating all eBPF files..."
	@go generate ./...

# Generate eBPF code in Docker container for reproducible builds
.PHONY: docker-generate
docker-generate:
	@echo "### Generating files in Docker..."
	@_git_dir=$$(git rev-parse --absolute-git-dir) && \
	_git_common_dir=$$(git rev-parse --path-format=absolute --git-common-dir) && \
	$(OCI_BIN) run --rm \
		$(if $(findstring podman,$(OCI_BIN)),  ,-u "$(DOCKER_USER)") \
		-v "$(CURDIR):/src:z" \
		-v "$$_git_common_dir:/src/.gitrepo:ro,z" \
		-e GIT_DIR="/src/.gitrepo$${_git_dir#$$_git_common_dir}" \
		-w /src \
		$(GEN_IMG) \
		make generate

.PHONY: verify
verify: prereqs go-mod-tidy lint test license-header-check

.PHONY: build
build: docker-generate verify compile

.PHONY: all
all: docker-generate notices-update build

.PHONY: compile compile-cache
compile:
	@echo "### Compiling OpenTelemetry eBPF Instrumentation"
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="-X '$(BUILDINFO_PKG).Version=$(RELEASE_VERSION)' -X '$(BUILDINFO_PKG).Revision=$(RELEASE_REVISION)'" -a -o bin/$(CMD) $(MAIN_GO_FILE)
compile-cache:
	@echo "### Compiling OpenTelemetry eBPF Instrumentation K8s cache"
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="-X '$(BUILDINFO_PKG).Version=$(RELEASE_VERSION)' -X '$(BUILDINFO_PKG).Revision=$(RELEASE_REVISION)'" -a -o bin/$(CACHE_CMD) $(CACHE_MAIN_GO_FILE)

.PHONY: debug
debug:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -gcflags "-N -l" -ldflags="-X '$(BUILDINFO_PKG).Version=$(RELEASE_VERSION)' -X '$(BUILDINFO_PKG).Revision=$(RELEASE_REVISION)'" -a -o bin/$(CMD) $(MAIN_GO_FILE)

.PHONY: dev
dev: prereqs generate compile-for-coverage

# Generated binary can provide coverage stats according to https://go.dev/blog/integration-test-coverage
.PHONY: compile-for-coverage compile-cache-for-coverage
compile-for-coverage:
	@echo "### Compiling project to generate coverage profiles"
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -cover -a -o bin/$(CMD) $(MAIN_GO_FILE)
compile-cache-for-coverage:
	@echo "### Compiling K8s cache service to generate coverage profiles"
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -cover -a -o bin/$(CACHE_CMD) $(CACHE_MAIN_GO_FILE)

.PHONY: test
test:
	@echo "### Testing code"
	KUBEBUILDER_ASSETS="$(shell go tool $(TOOLS_MODFILE) setup-envtest use $(ENVTEST_K8S_VERSION) -p path)" go test -short -race -a ./... -coverpkg=./... -coverprofile $(TEST_OUTPUT)/cover.all.txt

.PHONY: test-privileged
test-privileged: $(ENVTEST)
	@echo "### Testing only privileged-tagged tests"
	go test -short -race -tags=privileged_tests -a \
	$$(grep -rl '//go:build.*privileged_tests' . --include='*.go' | xargs -I{} dirname {} | sort -u | tr '\n' ' ') \
	-coverpkg=./... -coverprofile $(TEST_OUTPUT)/cover.all.txt

.PHONY: run-bpf-verifier-vm
run-bpf-verifier-vm:
	@echo "### Running BPF verifier tests"
	go test -v -count=1 -tags=bpf_verifier_tests ./pkg/internal/ebpf/verifier/...

.PHONY: cov-exclude-generated
cov-exclude-generated:
	grep -vE $(EXCLUDE_COVERAGE_FILES) $(TEST_OUTPUT)/cover.all.txt > $(TEST_OUTPUT)/cover.txt

.PHONY: coverage-report
coverage-report: cov-exclude-generated
	@echo "### Generating coverage report"
	go tool cover --func=$(TEST_OUTPUT)/cover.txt

.PHONY: coverage-report-html
coverage-report-html: cov-exclude-generated
	@echo "### Generating HTML coverage report"
	go tool cover --html=$(TEST_OUTPUT)/cover.txt

# Java agent targets
JAVA_AGENT_DIR := pkg/internal/java
JAVA_AGENT_EMBED_DIR := $(JAVA_AGENT_DIR)/embedded
JAVA_AGENT_EMBED_PATH := $(JAVA_AGENT_EMBED_DIR)/$(JAVA_AGENT)
JAVA_AGENT_JAVA_VERSION := $(shell tr -d '[:space:]' < $(JAVA_AGENT_DIR)/.java-version)
JAVA_AGENT_JAVA_HOME_CANDIDATES := /usr/lib/jvm/java-$(JAVA_AGENT_JAVA_VERSION)-openjdk /usr/lib/jvm/java-$(JAVA_AGENT_JAVA_VERSION)-openjdk-amd64
JAVA_AGENT_JAVA_HOME_FALLBACK := $(shell ls -d /usr/lib/jvm/java-*-openjdk* 2>/dev/null | sort -V | tail -n 1)
JAVA_AGENT_JAVA_HOME ?= $(or $(shell for d in $(JAVA_AGENT_JAVA_HOME_CANDIDATES); do [ -d "$$d" ] && { echo "$$d"; break; }; done),$(JAVA_AGENT_JAVA_HOME_FALLBACK))
JAVA_AGENT_GRADLE_ENV := $(if $(JAVA_AGENT_JAVA_HOME),JAVA_HOME=$(JAVA_AGENT_JAVA_HOME) PATH=$(JAVA_AGENT_JAVA_HOME)/bin:$$PATH,)

.PHONY: java-build
java-build:
	@echo "### Building Java agent"
	cd $(JAVA_AGENT_DIR) && $(JAVA_AGENT_GRADLE_ENV) gradle build
	mkdir -p $(JAVA_AGENT_EMBED_DIR)
	cp $(JAVA_AGENT_DIR)/build/$(JAVA_AGENT) $(JAVA_AGENT_EMBED_PATH)

.PHONY: java-docker-build
java-docker-build:
	@echo "### Building Java agent with Docker"
	mkdir -p $(JAVA_AGENT_EMBED_DIR)
	$(OCI_BIN) build --output type=local,dest=$(JAVA_AGENT_EMBED_DIR) --target=export -f javaagent.Dockerfile .

.PHONY: java-docker-sbom
java-docker-sbom:
	@echo "### Generating Java agent SBOM with Docker"
	@mkdir -p $(RELEASE_DIR)
	@$(OCI_BIN) run --rm \
		$(if $(findstring podman,$(OCI_BIN)),  ,-u "$(DOCKER_USER)") \
		-e HOME=/tmp \
		-e GRADLE_USER_HOME=/tmp/.gradle \
		-e OBI_JAVA_AGENT_SBOM_VERSION="$(RELEASE_VERSION)" \
		-v "$(CURDIR):/src:z" \
		-w /src/pkg/internal/java \
		$(GRADLE_IMAGE) \
		gradle :agent:cyclonedxDirectBom --no-daemon
	@cp pkg/internal/java/agent/build/reports/cyclonedx-direct/bom.json \
		$(RELEASE_DIR)/obi-java-agent-$(RELEASE_VERSION).cyclonedx.json

.PHONY: java-test
java-test:
	@echo "### Testing Java agent"
	cd $(JAVA_AGENT_DIR) && $(JAVA_AGENT_GRADLE_ENV) gradle test

.PHONY: java-spotless-check
java-spotless-check:
	@echo "### Checking Java code formatting"
	cd $(JAVA_AGENT_DIR) && $(JAVA_AGENT_GRADLE_ENV) gradle spotlessCheck

.PHONY: java-spotless-apply
java-spotless-apply:
	@echo "### Formatting Java code"
	cd $(JAVA_AGENT_DIR) && $(JAVA_AGENT_GRADLE_ENV) gradle spotlessApply

.PHONY: java-clean
java-clean:
	@echo "### Cleaning Java agent build artifacts"
	cd $(JAVA_AGENT_DIR) && $(JAVA_AGENT_GRADLE_ENV) gradle clean

.PHONY: java-verify
java-verify: java-spotless-check java-test java-build

# image-build is only used for local development. GH actions that build and publish the image don't make use of it
.PHONY: image-build
image-build:
	@echo "### Building the auto-instrumenter image"
	$(call check_defined, IMG_ORG, Your Docker repository user name)
	$(OCI_BIN) buildx build --load -t ${IMG} .

# generator-image-build is only used for local development. GH actions that build and publish the image don't make use of it
.PHONY: generator-image-build
generator-image-build:
	@echo "### Creating the image that generates the eBPF binaries"
	$(OCI_BIN) buildx build --load -t $(GEN_IMG) -f generator.Dockerfile  .


.PHONY: prepare-integration-test
prepare-integration-test:
	@echo "### Removing resources from previous integration tests, if any"
	rm -rf $(TEST_OUTPUT)/* || true
	$(MAKE) cleanup-integration-test

.PHONY: cleanup-integration-test
cleanup-integration-test:
	@echo "### Removing integration test clusters"
	go tool $(TOOLS_MODFILE) kind delete cluster -n test-kind-cluster || true
	@echo "### Removing docker containers and images"
	$(eval CONTAINERS := $(shell $(OCI_BIN) ps --format '{{.Names}}' | grep 'integration-'))
	$(if $(strip $(CONTAINERS)),$(OCI_BIN) rm -f $(CONTAINERS),@echo "No integration test containers to remove")
	$(eval IMAGES := $(shell $(OCI_BIN) images --format '{{.Repository}}:{{.Tag}}' | grep 'hatest-'))
	$(if $(strip $(IMAGES)),$(OCI_BIN) rmi -f $(IMAGES),@echo "No integration test images to remove")

.PHONY: run-integration-test
run-integration-test:
	@echo "### Running integration tests"
	go clean -testcache
	go test -p 1 -failfast -v -timeout 60m -a ./internal/test/integration

.PHONY: run-integration-test-k8s
run-integration-test-k8s:
	@echo "### Running integration tests"
	go clean -testcache
	go test -p 1 -failfast -v -timeout 60m -a ./internal/test/integration/k8s/...

.PHONY: run-integration-test-vm
run-integration-test-vm:
	@echo "### Running integration tests (pattern: $(TEST_PATTERN))"
	@TEST_TIMEOUT="60m"; \
	TEST_PARALLEL="1"; \
	if [ -f "/precompiled-tests/integration.test" ] && [ -f "/precompiled-tests/gotestsum" ]; then \
		echo "Using pre-compiled integration tests with gotestsum"; \
		chmod +x /precompiled-tests/integration.test /precompiled-tests/gotestsum; \
		/precompiled-tests/gotestsum \
			--rerun-fails=2 --rerun-fails-max-failures=2 \
			--raw-command -ftestname \
			--jsonfile=testoutput/vm-test-run-$(RUN_NUMBER).log \
			-- go tool test2json -t -p integration \
			/precompiled-tests/integration.test \
			-test.parallel=$$TEST_PARALLEL \
			-test.timeout=$$TEST_TIMEOUT \
			-test.v \
			-test.run="^($(TEST_PATTERN))\$$"; \
	elif [ -f "/precompiled-tests/integration.test" ]; then \
		echo "Using pre-compiled integration tests (gotestsum not available)"; \
		chmod +x /precompiled-tests/integration.test; \
		/precompiled-tests/integration.test \
			-test.parallel=$$TEST_PARALLEL \
			-test.timeout=$$TEST_TIMEOUT \
			-test.v \
			-test.run="^($(TEST_PATTERN))\$$"; \
	else \
		echo "Pre-compiled tests not found, compiling in VM"; \
		go tool $(TOOLS_MODFILE) gotestsum \
			--rerun-fails=2 --rerun-fails-max-failures=2 \
			-ftestname --jsonfile=testoutput/vm-test-run-$(RUN_NUMBER).log -- \
			-p $$TEST_PARALLEL \
			-timeout $$TEST_TIMEOUT \
			-v -a \
			-run="^($(TEST_PATTERN))\$$" ./internal/test/integration; \
	fi

.PHONY: run-integration-test-arm
run-integration-test-arm:
	@echo "### Running integration tests"
	go clean -testcache
	go test -p 1 -failfast -v -timeout 90m -a ./internal/test/integration -run "^TestMultiProcess"

.PHONY: unit-test-matrix-json
unit-test-matrix-json:
	@go list ./... | go tool $(TOOLS_MODFILE) gotestsum tool ci-matrix --partitions $${PARTITIONS:-3} --timing-files=$(TEST_OUTPUT)/unit-test-shard-*.log

.PHONY: run-unit-test-shard
run-unit-test-shard:
	@echo "### Running unit test shard $(SHARD_ID)"
	KUBEBUILDER_ASSETS="$(shell go tool $(TOOLS_MODFILE) setup-envtest use $(ENVTEST_K8S_VERSION) -p path)" \
	go tool $(TOOLS_MODFILE) gotestsum \
		--jsonfile=$(TEST_OUTPUT)/unit-test-shard-$(SHARD_ID).log \
		-- -short -race -a -coverpkg=./... \
		-coverprofile $(TEST_OUTPUT)/cover.all.txt \
		$(UNIT_TEST_PACKAGES)

.PHONY: integration-test-matrix-json
integration-test-matrix-json:
	@./scripts/generate-integration-matrix.sh internal/test/integration "$${PARTITIONS:-5}"

# Shared matrix for workflows that run the TestMultiProcess* suite
# (VM integration tests and ARM integration tests use the same set of tests).
.PHONY: multiprocess-integration-test-matrix-json
multiprocess-integration-test-matrix-json:
	@./scripts/generate-integration-matrix.sh internal/test/integration "$${PARTITIONS:-5}" "TestMultiProcess"

.PHONY: k8s-integration-test-matrix-json
k8s-integration-test-matrix-json:
	@./scripts/generate-dir-matrix.sh internal/test/integration/k8s common

.PHONY: oats-integration-test-matrix-json
oats-integration-test-matrix-json:
	@./scripts/generate-dir-matrix.sh internal/test/oats

.PHONY: integration-test
integration-test: prereqs prepare-integration-test
	$(MAKE) run-integration-test || (ret=$$?; $(MAKE) cleanup-integration-test && exit $$ret)
	$(MAKE) itest-coverage-data
	$(MAKE) cleanup-integration-test

.PHONY: integration-test-k8s
integration-test-k8s: prereqs prepare-integration-test
	$(MAKE) run-integration-test-k8s || (ret=$$?; $(MAKE) cleanup-integration-test && exit $$ret)
	$(MAKE) itest-coverage-data
	$(MAKE) cleanup-integration-test

.PHONY: integration-test-arm
integration-test-arm: prereqs prepare-integration-test
	$(MAKE) run-integration-test-arm || (ret=$$?; $(MAKE) cleanup-integration-test && exit $$ret)
	$(MAKE) itest-coverage-data
	$(MAKE) cleanup-integration-test

.PHONY: itest-coverage-data
itest-coverage-data:
	# merge coverage data from all the integration tests
	mkdir -p $(TEST_OUTPUT)/merge
	go tool covdata merge -i=$(TEST_OUTPUT) -o $(TEST_OUTPUT)/merge
	go tool covdata textfmt -i=$(TEST_OUTPUT)/merge -o $(TEST_OUTPUT)/itest-covdata.raw.txt
	# replace the unexpected /src/cmd/obi/main.go file by the module path
	sed 's/^\/src\/cmd\//go.opentelemetry.io\/obi\/cmd\//' $(TEST_OUTPUT)/itest-covdata.raw.txt > $(TEST_OUTPUT)/itest-covdata.all.txt
	# exclude generated files from coverage data
	grep -vE $(EXCLUDE_COVERAGE_FILES) $(TEST_OUTPUT)/itest-covdata.all.txt > $(TEST_OUTPUT)/itest-covdata.txt || true

.PHONY: oats-prereq
oats-prereq: docker-generate
	mkdir -p $(TEST_OUTPUT)/run

.PHONY: oats-test-sql
oats-test-sql: oats-prereq
	mkdir -p internal/test/oats/sql/$(TEST_OUTPUT)/run
	cd internal/test/oats/sql && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml go tool $(TOOLS_MODFILE) ginkgo -v -r

.PHONY: oats-test-redis
oats-test-redis: oats-prereq
	mkdir -p internal/test/oats/redis/$(TEST_OUTPUT)/run
	cd internal/test/oats/redis && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml go tool $(TOOLS_MODFILE) ginkgo -v -r

.PHONY: oats-test-kafka
oats-test-kafka: oats-prereq
	mkdir -p internal/test/oats/kafka/$(TEST_OUTPUT)/run
	cd internal/test/oats/kafka && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml go tool $(TOOLS_MODFILE) ginkgo -v -r

.PHONY: oats-test-http
oats-test-http: oats-prereq
	mkdir -p internal/test/oats/http/$(TEST_OUTPUT)/run
	cd internal/test/oats/http && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml go tool $(TOOLS_MODFILE) ginkgo -v -r

.PHONY: oats-test-mongo
oats-test-mongo: oats-prereq
	mkdir -p internal/test/oats/mongo/$(TEST_OUTPUT)/run
	cd internal/test/oats/mongo && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml go tool $(TOOLS_MODFILE) ginkgo -v -r

.PHONY: oats-test-memcached
oats-test-memcached: oats-prereq
	mkdir -p internal/test/oats/memcached/$(TEST_OUTPUT)/run
	cd internal/test/oats/memcached && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml go tool $(TOOLS_MODFILE) ginkgo -v -r

.PHONY: oats-test-ai
oats-test-ai: oats-prereq
	mkdir -p internal/test/oats/ai/$(TEST_OUTPUT)/run
	cd internal/test/oats/ai && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml go tool $(TOOLS_MODFILE) ginkgo -v -r

.PHONY: oats-test-nats
oats-test-nats: oats-prereq
	mkdir -p internal/test/oats/nats/$(TEST_OUTPUT)/run
	cd internal/test/oats/nats && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml go tool $(TOOLS_MODFILE) ginkgo -v -r

.PHONY: oats-test
oats-test: oats-test-sql oats-test-mongo oats-test-redis oats-test-kafka oats-test-http oats-test-memcached oats-test-ai oats-test-nats
	$(MAKE) itest-coverage-data

.PHONY: oats-test-debug
oats-test-debug: oats-prereq
	cd internal/test/oats/kafka && TESTCASE_BASE_PATH=./yaml TESTCASE_MANUAL_DEBUG=true TESTCASE_TIMEOUT=1h go tool $(TOOLS_MODFILE) ginkgo -v -r

.PHONY: license-header-check
license-header-check:
	@licRes=$$(for f in $$(find . -type f \( -iname '*.go' -o -iname '*.sh' -o -iname '*.c' -o -iname '*.h' \) ! -path './.git/*' ! -path './NOTICES/*' ) ; do \
	           awk '/Copyright The OpenTelemetry Authors|generated|GENERATED/ && NR<=4 { found=1; next } END { if (!found) print FILENAME }' $$f; \
	   done); \
	   if [ -n "$${licRes}" ]; then \
	           echo "license header checking failed:"; echo "$${licRes}"; \
	           exit 1; \
	   fi

.PHONY: artifact
artifact: docker-generate java-docker-build compile
	@echo "### Packing generated artifact for $(GOOS)/$(GOARCH)"
	@STAGING_DIR=$$(mktemp -d 2>/dev/null || mktemp -d -t obi.XXXXXX); \
	trap "rm -rf $$STAGING_DIR" EXIT; \
	cp ./bin/$(CMD) $$STAGING_DIR/; \
	cp LICENSE $$STAGING_DIR/; \
	cp NOTICE $$STAGING_DIR/; \
	cp -r NOTICES $$STAGING_DIR/; \
	tar -C $$STAGING_DIR -czf bin/obi-$(RELEASE_VERSION)-$(GOOS)-$(GOARCH).tar.gz $(CMD) LICENSE NOTICE NOTICES

.PHONY: release
release: artifact
	@echo "### Moving artifacts to $(RELEASE_DIR) directory"
	mkdir -p $(RELEASE_DIR)
	mv bin/obi-$(RELEASE_VERSION)-$(GOOS)-$(GOARCH).tar.gz $(RELEASE_DIR)/
	@echo "Verifying obi-$(RELEASE_VERSION)-$(GOOS)-$(GOARCH).tar.gz..."
	@mkdir -p $(RELEASE_DIR)/verify-$(GOARCH)
	@tar -xzf $(RELEASE_DIR)/obi-$(RELEASE_VERSION)-$(GOOS)-$(GOARCH).tar.gz -C $(RELEASE_DIR)/verify-$(GOARCH)
	@if [ ! -f $(RELEASE_DIR)/verify-$(GOARCH)/$(CMD) ]; then echo "ERROR: $(CMD) binary missing in $(GOARCH) archive"; exit 1; fi
	@if [ ! -f $(RELEASE_DIR)/verify-$(GOARCH)/LICENSE ]; then echo "ERROR: LICENSE missing in $(GOARCH) archive"; exit 1; fi
	@if [ ! -f $(RELEASE_DIR)/verify-$(GOARCH)/NOTICE ]; then echo "ERROR: NOTICE missing in $(GOARCH) archive"; exit 1; fi
	@if [ ! -d $(RELEASE_DIR)/verify-$(GOARCH)/NOTICES ]; then echo "ERROR: NOTICES directory missing in $(GOARCH) archive"; exit 1; fi
	@if [ ! -x $(RELEASE_DIR)/verify-$(GOARCH)/$(CMD) ]; then echo "ERROR: $(CMD) binary not executable in $(GOARCH) archive"; exit 1; fi
	@echo "✓ Archive $(GOARCH) verified successfully"
	@rm -rf $(RELEASE_DIR)/verify-$(GOARCH)
	@$(MAKE) release-checksums
	@echo "### Release artifacts ready in $(RELEASE_DIR)/"
	@ls -lh $(RELEASE_DIR)/

.PHONY: release-source
RELEASE_SOURCE_VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || git symbolic-ref --short -q HEAD || echo main)
release-source: docker-generate java-docker-build
	@./scripts/release-source.sh --release-version "$(RELEASE_SOURCE_VERSION)" --release-dir "$(RELEASE_DIR)"
	@$(MAKE) release-checksums RELEASE_VERSION=$(RELEASE_SOURCE_VERSION)

.PHONY: release-checksums
release-checksums:
	@echo "### Generating checksums"
	@mkdir -p $(RELEASE_DIR)
	@cd $(RELEASE_DIR) && \
	files=$$(find . -maxdepth 1 \( \
		-name 'obi-$(RELEASE_VERSION)-*.tar.gz' -o \
		-name 'obi-$(RELEASE_VERSION)-*.cyclonedx.json' -o \
		-name 'obi-java-agent-$(RELEASE_VERSION).cyclonedx.json' \
	\) | sed 's|^\./||' | sort) && \
	if [ -z "$$files" ]; then \
		echo "ERROR: No release artifacts found for obi-$(RELEASE_VERSION) in $(RELEASE_DIR)"; \
		exit 1; \
	fi && \
	if command -v sha256sum >/dev/null 2>&1; then \
		printf '%s\n' "$$files" | xargs sha256sum > SHA256SUMS; \
	elif command -v shasum >/dev/null 2>&1; then \
		printf '%s\n' "$$files" | xargs shasum -a 256 > SHA256SUMS; \
	else \
		echo "ERROR: Neither sha256sum nor shasum found. Please install coreutils or use macOS builtin shasum."; \
		exit 1; \
	fi

.PHONY: clean-release-dir
clean-release-dir:
	@echo "### Cleaning release directory"
	rm -rf $(RELEASE_DIR)/
	rm -f bin/obi-*.tar.gz
	rm -rf bin/LICENSE bin/NOTICE bin/NOTICES

.PHONY: clean-testoutput
clean-testoutput:
	@echo "### Cleaning ${TEST_OUTPUT} folder"
	rm -rf ${TEST_OUTPUT}/*

.PHONY: protoc-gen
protoc-gen:
	docker run --rm -v $(PWD):/src -w /src $(GEN_IMG) protoc --go_out=pkg/kubecache --go-grpc_out=pkg/kubecache proto/informer.proto

.PHONY: clang-format
clang-format:
	find ./bpf -type f -name "*.c" ! -path "./NOTICES/*" | xargs -P 0 -n 1 clang-format -i
	find ./bpf -type f -name "*.h" ! -path "./NOTICES/*" | xargs -P 0 -n 1 clang-format -i

.PHONY: clean-ebpf-generated-files
clean-ebpf-generated-files:
	find . -name "*_bpfel*" | xargs rm

NOTICES_DIR ?= ./NOTICES

C_LICENSES := $(shell find ./bpf -type f -name 'LICENSE*')
TARGET_C_LICENSES := $(patsubst ./%,$(NOTICES_DIR)/%,$(C_LICENSES))
# BPF code is licensed under the BSD-2-Clause, GPL-2.0-only, or LGPL-2.1 which
# require redistribution of the license and code.
BPF_FILES := $(shell find ./bpf/bpfcore/ -type f )
TARGET_BPF_FILES := $(patsubst ./%,$(NOTICES_DIR)/%,$(BPF_FILES))
TARGET_BPF := $(TARGET_C_LICENSES) $(TARGET_BPF_FILES)

.PHONY: notices-update
notices-update: docker-generate go-notices-update java-notices-update $(TARGET_BPF)

.PHONY: java-notices-update
java-notices-update:
	@echo "### Updating Java dependency notices"
	@mkdir -p $(NOTICES_DIR)/java/agent
	@$(OCI_BIN) run --rm \
		$(if $(findstring podman,$(OCI_BIN)),  ,-u "$(DOCKER_USER)") \
		-e HOME=/tmp \
		-e GRADLE_USER_HOME=/tmp/.gradle \
		-v "$(CURDIR):/src:z" \
		-w /src/pkg/internal/java \
		$(GRADLE_IMAGE) \
		gradle :agent:generateLicenseReport --no-daemon
	# Normalize the non-deterministic generation timestamp footer to keep
	# notices-update/check-clean-work-tree stable across CI runs.
	@awk '{ if ($$0 ~ /^This report was generated at /) print "This report was generated at <normalized>."; else print $$0 }' \
		pkg/internal/java/agent/build/reports/dependency-license/THIRD_PARTY_LICENSES.txt > \
		$(NOTICES_DIR)/java/agent/THIRD_PARTY_LICENSES.txt
	@cp pkg/internal/java/agent/build/reports/dependency-license/THIRD_PARTY_LICENSES.csv $(NOTICES_DIR)/java/agent/

.PHONY: go-notices-update
go-notices-update:
	@GOOS=$(GOOS) GOARCH=amd64 go tool $(TOOLS_MODFILE) go-licenses save ./... --save_path=$(NOTICES_DIR) --force

PYTHON_REQUIREMENTS_INS ?= $(shell find ./internal/test/integration/components -type f -name 'requirements.in' | sort)
PYTHON_REQUIREMENTS_DIRS := $(sort $(dir $(PYTHON_REQUIREMENTS_INS)))
PYTHON_REQUIREMENTS_LOCKS := $(sort $(foreach dir,$(PYTHON_REQUIREMENTS_DIRS),$(wildcard $(dir)requirements.txt $(dir)requirements-*.txt)))
PYTHON_REQUIREMENTS_UPDATE_TARGETS := $(patsubst %,%.update,$(PYTHON_REQUIREMENTS_LOCKS))

.PHONY: python-requirements-update $(PYTHON_REQUIREMENTS_UPDATE_TARGETS)
python-requirements-update: $(PYTHON_REQUIREMENTS_UPDATE_TARGETS)

$(PYTHON_REQUIREMENTS_UPDATE_TARGETS):
	@file="$(patsubst %.update,%,$@)"; \
	file_dir="$$(dirname "$$file")"; \
	file_name="$$(basename "$$file")"; \
	command="$$(sed -n 's/^#    //p' "$$file" | head -n 1)"; \
	python_version="$$(sed -n '2s/^# This file is autogenerated by pip-compile with Python //p' "$$file")"; \
	if [ -z "$$python_version" ]; then \
		case "$$file_name" in \
			requirements-3.9.txt) python_version='3.9' ;; \
			requirements-3.14.txt|requirements.txt) python_version='3.14' ;; \
			*) echo "Unable to determine Python version for $$file"; exit 1 ;; \
		esac; \
	fi; \
	if [ -n "$$command" ]; then \
		command_flags='--generate-hashes'; \
		case "$$command" in \
			*--allow-unsafe*) command_flags="$$command_flags --allow-unsafe" ;; \
		esac; \
		case "$$command" in \
			*--no-strip-extras*) command_flags="$$command_flags --no-strip-extras" ;; \
			*) command_flags="$$command_flags --strip-extras" ;; \
		esac; \
		case "$$python_version" in \
			3.9) image='$(PYTHON39_IMAGE)' ;; \
			3.14) image='$(PYTHON314_IMAGE)' ;; \
			*) echo "Unsupported Python version '$$python_version' for $$file"; exit 1 ;; \
		esac; \
		echo "### Updating $$file"; \
		$(OCI_BIN) run --rm \
			$(if $(findstring podman,$(OCI_BIN)),  ,-u "$(DOCKER_USER)") \
			-e HOME=/tmp \
			-e UV_CACHE_DIR=/tmp/.cache/uv \
			-v "$(CURDIR):/src:z" \
			-w "/src/$$file_dir" \
			"$$image" \
			uv pip compile --quiet $$command_flags -o "$$file_name" requirements.in; \
	fi

$(NOTICES_DIR)/%: %
	@mkdir -p $(dir $@)
	@cp $< $@

.PHONY: check-clean-work-tree
check-clean-work-tree:
	if [ -n "$$(git status --porcelain)" ]; then \
		git status; \
		git --no-pager diff; \
		echo 'Working tree is not clean, did you forget to run "make"?'; \
		exit 1; \
	fi

.PHONY: go-mod-tidy
GO_MOD_FILES := $(shell find . -type f -name 'go.mod' ! -path './NOTICES/*')
GO_MOD_TIDY_TARGETS := $(patsubst %/go.mod,%/.go-mod-tidy,$(GO_MOD_FILES))
GO_MOD_TIDY_117_TARGETS := $(filter %/testserver_1.17/.go-mod-tidy,$(GO_MOD_TIDY_TARGETS))
GO_MOD_TIDY_DEFAULT_TARGETS := $(filter-out $(GO_MOD_TIDY_117_TARGETS),$(GO_MOD_TIDY_TARGETS))
.PHONY: $(GO_MOD_TIDY_TARGETS)
go-mod-tidy: $(GO_MOD_TIDY_TARGETS)

$(GO_MOD_TIDY_DEFAULT_TARGETS):
	@echo "### Running go mod tidy in $(dir $@)"
	@cd "$(dir $@)" && go mod tidy

$(GO_MOD_TIDY_117_TARGETS):
	@echo "### Running go mod tidy -go=1.17 -compat=1.17 in $(dir $@)"
	@cd "$(dir $@)" && go mod tidy -go=1.17 -compat=1.17

.PHONY: check-go-mod
check-go-mod: go-mod-tidy
	@if ! git diff --quiet -- ':(glob)**/go.mod' ':(glob)**/go.sum' ':(exclude,glob)NOTICES/**'; then \
		echo 'go.mod/go.sum files are not clean, did you forget to run "make go-mod-tidy"?'; \
		git --no-pager diff -- ':(glob)**/go.mod' ':(glob)**/go.sum' ':(exclude,glob)NOTICES/**'; \
		exit 1; \
	fi

.PHONY: verify-mods
verify-mods:
	go tool $(TOOLS_MODFILE) multimod verify

.PHONY: prerelease
prerelease: verify-mods
	@[ "${MODSET}" ] || ( echo ">> env var MODSET is not set"; exit 1 )
	go tool $(TOOLS_MODFILE) multimod prerelease -m ${MODSET}

COMMIT ?= "HEAD"
.PHONY: add-tags
add-tags: verify-mods
	@[ "${MODSET}" ] || ( echo ">> env var MODSET is not set"; exit 1 )
	go tool $(TOOLS_MODFILE) multimod tag -m ${MODSET} -c ${COMMIT}

.PHONY: check-ebpf-ver-synced
check-ebpf-ver-synced:
	@if grep -Fq "$(CILIUM_EBPF_PKG) $(CILIUM_EBPF_VER)" go.mod && \
	   grep -Fq "$(CILIUM_EBPF_PKG) $(CILIUM_EBPF_VER)" bpf/bpfcore/placeholder.go; then \
		echo "ebpf lib version in sync"; \
	else \
		echo "ebpf lib version out of sync between go.mod and bpf/bpfcore/placeholder.go!"; \
		exit 1; \
	fi

.PHONY: vanity-import-check
vanity-import-check:
	go tool $(TOOLS_MODFILE) porto --include-internal --skip-dirs "^NOTICES$$" -l . || ( echo "(run: make vanity-import-fix)"; exit 1 )

.PHONY: vanity-import-fix
vanity-import-fix: $(PORTO)
	go tool $(TOOLS_MODFILE) porto --include-internal --skip-dirs "^NOTICES$$" -w .

.PHONY: regenerate-port-lookup
regenerate-port-lookup:
	go run cmd/generate-port-lookup/main.go -dst pkg/internal/netolly/flow/transport/protocol.go
	$(MAKE) fmt

CONFIG_SCHEMA_FILE ?= devdocs/config/config-schema.json
CONFIG_DOCS_FILE ?= devdocs/config/CONFIG.md

.PHONY: generate-config-schema
generate-config-schema:
	@echo "### Generating JSON schema for OBI configuration"
	@mkdir -p $(dir $(CONFIG_SCHEMA_FILE))
	go run ./cmd/obi-schema -output $(CONFIG_SCHEMA_FILE)
	@echo "### Generating configuration reference docs"
	go run ./cmd/config-docs -schema $(CONFIG_SCHEMA_FILE) -output $(CONFIG_DOCS_FILE)

.PHONY: check-config-schema
check-config-schema:
	@echo "### Checking if JSON schema is up-to-date"
	@mkdir -p $(dir $(CONFIG_SCHEMA_FILE))
	@go run ./cmd/obi-schema -output $(CONFIG_SCHEMA_FILE).tmp
	@if ! diff -q $(CONFIG_SCHEMA_FILE) $(CONFIG_SCHEMA_FILE).tmp > /dev/null 2>&1; then \
		echo "JSON schema is out of date. Run 'make generate-config-schema' to update it."; \
		echo "Diff:"; \
		diff $(CONFIG_SCHEMA_FILE) $(CONFIG_SCHEMA_FILE).tmp || true; \
		rm -f $(CONFIG_SCHEMA_FILE).tmp; \
		exit 1; \
	fi
	@rm -f $(CONFIG_SCHEMA_FILE).tmp
	@echo "JSON schema is up-to-date"
	@echo "### Checking if configuration docs are up-to-date"
	@go run ./cmd/config-docs -schema $(CONFIG_SCHEMA_FILE) -output $(CONFIG_DOCS_FILE).tmp
	@if ! diff -q $(CONFIG_DOCS_FILE) $(CONFIG_DOCS_FILE).tmp > /dev/null 2>&1; then \
		echo "Configuration docs are out of date. Run 'make generate-config-schema' to update."; \
		echo "Diff:"; \
		diff $(CONFIG_DOCS_FILE) $(CONFIG_DOCS_FILE).tmp || true; \
		rm -f $(CONFIG_DOCS_FILE).tmp; \
		exit 1; \
	fi
	@rm -f $(CONFIG_DOCS_FILE).tmp
	@echo "Configuration docs are up-to-date"
