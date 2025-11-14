# Main binary configuration
CMD ?= ebpf-instrument
MAIN_GO_FILE ?= cmd/$(CMD)/main.go

CACHE_CMD ?= k8s-cache
CACHE_MAIN_GO_FILE ?= cmd/$(CACHE_CMD)/main.go

GOOS ?= linux
GOARCH ?= amd64

# RELEASE_VERSION will contain the tag name, or the branch name if current commit is not a tag
RELEASE_VERSION := $(shell git describe --all | cut -d/ -f2)
RELEASE_REVISION := $(shell git rev-parse --short HEAD )
BUILDINFO_PKG ?= go.opentelemetry.io/obi/pkg/buildinfo
TEST_OUTPUT ?= ./testoutput

IMG_REGISTRY ?= docker.io
# Set your registry username. CI will set 'otel' but you mustn't use it for manual pushing.
IMG_ORG ?=
IMG_NAME ?= ebpf-instrument

# Container image creation creation
VERSION ?= dev
IMG ?= $(IMG_REGISTRY)/$(IMG_ORG)/$(IMG_NAME):$(VERSION)

# The generator is a container image that provides a reproducible environment for
# building eBPF binaries
GEN_IMG ?= ghcr.io/open-telemetry/obi-generator:0.2.2

OCI_BIN ?= docker

# User to run as in docker images.
DOCKER_USER=$(shell id -u):$(shell id -g)
DEPENDENCIES_DOCKERFILE=./dependencies.Dockerfile

# BPF code generator dependencies
CLANG ?= clang
CFLAGS := -std=gnu17 -O2 -g -Wunaligned-access -Wpacked -Wpadded -Wall -Werror $(CFLAGS)

CLANG_TIDY ?= clang-tidy

CILIUM_EBPF_VER ?= v0.20.0
CILIUM_EBPF_PKG := github.com/cilium/ebpf

# regular expressions for excluded file patterns
EXCLUDE_COVERAGE_FILES="(_bpfel.go)|(/opentelemetry-ebpf-instrumentation/internal/test/)|(/opentelemetry-ebpf-instrumentation/configs/)|(.pb.go)|(/pkg/export/otel/metric/)|(/cmd/obi-genfiles)"

.DEFAULT_GOAL := all

# go-install-tool will 'go install' any package $2 and install it locally to $1.
# This will prevent that they are installed in the $USER/go/bin folder and different
# projects ca have different versions of the tools
PROJECT_DIR := $(shell dirname $(abspath $(firstword $(MAKEFILE_LIST))))

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
TOOLS_MOD_DIR := ./internal/tools

# Tools directory for built tool binaries.
TOOLS = $(CURDIR)/.tools

$(TOOLS):
	@mkdir -p $@
$(TOOLS)/%: $(TOOLS_MOD_DIR)/go.mod | $(TOOLS)
	cd $(TOOLS_MOD_DIR) && \
	go build -o $@ $(PACKAGE)

BPF2GO ?= $(TOOLS)/bpf2go
$(TOOLS)/bpf2go: PACKAGE=github.com/cilium/ebpf/cmd/bpf2go

GOLANGCI_LINT = $(TOOLS)/golangci-lint
$(TOOLS)/golangci-lint: PACKAGE=github.com/golangci/golangci-lint/v2/cmd/golangci-lint

GO_OFFSETS_TRACKER ?= $(TOOLS)/go-offsets-tracker
$(TOOLS)/go-offsets-tracker: PACKAGE=github.com/grafana/go-offsets-tracker/cmd/go-offsets-tracker

GINKGO ?= $(TOOLS)/ginkgo
$(TOOLS)/ginkgo: PACKAGE=github.com/onsi/ginkgo/v2/ginkgo

# Required for k8s-cache unit tests
ENVTEST_K8S_VERSION ?= 1.30.0
ENVTEST ?= $(TOOLS)/setup-envtest
$(TOOLS)/setup-envtest: PACKAGE=sigs.k8s.io/controller-runtime/tools/setup-envtest

KIND ?= $(TOOLS)/kind
$(TOOLS)/kind: PACKAGE=sigs.k8s.io/kind

GOLICENSES = $(TOOLS)/go-licenses
$(TOOLS)/go-licenses: PACKAGE=github.com/google/go-licenses/v2

GOTESTSUM = $(TOOLS)/gotestsum
$(TOOLS)/gotestsum: PACKAGE=gotest.tools/gotestsum

MULTIMOD = $(TOOLS)/multimod
$(TOOLS)/multimod: PACKAGE=go.opentelemetry.io/build-tools/multimod

.PHONY: tools
tools: $(BPF2GO) $(GOLANGCI_LINT) $(GO_OFFSETS_TRACKER) $(GINKGO) $(ENVTEST) $(KIND) $(GOLICENSES) $(GOTESTSUM) $(MULTIMOD)

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
fmt: $(GOLANGCI_LINT)
	@echo "### Formatting code and fixing imports"
	$(GOLANGCI_LINT) fmt

.PHONY: clang-tidy
clang-tidy:
	cd bpf && find . -type f \( -name '*.c' -o -name '*.h' \) ! -path "./bpfcore/*" ! -path "./NOTICES/*" | xargs clang-tidy

.PHONY: lint
lint: $(GOLANGCI_LINT)
	@echo "### Linting code"
	$(GOLANGCI_LINT) run ./... --timeout=6m

MARKDOWNIMAGE := $(shell awk '$$4=="markdown" {print $$2}' $(DEPENDENCIES_DOCKERFILE))
WORKDIR := "/go/src/go.opentelemetry.io/obi"
.PHONY: lint-markdown
lint-markdown:
	@echo "### Linting markdown"
	@docker run --rm -u $(DOCKER_USER) -v "$(CURDIR):$(WORKDIR)" -w "$(WORKDIR)" $(MARKDOWNIMAGE) -c $(WORKDIR)/.markdownlint.yaml $(WORKDIR)/**/*.md

.PHONY: lint-markdown-fix
lint-markdown-fix:
	@echo "### Formatting markdown"
	@docker run --rm -u $(DOCKER_USER) -v "$(CURDIR):$(WORKDIR)" -w "$(WORKDIR)" $(MARKDOWNIMAGE) -c $(WORKDIR)/.markdownlint.yaml --fix $(WORKDIR)/**/*.md

.PHONY: update-offsets
update-offsets: $(GO_OFFSETS_TRACKER)
	@echo "### Updating pkg/internal/goexec/offsets.json"
	$(GO_OFFSETS_TRACKER) -i configs/offsets/tracker_input.json pkg/internal/goexec/offsets.json

.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: export BPF2GO := $(BPF2GO)
generate: $(BPF2GO)
	@echo "### Generating files..."
	@OTEL_EBPF_GENFILES_RUN_LOCALLY=1 go generate cmd/obi-genfiles/obi_genfiles.go

.PHONY: docker-generate
docker-generate:
	@echo "### Generating files (docker)..."
	@OTEL_EBPF_GENFILES_GEN_IMG=$(GEN_IMG) go generate cmd/obi-genfiles/obi_genfiles.go

.PHONY: verify
verify: prereqs lint test license-header-check

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
test: $(ENVTEST)
	@echo "### Testing code"
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" go test -race -a ./... -coverpkg=./... -coverprofile $(TEST_OUTPUT)/cover.all.txt

.PHONY: test-privileged
test-privileged: $(ENVTEST)
	@echo "### Testing code with privileged tests enabled"
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" PRIVILEGED_TESTS=true go test -race -a ./... -coverpkg=./... -coverprofile $(TEST_OUTPUT)/cover.all.txt

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
cleanup-integration-test: $(KIND)
	@echo "### Removing integration test clusters"
	$(KIND) delete cluster -n test-kind-cluster || true
	@echo "### Removing docker containers and images"
	$(eval CONTAINERS := $(shell $(OCI_BIN) ps --format '{{.Names}}' | grep 'integration-'))
	$(if $(strip $(CONTAINERS)),$(OCI_BIN) rm -f $(CONTAINERS),@echo "No integration test containers to remove")
	$(eval IMAGES := $(shell $(OCI_BIN) images --format '{{.Repository}}:{{.Tag}}' | grep 'hatest-'))
	$(if $(strip $(IMAGES)),$(OCI_BIN) rmi -f $(IMAGES),@echo "No integration test images to remove")

.PHONY: run-integration-test
run-integration-test:
	@echo "### Running integration tests"
	go clean -testcache
	go test -p 1 -failfast -v -timeout 60m -a ./internal/test/integration/... --tags=integration

.PHONY: run-integration-test-k8s
run-integration-test-k8s:
	@echo "### Running integration tests"
	go clean -testcache
	go test -p 1 -failfast -v -timeout 60m -a ./internal/test/integration/... --tags=integration_k8s

.PHONY: run-integration-test-vm
run-integration-test-vm:
	@echo "### Running integration tests (pattern: $(TEST_PATTERN))"
	@TEST_TIMEOUT="60m"; \
	TEST_PARALLEL="1"; \
	if [ -f "/precompiled-tests/integration.test" ]; then \
		echo "Using pre-compiled integration tests"; \
		chmod +x /precompiled-tests/integration.test; \
		/precompiled-tests/integration.test \
			-test.parallel=$$TEST_PARALLEL \
			-test.timeout=$$TEST_TIMEOUT \
			-test.failfast \
			-test.v \
			-test.run="^($(TEST_PATTERN))\$$"; \
	else \
		echo "Pre-compiled tests not found, compiling in VM"; \
		$(MAKE) $(GOTESTSUM); \
		$(GOTESTSUM) -ftestname --jsonfile=testoutput/vm-test-run-$(RUN_NUMBER).log -- \
			-p $$TEST_PARALLEL \
			-timeout $$TEST_TIMEOUT \
			-failfast \
			-v -a \
			-tags=integration \
			-run="^($(TEST_PATTERN))\$$" ./internal/test/integration/...; \
	fi

.PHONY: run-integration-test-arm
run-integration-test-arm:
	@echo "### Running integration tests"
	go clean -testcache
	go test -p 1 -failfast -v -timeout 90m -a ./internal/test/integration/... --tags=integration -run "^TestMultiProcess"

.PHONY: integration-test-matrix-json
integration-test-matrix-json:
	@./scripts/generate-integration-matrix.sh "$${TEST_TAGS:-integration}" internal/test/integration "$${PARTITIONS:-5}"

.PHONY: vm-integration-test-matrix-json
vm-integration-test-matrix-json:
	@./scripts/generate-integration-matrix.sh "$${TEST_TAGS:-integration}" internal/test/integration "$${PARTITIONS:-3}" "TestMultiProcess"

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
	# replace the unexpected /src/cmd/ebpf-instrument/main.go file by the module path
	sed 's/^\/src\/cmd\//github.com\/open-telemetry\/opentelemetry-ebpf-instrumentation\/cmd\//' $(TEST_OUTPUT)/itest-covdata.raw.txt > $(TEST_OUTPUT)/itest-covdata.all.txt
	# exclude generated files from coverage data
	grep -vE $(EXCLUDE_COVERAGE_FILES) $(TEST_OUTPUT)/itest-covdata.all.txt > $(TEST_OUTPUT)/itest-covdata.txt

.PHONY: oats-prereq
oats-prereq: $(GINKGO) docker-generate
	mkdir -p $(TEST_OUTPUT)/run

.PHONY: oats-test-sql
oats-test-sql: oats-prereq
	mkdir -p internal/test/oats/sql/$(TEST_OUTPUT)/run
	cd internal/test/oats/sql && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml $(GINKGO) -v -r

.PHONY: oats-test-redis
oats-test-redis: oats-prereq
	mkdir -p internal/test/oats/redis/$(TEST_OUTPUT)/run
	cd internal/test/oats/redis && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml $(GINKGO) -v -r

.PHONY: oats-test-kafka
oats-test-kafka: oats-prereq
	mkdir -p internal/test/oats/kafka/$(TEST_OUTPUT)/run
	cd internal/test/oats/kafka && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml $(GINKGO) -v -r

.PHONY: oats-test-http
oats-test-http: oats-prereq
	mkdir -p internal/test/oats/http/$(TEST_OUTPUT)/run
	cd internal/test/oats/http && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml $(GINKGO) -v -r

.PHONY: oats-test-mongo
oats-test-mongo: oats-prereq
	mkdir -p internal/test/oats/mongo/$(TEST_OUTPUT)/run
	cd internal/test/oats/mongo && TESTCASE_TIMEOUT=5m TESTCASE_BASE_PATH=./yaml $(GINKGO) -v -r

.PHONY: oats-test
oats-test: oats-test-sql oats-test-mongo oats-test-redis oats-test-kafka oats-test-http
	$(MAKE) itest-coverage-data

.PHONY: oats-test-debug
oats-test-debug: oats-prereq
	cd internal/test/oats/kafka && TESTCASE_BASE_PATH=./yaml TESTCASE_MANUAL_DEBUG=true TESTCASE_TIMEOUT=1h $(GINKGO) -v -r

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
artifact: docker-generate compile
	@echo "### Packing generated artifact"
	cp LICENSE ./bin
	cp NOTICE ./bin
	tar -C ./bin -cvzf bin/opentelemetry-ebpf-instrumentation.tar.gz ebpf-instrument LICENSE NOTICE

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
notices-update: docker-generate go-notices-update $(TARGET_BPF)

.PHONY: go-notices-update
go-notices-update: $(GOLICENSES)
	@$(GOLICENSES) save ./... --save_path=$(NOTICES_DIR) --force

$(NOTICES_DIR)/%: %
	@mkdir -p $(dir $@)
	@cp $< $@

.PHONY: check-clean-work-tree
check-clean-work-tree:
	if [ -n "$$(git status --porcelain)" ]; then \
		git status; \
		git --no-pager diff; \
		echo 'Working tree is not clean, did you forget to run "make"?' \
		exit 1; \
	fi

.PHONY: check-go-mod
check-go-mod:
	go mod tidy
	git diff -s --exit-code

.PHONY: verify-mods
verify-mods: $(MULTIMOD)
	$(MULTIMOD) verify

.PHONY: prerelease
prerelease: verify-mods
	@[ "${MODSET}" ] || ( echo ">> env var MODSET is not set"; exit 1 )
	$(MULTIMOD) prerelease -m ${MODSET}

COMMIT ?= "HEAD"
.PHONY: add-tags
add-tags: verify-mods
	@[ "${MODSET}" ] || ( echo ">> env var MODSET is not set"; exit 1 )
	$(MULTIMOD) tag -m ${MODSET} -c ${COMMIT}

.PHONY: check-ebpf-ver-synced
check-ebpf-ver-synced:
	@if grep -Fq "$(CILIUM_EBPF_PKG) $(CILIUM_EBPF_VER)" go.mod && \
	   grep -Fq "$(CILIUM_EBPF_PKG) $(CILIUM_EBPF_VER)" bpf/bpfcore/placeholder.go; then \
		echo "ebpf lib version in sync"; \
	else \
		echo "ebpf lib version out of sync between go.mod and bpf/bpfcore/placeholder.go!"; \
		exit 1; \
	fi
