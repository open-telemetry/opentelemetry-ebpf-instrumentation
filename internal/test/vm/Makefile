WORKDIR ?= $(HOME)

ARCH ?= amd64
ifeq ($(filter $(ARCH),amd64 x86_64),)
  $(error Unsupported ARCH=$(ARCH). Only amd64 is supported; arm64 GH runners lack nested KVM)
endif

KERNEL_ID ?=
KERNEL ?=
# When KERNEL_ID is set and KERNEL is not, the launchvm rule shells out to
# prepare-kernel.sh, which pulls the LVH artifact on cache miss and yields
# the absolute KERNEL/MODULES_DIR paths. CI sets KERNEL/MODULES_DIR
# explicitly in the workflow; local devs can pass either KERNEL_ID alone or
# the full pair.

CGROUP_MODE ?=
# rootfs filename varies by cgroup mode so we can cache/upload both variants.
ROOT_SUFFIX := $(if $(CGROUP_MODE),-$(CGROUP_MODE),)
TARBALL ?= /tmp/rootfs$(ROOT_SUFFIX).tar
# do NOT put ROOT_IMG on a tmpfs backed fs
ROOT_IMG ?= $(WORKDIR)/rootfs$(ROOT_SUFFIX).qcow2
ROOT_IMAGE_RAW ?= $(WORKDIR)/rootfs$(ROOT_SUFFIX).raw
REPO_ROOT ?= ../../..
TARGET_TEST ?= run-integration-test-vm
TEST_PATTERN ?= TestMultiProcess
RUN_NUMBER ?= 1
TEST_OUTPUT = $(REPO_ROOT)/testoutput
MNT ?= mnt
IMG_SIZE ?= 20G
# Map Linux arch names to QEMU binary names.
QEMU_ARCH := $(if $(filter $(ARCH),amd64 x86_64),x86_64,$(if $(filter $(ARCH),arm64 aarch64),aarch64,$(ARCH)))
QEMU_BIN = qemu-system-$(QEMU_ARCH)
QEMU := $(shell which $(QEMU_BIN))
QEMU_MEMORY ?= 8192
PRECOMPILED_TESTS_DIR ?=
# Path to /lib/modules tree for the active LVH kernel. CI populates via
# prepare-kernel.sh; local invocations can rely on that auto-resolution.
MODULES_DIR ?=

.PHONY: all clean launchvm launchvm-run change-owner check_qemu build-rootfs write-test-env

all: launchvm change-owner

build-rootfs: $(ROOT_IMG)

check_qemu:
ifeq ($(QEMU),)
	$(error "$(QEMU_BIN) binary not found. Cannot proceed.")
endif
	@echo "QEMU is available at $(QEMU)"


# Ensure test output directory exists
$(TEST_OUTPUT):
	mkdir -p $(TEST_OUTPUT)

$(ROOT_IMG): Dockerfile
	DOCKER_BUILDKIT=1 docker build --quiet -f Dockerfile \
		--build-arg CGROUP_MODE=$(CGROUP_MODE) \
		--output "type=tar,dest=$(TARBALL)" .
	# Create a raw image, format it, and extract the tarball
	fallocate -l $(IMG_SIZE) $(ROOT_IMAGE_RAW)
	mkfs.ext4 $(ROOT_IMAGE_RAW)
	[ -d $(MNT) ] || mkdir -p $(MNT)
	sudo mount -o loop $(ROOT_IMAGE_RAW) mnt
	sudo tar -xf $(TARBALL) -C $(MNT)
	sync -f $(MNT) && sudo umount -l $(MNT)
	rm -f $(TARBALL) && rmdir $(MNT)
	# Convert the raw image to qcow2 format
	qemu-img convert $(ROOT_IMAGE_RAW) -O qcow2 $(ROOT_IMG) && rm $(ROOT_IMAGE_RAW)

write-test-env: $(TEST_OUTPUT)
	@printf 'target=%s\ntest_pattern=%s\nrun_number=%s\n' \
		"$(TARGET_TEST)" "$(TEST_PATTERN)" "$(RUN_NUMBER)" \
		> $(TEST_OUTPUT)/test-env

launchvm: check_qemu $(ROOT_IMG) $(TEST_OUTPUT) write-test-env
	@RESOLVED_KERNEL="$(KERNEL)"; \
	RESOLVED_MODULES="$(MODULES_DIR)"; \
	if [ -z "$$RESOLVED_KERNEL" ] && [ -n "$(KERNEL_ID)" ]; then \
		echo "Resolving KERNEL_ID=$(KERNEL_ID) ARCH=$(ARCH) via prepare-kernel.sh"; \
		eval "$$(bash prepare-kernel.sh "$(KERNEL_ID)" "$(ARCH)")"; \
		RESOLVED_KERNEL="$$KERNEL"; \
		RESOLVED_MODULES="$$MODULES_DIR"; \
	fi; \
	if [ ! -f "$$RESOLVED_KERNEL" ]; then \
		echo "ERROR: kernel image not found at '$$RESOLVED_KERNEL'" >&2; \
		echo "Set KERNEL=<path> [MODULES_DIR=<path>] ARCH=amd64, OR" >&2; \
		echo "set KERNEL_ID=<id-from-kernels.yaml> ARCH=amd64" >&2; \
		exit 1; \
	fi; \
	export KERNEL="$$RESOLVED_KERNEL"; \
	export MODULES_DIR="$$RESOLVED_MODULES"; \
	$(MAKE) launchvm-run KERNEL="$$KERNEL" MODULES_DIR="$$MODULES_DIR"

launchvm-run:
	@echo "KVM present: $$([ -e /dev/kvm ] && echo yes || echo no)"
	@PRECOMPILED_VIRTFS=""; \
	if [ -n "$(PRECOMPILED_TESTS_DIR)" ] && [ -d "$(PRECOMPILED_TESTS_DIR)" ]; then \
		echo "Starting QEMU with pre-compiled tests from $(PRECOMPILED_TESTS_DIR)"; \
		PRECOMPILED_VIRTFS="-virtfs local,path=$(PRECOMPILED_TESTS_DIR),mount_tag=precompiled,security_model=mapped,id=precompiled"; \
	fi; \
	MODULES_VIRTFS=""; \
	if [ -n "$(MODULES_DIR)" ] && [ -d "$(MODULES_DIR)" ]; then \
		echo "Mounting kernel modules from $(MODULES_DIR)"; \
		MODULES_VIRTFS="-virtfs local,path=$(MODULES_DIR),mount_tag=modules,security_model=mapped,id=modules"; \
	fi; \
	if [ -e /dev/kvm ]; then \
		QEMU_ACCEL="-enable-kvm -cpu host"; \
	else \
		echo "KVM not available, falling back to TCG"; \
		QEMU_ACCEL="-accel tcg,thread=multi -cpu qemu64"; \
	fi; \
	qemu-system-x86_64 $$QEMU_ACCEL -m $(QEMU_MEMORY) -smp 2 -kernel $(KERNEL) \
		-drive file=$(ROOT_IMG),format=qcow2,if=none,id=hd0 \
		-device virtio-blk-pci,drive=hd0 \
		-append "earlyprintk=ttyS0 console=ttyS0 root=/dev/vda rw quiet rcupdate.rcu_cpu_stall_timeout=60 panic=5" \
		-no-reboot \
		-virtfs local,path=$(REPO_ROOT),mount_tag=obi,security_model=mapped,id=obi \
		-virtfs local,path=$(TEST_OUTPUT),mount_tag=testout,security_model=mapped,id=testout \
		$$PRECOMPILED_VIRTFS \
		$$MODULES_VIRTFS \
		-netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
		-nographic

change-owner:
	@current_owner=$$(stat -c '%U' .); \
	chown -R $$current_owner $(TEST_OUTPUT)

clean:
	rm -f $(ROOT_IMG) $(ROOT_IMAGE_RAW) $(TARBALL)
