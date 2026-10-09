ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
SUPPORTED_ARCHES := amd64 arm64
BPF_TARGETS ?= amd64,arm64
comma := ,
ARCHES := $(sort $(subst $(comma), ,$(BPF_TARGETS)))
UNSUPPORTED_ARCHES := $(filter-out $(SUPPORTED_ARCHES),$(ARCHES))
BPF_TARGET_FILE_ARCHES := $(patsubst amd64,x86,$(ARCHES))

ifeq ($(ARCHES),)
$(error BPF_TARGETS is empty; use amd64, arm64, or both)
endif
ifneq ($(UNSUPPORTED_ARCHES),)
$(error Unsupported BPF_TARGETS: $(UNSUPPORTED_ARCHES) (supported: $(SUPPORTED_ARCHES)))
endif

CLANG ?= clang
CFLAGS := -std=gnu17 -O2 -g -Wunaligned-access -Wpacked -Wpadded -Wall -Werror $(CFLAGS)
TOOLS_MODFILE := -modfile=$(ROOT)/internal/tools/go.mod
BPF2GO_WRAPPER := $(ROOT)/.tools/bpf2go
BPF2GO ?= $(BPF2GO_WRAPPER)

$(BPF2GO_WRAPPER):
	@mkdir -p $(dir $@)
	@printf '#!/bin/sh\nexec go tool $(TOOLS_MODFILE) bpf2go "$$@"\n' > $@
	@chmod +x $@

export BPF2GO_MAKEBASE := $(ROOT)
export BPF_CLANG := $(CLANG)
export BPF_CFLAGS := $(CFLAGS)
export BPF2GO

DEPFILES := $(foreach arch,$(BPF_TARGET_FILE_ARCHES),$(shell cd $(ROOT) && find pkg -type f -name '*_$(arch)_bpfel.go.d' 2>/dev/null))
-include $(DEPFILES)

# The .d files name generated Go targets and contain bpf2go's full input graph.
GENERATED_GO := $(patsubst %.go.d,%.go,$(DEPFILES))
GENERATED_OBJECTS := $(GENERATED_GO:.go=.o)
GENERATED_TARGETS := $(GENERATED_GO) $(GENERATED_OBJECTS)
EXISTING_GO := $(foreach arch,$(BPF_TARGET_FILE_ARCHES),$(shell cd $(ROOT) && find pkg -type f -name '*_$(arch)_bpfel.go' 2>/dev/null))
MISSING_DEPFILES := $(filter-out $(GENERATED_GO),$(EXISTING_GO))
MISSING_ARCHES := $(foreach arch,$(BPF_TARGET_FILE_ARCHES),$(if $(shell cd $(ROOT) && find pkg -type f -name '*_$(arch)_bpfel.go' -print -quit),,$(arch)))

define generate_package
	@echo "Generating $(@D) for $(1)..."
	@cd $(ROOT) && BPF_TARGETS=$(1) go generate -run BPF2GO ./$(@D)
endef

.PHONY: generate generate/all
generate: $(BPF2GO)
ifeq ($(strip $(GENERATED_GO)),)
	@$(MAKE) -f $(ROOT)/bpf/Makefile generate/all BPF_TARGETS="$(BPF_TARGETS)"
else ifneq ($(strip $(MISSING_ARCHES)),)
	@$(MAKE) -f $(ROOT)/bpf/Makefile generate/all BPF_TARGETS="$(BPF_TARGETS)"
else ifneq ($(strip $(MISSING_DEPFILES)),)
	@$(MAKE) -f $(ROOT)/bpf/Makefile generate/all BPF_TARGETS="$(BPF_TARGETS)"
else
generate: $(GENERATED_TARGETS)
endif

# A selected architecture with no existing dependency files needs an initial full generation.
$(GENERATED_GO):
	$(if $(findstring _x86_bpfel.go,$@),$(call generate_package,amd64),$(call generate_package,arm64))

$(GENERATED_OBJECTS): %.o: %.go
	@if [ ! -f "$@" ]; then \
	  cd $(ROOT) && BPF_TARGETS=$(if $(findstring _x86_bpfel.o,$@),amd64,arm64) go generate -run BPF2GO ./$(@D); \
	fi

generate/all: $(BPF2GO)
	@echo "Generating all BPF files ($(ARCHES))..."
	@cd $(ROOT) && printf '%s\n' $(ARCHES) | xargs -P $(words $(ARCHES)) -I{} env BPF_TARGETS={} go generate -run BPF2GO ./...
