# Keep `make <task>` working while Mise owns the task definitions.
.DEFAULT_GOAL := __mise

empty :=
space := $(empty) $(empty)
mise_tasks := $(if $(strip $(MAKECMDGOALS)),$(subst $(space), ::: ,$(MAKECMDGOALS)),all)

.PHONY: __mise $(MAKECMDGOALS)

ifneq ($(strip $(MAKECMDGOALS)),)
$(MAKECMDGOALS): __mise
	@:
endif

__mise:
	@if ! command -v mise >/dev/null 2>&1; then \
		echo 'Error: mise is required to run repository tasks.' >&2; \
		echo 'Install mise: https://mise.jdx.dev/installing-mise.html' >&2; \
		exit 127; \
	fi
	@mise run $(mise_tasks)
