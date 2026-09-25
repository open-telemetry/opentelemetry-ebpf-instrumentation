// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The netFdRead continuation is a jump table slot no other tracer has. It is
// declared here rather than in one .c file because go_net.c is built both on
// its own, by clang-tidy, and as part of gotracer.c: both need the slot, and
// the slot and its program must come from the same place. Include this before
// anything that pulls in generictracer/k_tracer_tailcall.h
#define OBI_JUMP_TABLE_EXTRA_ENTRIES(entry)                                                        \
    entry(k_tail_continue_netfd_read, obi_continue_netfd_read, struct pt_regs *)
