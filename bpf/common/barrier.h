// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif
