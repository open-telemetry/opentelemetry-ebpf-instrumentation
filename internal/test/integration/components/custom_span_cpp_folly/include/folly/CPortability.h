// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Minimal stub of folly/CPortability.h sufficient to compile
// folly/tracing/StaticTracepoint.h on Linux. The full folly header pulls
// in significant infrastructure; the only macro StaticTracepoint.h actually
// reads is FOLLY_HAVE_ELF.
#pragma once

#define FOLLY_HAVE_ELF 1
#define FOLLY_NAME_RESOLVABLE
