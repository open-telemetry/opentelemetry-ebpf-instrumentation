// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Default values that can be overridden at runtime and are needed to compile OBI
// because max_entries field in a map must be compile-time constant
#define MAX_CONCURRENT_REQUESTS 10000 // 10000 requests per second max for a single traced process
// 10 * MAX_CONCURRENT_REQUESTS total ongoing requests, for maps shared among multiple tracers, e.g. pinned maps
#define MAX_CONCURRENT_SHARED_REQUESTS 30000
#define MAX_CONCURRENT_CUSTOM_SPANS 1000 // 1000 custom spans should be rare across monitored apps

// Memory-BIO TLS correlation maps: one entry per live TLS connection, so they
// sit well below the limits above. All three are LRU, so an underestimate costs
// correlation on the oldest connections while updates keep succeeding.
#define MAX_CONCURRENT_TLS_CONNECTIONS 4096
// A connection names a read BIO and a write BIO.
#define MAX_CONCURRENT_TLS_BIOS (MAX_CONCURRENT_TLS_CONNECTIONS * 2)
