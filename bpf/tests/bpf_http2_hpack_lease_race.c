// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>

#include <bpfcore/bpf_helpers.h>

#include <maps/ongoing_http2_connections.h>

_Static_assert(k_ongoing_http2_connections_map_type == BPF_MAP_TYPE_HASH,
               "generation-checked tuple deletion requires a non-LRU map");

typedef struct generation_model {
    uint64_t raw_generation;
    uint64_t state_generation;
    uint64_t lease_generation;
    uint64_t lease_token;
    uint32_t raw_retired;
    uint32_t state_desynced;
    uint32_t lease_poisoned;
    uint32_t dynamic_mutations;
} generation_model_t;

static unsigned int failures;

static void assert_u64(uint64_t want, uint64_t got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr,
            "%s: want %llu, got %llu\n",
            message,
            (unsigned long long)want,
            (unsigned long long)got);
    failures++;
}

static void contender_retire(generation_model_t *model, uint64_t generation) {
    if (model->raw_generation == generation) {
        model->raw_retired = 1;
    }
    if (model->state_generation == generation) {
        model->state_desynced = 1;
    }
    if (model->lease_generation == generation) {
        model->lease_poisoned = 1;
    }
}

static void owner_release(generation_model_t *model, uint64_t generation, uint64_t token) {
    const int owns = model->lease_generation == generation && model->lease_token == token;
    if (!owns) {
        return;
    }
    if (model->lease_poisoned && model->raw_generation == generation) {
        model->raw_retired = 1;
    }
    if ((model->lease_poisoned || (model->raw_generation == generation && model->raw_retired)) &&
        model->state_generation == generation) {
        model->state_generation = 0;
    }
    if (model->raw_generation == generation && model->raw_retired) {
        model->raw_generation = 0;
        model->raw_retired = 0;
    }
    model->lease_generation = 0;
    model->lease_token = 0;
    model->lease_poisoned = 0;
}

static void test_retirement_survives_owner_last_check(void) {
    generation_model_t model = {
        .raw_generation = 1,
        .state_generation = 1,
        .lease_generation = 1,
        .lease_token = 11,
    };

    // Model the formerly failing order: the owner has already observed an
    // unpoisoned lease before the contender publishes retirement.
    const uint32_t stale_poison_snapshot = model.lease_poisoned;
    (void)stale_poison_snapshot;
    contender_retire(&model, 1);
    owner_release(&model, 1, 11);

    assert_u64(0, model.raw_generation, "owner reclaims the logically retired raw generation");
    assert_u64(0, model.state_generation, "owner reclaims exact HPACK state");
    assert_u64(0, model.lease_generation, "owner releases the exact lease");
}

static void test_release_before_retirement_is_still_safe(void) {
    generation_model_t model = {
        .raw_generation = 1,
        .state_generation = 1,
        .lease_generation = 1,
        .lease_token = 11,
    };

    owner_release(&model, 1, 11);
    contender_retire(&model, 1);

    assert_u64(1, model.raw_generation, "late contender leaves the raw slot present");
    assert_u64(1, model.raw_retired, "late contender makes the raw slot non-routable");
}

static void test_delayed_generation_cannot_retire_replacement(void) {
    generation_model_t model = {
        .raw_generation = 2,
        .state_generation = 2,
        .lease_generation = 2,
        .lease_token = 22,
    };

    contender_retire(&model, 1);

    assert_u64(2, model.raw_generation, "stale A retirement preserves raw B");
    assert_u64(0, model.raw_retired, "stale A retirement cannot mark B retired");
    assert_u64(2, model.state_generation, "stale A retirement preserves state B");
}

static void test_nonowner_poison_only_sets_monotonic_flags(void) {
    generation_model_t model = {
        .raw_generation = 1,
        .state_generation = 1,
        .lease_generation = 1,
        .lease_token = 11,
        .dynamic_mutations = 7,
    };

    contender_retire(&model, 1);

    assert_u64(1, model.raw_retired, "nonowner publishes raw retirement");
    assert_u64(1, model.state_desynced, "nonowner publishes state desync");
    assert_u64(7, model.dynamic_mutations, "nonowner never mutates dynamic-table fields");
}

int main(void) {
    test_retirement_survives_owner_last_check();
    test_release_before_retirement_is_still_safe();
    test_delayed_generation_cannot_retire_replacement();
    test_nonowner_poison_only_sets_monotonic_flags();

    if (failures) {
        fprintf(stderr, "%u test(s) failed\n", failures);
        return 1;
    }
    return 0;
}
