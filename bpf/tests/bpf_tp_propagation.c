// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

static inline long bpf_loop(unsigned int nr_loops,
                            int (*callback_fn)(unsigned int, void *),
                            void *callback_ctx,
                            unsigned long long flags) {
    (void)flags;

    for (unsigned int i = 0; i < nr_loops; i++) {
        if (callback_fn(i, callback_ctx)) {
            break;
        }
    }

    return 0;
}

#include <common/http_types.h>
#include <common/event_defs.h>
#include <common/sampling_decision.h>
#include <common/sampling_math.h>
#include <common/trace_util.h>
#include <generictracer/http1_sampling.h>
#include <tpinjector/tp_options.h>

static unsigned int failures;

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void assert_bytes(const void *want, const void *got, size_t len, const char *message) {
    if (memcmp(want, got, len) == 0) {
        return;
    }
    fprintf(stderr, "%s: byte sequences differ\n", message);
    failures++;
}

static tp_info_t test_traceparent(u8 flags) {
    tp_info_t tp = {.flags = flags};
    for (u8 i = 0; i < TRACE_ID_SIZE_BYTES; i++) {
        tp.trace_id[i] = i + 1;
    }
    for (u8 i = 0; i < SPAN_ID_SIZE_BYTES; i++) {
        tp.span_id[i] = i + 17;
    }
    return tp;
}

static void test_old_writer_to_new_reader(void) {
    const tp_info_t written = test_traceparent(k_flag_sampled);
    otel_tcp_option_t legacy = {};
    make_otel_tcp_option(&legacy, &written);

    otel_tcp_extended_option_t read = {};
    memcpy(&read, &legacy, sizeof(legacy));

    assert_bool(k_tcp_option_otel_legacy_len, legacy.len, "legacy option length");
    assert_bytes(written.trace_id, legacy.trace_id, sizeof(legacy.trace_id), "legacy trace ID");
    assert_bytes(written.span_id, legacy.span_id, sizeof(legacy.span_id), "legacy span ID");
    assert_bool(
        1, valid_otel_tcp_option(&read, sizeof(legacy)), "new reader accepts legacy option");
    assert_bool(
        k_flag_sampled, otel_tcp_flags(&read, sizeof(legacy)), "legacy option implies sampled");
}

static void test_sampled_new_writer_to_old_reader(void) {
    tp_info_t written = test_traceparent(k_flag_sampled);
    new_trace_id(&written);
    otel_tcp_option_t legacy = {};
    make_otel_tcp_option(&legacy, &written);

    assert_bool(
        k_flag_sampled | k_flag_random, written.flags, "sampled root carries random trace flag");
    assert_bool(k_tcp_option_otel_legacy_len, legacy.len, "new legacy option length");
    assert_bool(1, use_otel_tcp_legacy_option(&written), "sampled root stays legacy");
    assert_bool(k_tcp_option_otel_legacy_len,
                otel_tcp_option_wire_len(&written),
                "sampled root wire length");
    assert_bytes(written.trace_id, legacy.trace_id, sizeof(legacy.trace_id), "old reader trace ID");
    assert_bytes(written.span_id, legacy.span_id, sizeof(legacy.span_id), "old reader span ID");
    assert_bool(1,
                valid_otel_tcp_legacy_option(&legacy, sizeof(legacy)),
                "old reader accepts sampled option");
}

static void test_unsampled_new_writer_to_new_reader(void) {
    const tp_info_t written = test_traceparent(0);
    otel_tcp_extended_option_t extended = {};
    make_otel_tcp_extended_option(&extended, &written);

    assert_bool(k_tcp_option_otel_extended_len, extended.legacy.len, "extended option length");
    assert_bytes(written.trace_id,
                 extended.legacy.trace_id,
                 sizeof(extended.legacy.trace_id),
                 "extended trace ID");
    assert_bytes(written.span_id,
                 extended.legacy.span_id,
                 sizeof(extended.legacy.span_id),
                 "extended span ID");
    assert_bool(1,
                valid_otel_tcp_option(&extended, sizeof(extended)),
                "new reader accepts extended option");
    assert_bool(
        0, otel_tcp_flags(&extended, sizeof(extended)), "new reader uses explicit unsampled flag");
}

static void test_unsampled_new_writer_is_rejected_by_old_reader(void) {
    const tp_info_t written = test_traceparent(0);
    otel_tcp_extended_option_t extended = {};
    make_otel_tcp_extended_option(&extended, &written);

    assert_bool(0,
                valid_otel_tcp_legacy_option(&extended.legacy, sizeof(extended)),
                "old reader rejects extended option");
}

static void test_random_flags_wire_compatibility(void) {
    enum { k_timestamp_connection_option_budget = 28 };

    const tp_info_t unsampled = test_traceparent(k_flag_random);
    assert_bool(
        0, use_otel_tcp_legacy_option(&unsampled), "unsampled random flags require extension");
    assert_bool(k_tcp_option_otel_extended_len,
                otel_tcp_option_wire_len(&unsampled),
                "unsampled random flags wire length");

    const tp_info_t sampled = test_traceparent(k_flag_sampled | k_flag_random);
    assert_bool(1, use_otel_tcp_legacy_option(&sampled), "sampled context stays legacy");
    assert_bool(k_tcp_option_otel_legacy_len,
                otel_tcp_option_wire_len(&sampled),
                "sampled context wire length");
    otel_tcp_extended_option_t extended = {};
    make_otel_tcp_extended_option(&extended, &unsampled);
    assert_bool(k_flag_random,
                otel_tcp_flags(&extended, sizeof(extended)),
                "unsampled random flag survives TCP propagation");

    assert_bool(1,
                otel_tcp_option_wire_len(&unsampled) <= k_timestamp_connection_option_budget,
                "extended flags fit timestamp budget");
    assert_bool(1,
                otel_tcp_option_wire_len(&sampled) <= k_timestamp_connection_option_budget,
                "legacy sampled flags fit timestamp budget");
}

static void test_tcp_option_budget(void) {
    enum { k_timestamp_connection_option_budget = 28 };

    const tp_info_t sampled = test_traceparent(k_flag_sampled);
    const tp_info_t unsampled = test_traceparent(0);

    assert_bool(
        k_tcp_option_otel_legacy_len, otel_tcp_option_wire_len(&sampled), "sampled wire length");
    assert_bool(k_tcp_option_otel_extended_len,
                otel_tcp_option_wire_len(&unsampled),
                "unsampled wire length");
    assert_bool(1,
                otel_tcp_option_wire_len(&sampled) <= k_timestamp_connection_option_budget,
                "sampled option fits timestamp budget");
    assert_bool(1,
                otel_tcp_option_wire_len(&unsampled) <= k_timestamp_connection_option_budget,
                "unsampled option fits timestamp budget");
}

static void
assert_traceparent_flags(const char *want, u8 initial_flags, u8 sampled, const char *message) {
    tp_info_t tp = test_traceparent(initial_flags);
    unsigned char encoded[FLAGS_CHAR_LEN] = {};

    apply_sampler_result(&tp, sampled);
    encode_traceparent_flags(encoded, tp.flags);

    assert_bytes(want, encoded, sizeof(encoded), message);
    assert_bool(1, tp.sampling_decision, "sampling decision marker");
}

static void test_always_on_disagreement(void) {
    assert_traceparent_flags(
        "03", k_flag_random, 1, "always-on preserves random flag in unsampled header");
}

static void test_always_off_disagreement(void) {
    assert_traceparent_flags("02",
                             k_flag_sampled | k_flag_random,
                             0,
                             "always-off preserves random flag in sampled header");
}

static void test_reserved_flags_are_cleared(void) {
    assert_traceparent_flags("03", 0x06, 1, "always-on clears reserved trace flags on the wire");
    assert_traceparent_flags("02", 0x07, 0, "always-off clears reserved trace flags on the wire");

    unsigned char encoded[FLAGS_CHAR_LEN] = {};
    encode_traceparent_flags(encoded, 0x84);
    assert_bytes("00", encoded, sizeof(encoded), "encoding clears unsupported trace flags");
}

static void test_ratio_disagreement(void) {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES] = {};
    const u64 threshold = UINT64_C(1) << 62;

    trace_id[15] = 2;
    assert_traceparent_flags("01",
                             0,
                             sampler_trace_id_ratio(trace_id, threshold),
                             "ratio rewrites unsampled header below threshold");

    const u64 encoded = threshold << 1;
    for (u8 i = 0; i < sizeof(encoded); i++) {
        trace_id[TRACE_ID_SIZE_BYTES - 1 - i] = (unsigned char)(encoded >> (i * 8));
    }
    assert_traceparent_flags("00",
                             k_flag_sampled,
                             sampler_trace_id_ratio(trace_id, threshold),
                             "ratio rewrites sampled header at threshold");
}

static void test_traceparent_validation(void) {
    unsigned char value[] = "00-0102030405060708090a0b0c0d0e0f10-0102030405060708-03";

    assert_bool(1, valid_traceparent_value(value), "valid traceparent value");

    value[3] = 'z';
    assert_bool(0, valid_traceparent_value(value), "invalid trace ID hex");
    value[3] = '0';

    memset(value + 3, '0', TRACE_ID_CHAR_LEN);
    assert_bool(0, valid_traceparent_value(value), "zero trace ID");
    memcpy(value + 3, "0102030405060708090a0b0c0d0e0f10", TRACE_ID_CHAR_LEN);

    memset(value + 36, '0', SPAN_ID_CHAR_LEN);
    assert_bool(0, valid_traceparent_value(value), "zero span ID");
    memcpy(value + 36, "0102030405060708", SPAN_ID_CHAR_LEN);

    value[53] = 'z';
    assert_bool(0, valid_traceparent_value(value), "invalid flags hex");
    value[53] = '0';

    value[0] = 'f';
    value[1] = 'f';
    assert_bool(0, valid_traceparent_value(value), "forbidden version");

    value[0] = '0';
    value[1] = '0';
    value[3] = 'A';
    assert_bool(0, valid_traceparent_value(value), "uppercase hex");
}

static void test_http_traceparent_validation(void) {
    unsigned char header[] =
        "Traceparent: 00-0102030405060708090a0b0c0d0e0f10-0102030405060708-03\r\n";
    unsigned char *value = header + 13;

    assert_bool(1, valid_http_traceparent_header(header), "valid v00 HTTP traceparent");
    assert_bool(
        1, valid_http_traceparent_value(value, '\r'), "valid v00 net/http line traceparent");
    assert_bool(1, valid_traceparent_value_length(value, 55), "valid v00 fixed-length traceparent");
    assert_bool(k_flag_random,
                traceparent_flags_for_version(value, 0x86),
                "v00 keeps supported trace flags");

    header[TRACE_PARENT_HEADER_LEN] = 'x';
    assert_bool(0, valid_http_traceparent_header(header), "v00 rejects a value suffix");
    assert_bool(
        0, valid_http_traceparent_value(value, 'x'), "v00 net/http line rejects a value suffix");
    assert_bool(0, valid_traceparent_value_length(value, 56), "v00 rejects an extended value");

    header[TRACE_PARENT_HEADER_LEN] = '\r';
    header[TRACE_PARENT_HEADER_LEN + 1] = 'x';
    assert_bool(0, valid_http_traceparent_header(header), "HTTP traceparent requires final LF");
    header[TRACE_PARENT_HEADER_LEN + 1] = '\n';

    header[0] = 'T';
    header[13] = '0';
    header[14] = '1';
    header[TRACE_PARENT_HEADER_LEN] = 'x';
    assert_bool(
        0, valid_http_traceparent_header(header), "higher version rejects a non-delimited suffix");
    assert_bool(0,
                valid_http_traceparent_value(value, 'x'),
                "higher version net/http line rejects a non-delimited suffix");
    assert_bool(1,
                valid_http_traceparent_value(value, '\r'),
                "higher version net/http line accepts its fixed base");
    assert_bool(
        1, valid_traceparent_value_length(value, 55), "higher version accepts its fixed base");
    value[53] = '8';
    value[54] = '5';
    assert_bool(k_flag_sampled,
                traceparent_flags_for_version(value, 0x85),
                "higher version ignores unsupported trace flags");
    value[53] = '0';
    value[54] = '3';

    header[TRACE_PARENT_HEADER_LEN] = '-';
    assert_bool(0,
                valid_http_traceparent_header(header),
                "fixed HTTP traceparent header rejects an unbounded extension");
    assert_bool(1,
                valid_http_traceparent_value(value, '-'),
                "higher version net/http line accepts a delimited extension");
    assert_bool(1,
                valid_traceparent_value_length(value, 56),
                "higher version accepts a delimited extension");

    const unsigned char no_ows[k_http1_split_traceparent_min_len] =
        "Traceparent:00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r\n";
    const unsigned char one_ows[] =
        "Traceparent:\t00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r\n";
    const unsigned char two_ows[] =
        "Traceparent: \t00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r\n";
    assert_bool(
        12, http_traceparent_value_offset(no_ows), "HTTP traceparent accepts no whitespace");
    assert_bool(13, http_traceparent_value_offset(one_ows), "HTTP traceparent accepts one tab");
    assert_bool(
        14, http_traceparent_value_offset(two_ows), "HTTP traceparent accepts mixed whitespace");
}

static void test_split_http_traceparent_adoption(void) {
    unsigned char header[] =
        "Traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-03\r\n";
    const unsigned char trace_id[TRACE_ID_SIZE_BYTES] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const unsigned char parent_id[SPAN_ID_SIZE_BYTES] = {17, 18, 19, 20, 21, 22, 23, 24};
    tp_info_t tp = {
        .span_id = {31},
        .sampling_decision = k_sampling_decision_applied,
    };

    assert_bool(1,
                http1_adopt_split_server_traceparent(&tp, header, sizeof(header) - 1),
                "adopt split Traceparent");
    assert_bytes(trace_id, tp.trace_id, sizeof(trace_id), "split Traceparent trace ID");
    assert_bytes(parent_id, tp.parent_id, sizeof(parent_id), "split Traceparent parent ID");
    assert_bool(31, tp.span_id[0], "split Traceparent preserves server span ID");
    assert_bool(k_flag_sampled | k_flag_random,
                tp.flags,
                "split Traceparent preserves supported v00 flags");
    assert_bool(k_sampling_decision_pending,
                tp.sampling_decision,
                "split Traceparent requires a new server decision");

    header[13] = '0';
    header[14] = '1';
    header[66] = '8';
    header[67] = '5';
    assert_bool(1,
                http1_adopt_split_server_traceparent(&tp, header, sizeof(header) - 1),
                "adopt future-version split Traceparent");
    assert_bool(
        k_flag_sampled, tp.flags, "future-version split Traceparent masks unsupported flags");

    const tp_info_t original = tp;
    header[69] = 'x';
    assert_bool(0,
                http1_adopt_split_server_traceparent(&tp, header, sizeof(header) - 1),
                "reject split Traceparent without CRLF");
    assert_bytes(&original, &tp, sizeof(tp), "invalid split Traceparent leaves state unchanged");
}

static void test_split_http_traceparent_adoption_variants(void) {
    const unsigned char trailing_headers[] =
        "Traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r\n"
        "User-Agent: test\r\n\r\n";
    const unsigned char no_ows[] =
        "Traceparent:00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r\n";
    const unsigned char tab_ows[] =
        "Traceparent:\t00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r\n";
    const unsigned char mixed_ows[] =
        "Traceparent: \t00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r\n";
    const unsigned char eight_ows[k_http1_split_traceparent_max_len] =
        "Traceparent:"
        "        "
        "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r\n";
    const unsigned char nine_ows[] = "Traceparent:"
                                     "        "
                                     " 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r\n";
    const unsigned char truncated_one_ows[k_http1_split_traceparent_min_len] =
        "Traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r";
    const unsigned char trace_id[TRACE_ID_SIZE_BYTES] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const unsigned char parent_id[SPAN_ID_SIZE_BYTES] = {17, 18, 19, 20, 21, 22, 23, 24};
    tp_info_t tp = {};

    assert_bool(1,
                http1_adopt_split_server_traceparent(
                    &tp, trailing_headers, k_http1_split_traceparent_max_len),
                "split Traceparent accepts trailing headers");
    assert_bool(1,
                http1_adopt_split_server_traceparent(&tp, no_ows, sizeof(no_ows)),
                "split Traceparent accepts no optional whitespace");
    assert_bool(1,
                http1_adopt_split_server_traceparent(&tp, tab_ows, sizeof(tab_ows) - 1),
                "split Traceparent accepts tab whitespace");
    assert_bool(1,
                http1_adopt_split_server_traceparent(&tp, mixed_ows, sizeof(mixed_ows) - 1),
                "split Traceparent accepts mixed whitespace");
    assert_bool(1,
                http1_adopt_split_server_traceparent(&tp, eight_ows, sizeof(eight_ows)),
                "split Traceparent accepts the maximum optional whitespace");
    assert_bytes(trace_id, tp.trace_id, sizeof(trace_id), "variant split Traceparent trace ID");
    assert_bytes(parent_id, tp.parent_id, sizeof(parent_id), "variant split Traceparent parent ID");

    const tp_info_t original = tp;
    assert_bool(
        0,
        http1_adopt_split_server_traceparent(&tp, nine_ows, k_http1_split_traceparent_max_len),
        "split Traceparent rejects excessive optional whitespace");
    assert_bytes(&original, &tp, sizeof(tp), "excess whitespace leaves state unchanged");
    assert_bool(
        0,
        http1_adopt_split_server_traceparent(&tp, truncated_one_ows, sizeof(truncated_one_ows)),
        "split Traceparent rejects a truncated CRLF");
    assert_bytes(&original, &tp, sizeof(tp), "truncated split Traceparent leaves state unchanged");
}

static void test_split_http_traceparent_adoption_eligibility(void) {
    const u32 split_len = TRACE_PARENT_HEADER_LEN + 2;
    unsigned char scan_buf[TRACE_BUF_SIZE] = {};
    scan_buf[k_http1_legacy_scan_loops - 1] = '\n';

    assert_bool(1,
                http1_can_adopt_client_handoff(EVENT_HTTP_CLIENT),
                "client requests can adopt an outgoing handoff");
    assert_bool(0,
                http1_can_adopt_client_handoff(EVENT_HTTP_REQUEST),
                "server requests cannot adopt an outgoing handoff");

    assert_bool(1,
                http1_scan_fully_observed(
                    scan_buf, k_http1_legacy_scan_loops, k_http1_legacy_scan_loops, 0),
                "legacy scan can arm only after observing its full line-bounded buffer");
    assert_bool(0,
                http1_scan_fully_observed(
                    scan_buf, k_http1_legacy_scan_loops, k_http1_legacy_scan_loops + 1, 0),
                "legacy scan never arms when bytes extend past its scan window");
    scan_buf[k_http1_legacy_scan_loops - 1] = 'x';
    assert_bool(0,
                http1_scan_fully_observed(
                    scan_buf, k_http1_legacy_scan_loops, k_http1_legacy_scan_loops, 0),
                "unfinished header lines never arm continuation parsing");
    scan_buf[TRACE_BUF_SIZE - 2] = '\n';
    assert_bool(1,
                http1_scan_fully_observed(scan_buf, TRACE_BUF_SIZE - 1, TRACE_BUF_SIZE - 1, 1),
                "full scanner can arm after a complete bounded buffer");
    assert_bool(0,
                http1_scan_fully_observed(scan_buf, TRACE_BUF_SIZE - 1, TRACE_BUF_SIZE, 1),
                "full scanner never arms after input truncation");

    assert_bool(k_http1_split_traceparent_server,
                http1_split_traceparent_role(EVENT_HTTP_REQUEST, TCP_RECV, 1, split_len),
                "expected server fragment can adopt a split Traceparent");
    assert_bool(k_http1_split_traceparent_client,
                http1_split_traceparent_role(EVENT_HTTP_CLIENT, TCP_SEND, 1, split_len),
                "expected client fragment can adopt a split Traceparent");
    assert_bool(k_http1_split_traceparent_none,
                http1_split_traceparent_role(EVENT_HTTP_REQUEST, TCP_SEND, 1, split_len),
                "server response cannot adopt a split Traceparent");
    assert_bool(k_http1_split_traceparent_none,
                http1_split_traceparent_role(EVENT_HTTP_REQUEST, TCP_RECV, 0, split_len),
                "unarmed server body cannot adopt a split Traceparent");
    assert_bool(k_http1_split_traceparent_server,
                http1_split_traceparent_role(EVENT_HTTP_REQUEST, TCP_RECV, 1, split_len + 1),
                "server fragment with trailing data can adopt a split Traceparent");
    assert_bool(k_http1_split_traceparent_server,
                http1_split_traceparent_role(
                    EVENT_HTTP_REQUEST, TCP_RECV, 1, k_http1_split_traceparent_min_len),
                "minimum server fragment can adopt a split Traceparent");
    assert_bool(k_http1_split_traceparent_none,
                http1_split_traceparent_role(
                    EVENT_HTTP_REQUEST, TCP_RECV, 1, k_http1_split_traceparent_min_len - 1),
                "short server fragment cannot adopt a split Traceparent");
    assert_bool(k_http1_split_traceparent_none,
                http1_split_traceparent_role(EVENT_HTTP_REQUEST, TCP_RECV, 1, -1),
                "negative server fragment length cannot adopt a split Traceparent");
    assert_bool(1,
                http1_expect_split_traceparent(k_http1_traceparent_scan_unknown, 1),
                "an incomplete initial scan arms the immediate next fragment");
    assert_bool(0,
                http1_expect_split_traceparent(k_http1_traceparent_scan_absent, 1),
                "a complete header block never arms body adoption");
    assert_bool(0,
                http1_expect_split_traceparent(k_http1_traceparent_scan_unknown, 0),
                "a failed or truncated scan never enables continuation parsing");
}

static void test_split_http_client_traceparent_adoption(void) {
    const unsigned char header[] =
        "Traceparent: 00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01\r\n";
    const unsigned char trace_id[TRACE_ID_SIZE_BYTES] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const unsigned char span_id[SPAN_ID_SIZE_BYTES] = {17, 18, 19, 20, 21, 22, 23, 24};
    const unsigned char zero_parent[SPAN_ID_SIZE_BYTES] = {};
    tp_info_t tp = {
        .parent_id = {31},
        .parent_remote = 1,
        .sampling_decision = k_sampling_decision_pending,
    };

    assert_bool(1,
                http1_adopt_split_client_traceparent(&tp, header, sizeof(header) - 1),
                "adopt split client Traceparent");
    assert_bytes(trace_id, tp.trace_id, sizeof(trace_id), "split client Traceparent trace ID");
    assert_bytes(span_id, tp.span_id, sizeof(span_id), "split client Traceparent span ID");
    assert_bytes(zero_parent,
                 tp.parent_id,
                 sizeof(zero_parent),
                 "split client Traceparent clears parent ID");
    assert_bool(0, tp.parent_remote, "split client Traceparent is not a remote parent");
    assert_bool(k_sampling_decision_applied,
                tp.sampling_decision,
                "split client Traceparent preserves wire sampling");
}

static void test_new_trace_id_sets_random_flag(void) {
    tp_info_t unsampled = {};
    new_trace_id(&unsampled);
    assert_bool(k_flag_random, unsampled.flags, "unsampled root random flag");

    tp_info_t sampled = {.flags = k_flag_sampled};
    new_trace_id(&sampled);
    assert_bool(k_flag_sampled | k_flag_random, sampled.flags, "sampled root random flag");
}

static tp_info_pid_t test_outbound_candidate(u8 sampling_decision) {
    tp_info_pid_t candidate = {
        .pid = 42,
        .valid = 1,
        .written = 1,
        .req_type = EVENT_HTTP_CLIENT,
    };
    candidate.tp = test_traceparent(k_flag_random);
    candidate.tp.sampling_decision = sampling_decision;
    for (u8 i = 0; i < SPAN_ID_SIZE_BYTES; i++) {
        candidate.tp.parent_id[i] = i + 33;
    }
    return candidate;
}

static void test_preserve_outbound_traceparent(void) {
    tp_info_t tp = test_traceparent(0x85);
    tp.sampling_decision = k_sampling_decision_pending;
    tp.parent_remote = 1;
    const tp_info_t original = tp;

    preserve_outbound_traceparent(&tp);

    assert_bytes(original.trace_id, tp.trace_id, sizeof(tp.trace_id), "preserve trace ID");
    assert_bytes(original.span_id, tp.span_id, sizeof(tp.span_id), "preserve span ID");
    assert_bool(original.flags, tp.flags, "preserve trace flags");
    assert_bool(k_sampling_decision_applied,
                tp.sampling_decision,
                "preserve makes wire flags authoritative");
    assert_bool(0, tp.parent_remote, "outbound Traceparent is not a remote parent");
}

static void test_commit_outbound_traceparent(void) {
    tp_info_t tp = test_traceparent(0x84);
    tp.sampling_decision = k_sampling_decision_pending;

    commit_outbound_traceparent(&tp);

    assert_bool(0x84, tp.flags, "commit preserves full trace flags");
    assert_bool(k_sampling_decision_pending,
                tp.sampling_decision,
                "commit preserves a pending sampling decision");
}

static void test_adopt_outbound_traceparent(void) {
    tp_info_t tp = {};
    tp_info_pid_t candidate = test_outbound_candidate(0);

    assert_bool(1,
                adopt_outbound_traceparent(&tp, &candidate, 42, EVENT_HTTP_CLIENT),
                "adopt matching outbound traceparent");
    assert_bytes(candidate.tp.trace_id, tp.trace_id, sizeof(tp.trace_id), "adopt trace ID");
    assert_bytes(candidate.tp.span_id, tp.span_id, sizeof(tp.span_id), "adopt span ID");
    assert_bytes(candidate.tp.parent_id, tp.parent_id, sizeof(tp.parent_id), "adopt parent ID");
    assert_bool(candidate.tp.flags, tp.flags, "adopt trace flags");
    assert_bool(k_sampling_decision_pending,
                tp.sampling_decision,
                "adopt preserves a pending OBI decision");

    candidate.tp.sampling_decision = 1;
    assert_bool(1,
                adopt_outbound_traceparent(&tp, &candidate, 42, EVENT_HTTP_CLIENT),
                "adopt authoritative outbound traceparent");
    assert_bool(1, tp.sampling_decision, "adopt authoritative decision");
}

static void test_reject_invalid_outbound_traceparent(void) {
    tp_info_t tp = test_traceparent(k_flag_sampled);
    tp_info_pid_t candidate = test_outbound_candidate(1);

    assert_bool(0,
                adopt_outbound_traceparent(&tp, NULL, 42, EVENT_HTTP_CLIENT),
                "reject missing outbound traceparent");

    candidate.valid = 0;
    assert_bool(0,
                adopt_outbound_traceparent(&tp, &candidate, 42, EVENT_HTTP_CLIENT),
                "reject invalid outbound traceparent");
    candidate.valid = 1;

    candidate.written = 0;
    assert_bool(0,
                adopt_outbound_traceparent(&tp, &candidate, 42, EVENT_HTTP_CLIENT),
                "reject unwritten outbound traceparent");
    candidate.written = 1;

    assert_bool(0,
                adopt_outbound_traceparent(&tp, &candidate, 43, EVENT_HTTP_CLIENT),
                "reject outbound traceparent from another process");
    assert_bool(0,
                adopt_outbound_traceparent(&tp, &candidate, 42, EVENT_GRPC_CLIENT),
                "reject outbound traceparent for another request type");

    memset(candidate.tp.trace_id, 0, sizeof(candidate.tp.trace_id));
    assert_bool(0,
                adopt_outbound_traceparent(&tp, &candidate, 42, EVENT_HTTP_CLIENT),
                "reject outbound traceparent with zero trace ID");
}

static void test_outbound_traceparent_state_is_exact(void) {
    tp_info_pid_t candidate = test_outbound_candidate(1);

    candidate.written = k_outbound_trace_pending;
    assert_bool(
        1,
        outbound_traceparent_matches(&candidate, 42, EVENT_HTTP_CLIENT, k_outbound_trace_pending),
        "match pending outbound state");
    assert_bool(
        0,
        outbound_traceparent_matches(&candidate, 42, EVENT_HTTP_CLIENT, k_outbound_trace_written),
        "pending state is not written");

    candidate.written = k_outbound_trace_written;
    assert_bool(
        1,
        outbound_traceparent_matches(&candidate, 42, EVENT_HTTP_CLIENT, k_outbound_trace_written),
        "match written outbound state");
    assert_bool(
        0,
        outbound_traceparent_matches(&candidate, 42, EVENT_HTTP_CLIENT, k_outbound_trace_pending),
        "written state is not pending");

    candidate.written = 2;
    assert_bool(
        0,
        outbound_traceparent_matches(&candidate, 42, EVENT_HTTP_CLIENT, k_outbound_trace_pending),
        "reject corrupt pending state");
    assert_bool(
        0,
        outbound_traceparent_matches(&candidate, 42, EVENT_HTTP_CLIENT, k_outbound_trace_written),
        "reject corrupt written state");

    candidate.written = k_outbound_trace_written;
    candidate.valid = 2;
    assert_bool(
        0,
        outbound_traceparent_matches(&candidate, 42, EVENT_HTTP_CLIENT, k_outbound_trace_written),
        "reject noncanonical valid state");
}

static void test_restore_outbound_traceparent_flags(void) {
    tp_info_t tp = test_traceparent(k_flag_sampled | k_flag_random);
    for (u8 i = 0; i < SPAN_ID_SIZE_BYTES; i++) {
        tp.parent_id[i] = i + 33;
    }
    tp.sampling_decision = k_sampling_decision_pending;
    const tp_info_t rewritten = tp;

    restore_outbound_traceparent_flags(&tp, 0x86);

    assert_bytes(rewritten.span_id, tp.span_id, sizeof(tp.span_id), "retain rewritten span ID");
    assert_bytes(
        rewritten.parent_id, tp.parent_id, sizeof(tp.parent_id), "retain rewritten parent ID");
    assert_bool(k_flag_random, tp.flags, "restore supported original trace flags");
    assert_bool(k_sampling_decision_pending,
                tp.sampling_decision,
                "restored wire flags preserve a pending sampling decision");
}

static void test_restore_outbound_traceparent(void) {
    tp_info_t tp = test_traceparent(k_flag_sampled | k_flag_random);
    unsigned char original_span_id[SPAN_ID_SIZE_BYTES];
    for (u8 i = 0; i < SPAN_ID_SIZE_BYTES; i++) {
        original_span_id[i] = i + 49;
        tp.parent_id[i] = i + 33;
    }
    tp.sampling_decision = k_sampling_decision_pending;

    restore_outbound_traceparent(&tp, original_span_id, 0x84);

    assert_bytes(original_span_id, tp.span_id, sizeof(tp.span_id), "restore original span ID");
    const unsigned char zero_parent_id[SPAN_ID_SIZE_BYTES] = {};
    assert_bytes(zero_parent_id, tp.parent_id, sizeof(tp.parent_id), "clear rewritten parent ID");
    assert_bool(0, tp.flags, "clear unsupported trace flags after failed rewrite");
    assert_bool(k_sampling_decision_applied,
                tp.sampling_decision,
                "restored application traceparent remains authoritative");
}

static void test_copy_sampling_state(void) {
    const tp_info_t src = {
        .flags = k_flag_random,
        .sampling_decision = 1,
        .parent_remote = 1,
    };
    tp_info_t dest = {
        .flags = k_flag_sampled,
        .sampling_decision = 0,
    };

    copy_sampling_state(&dest, &src);

    assert_bool(k_flag_random, dest.flags, "copy authoritative trace flags");
    assert_bool(1, dest.sampling_decision, "copy authoritative sampling decision");
    assert_bool(1, dest.parent_remote, "copy remote parent state");
}

static void test_inherit_parent_sampling_state(void) {
    const tp_info_t parent = {
        .flags = k_flag_random,
        .sampling_decision = k_sampling_decision_fail_closed,
    };
    tp_info_t child = {
        .flags = k_flag_sampled,
        .sampling_decision = k_sampling_decision_applied,
    };

    inherit_parent_sampling_state(&child, &parent);

    assert_bool(k_flag_random, child.flags, "inherit parent trace flags");
    assert_bool(k_sampling_decision_pending,
                child.sampling_decision,
                "child requires its own sampling decision");
}

int main(void) {
    test_old_writer_to_new_reader();
    test_sampled_new_writer_to_old_reader();
    test_unsampled_new_writer_to_new_reader();
    test_unsampled_new_writer_is_rejected_by_old_reader();
    test_random_flags_wire_compatibility();
    test_tcp_option_budget();
    test_always_on_disagreement();
    test_always_off_disagreement();
    test_reserved_flags_are_cleared();
    test_ratio_disagreement();
    test_traceparent_validation();
    test_http_traceparent_validation();
    test_split_http_traceparent_adoption();
    test_split_http_traceparent_adoption_variants();
    test_split_http_traceparent_adoption_eligibility();
    test_split_http_client_traceparent_adoption();
    test_new_trace_id_sets_random_flag();
    test_preserve_outbound_traceparent();
    test_commit_outbound_traceparent();
    test_adopt_outbound_traceparent();
    test_reject_invalid_outbound_traceparent();
    test_outbound_traceparent_state_is_exact();
    test_restore_outbound_traceparent_flags();
    test_restore_outbound_traceparent();
    test_copy_sampling_state();
    test_inherit_parent_sampling_state();

    return failures == 0 ? 0 : 1;
}
