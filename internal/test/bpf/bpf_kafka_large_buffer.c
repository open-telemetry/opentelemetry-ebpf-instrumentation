// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The following code is copied from the bpf/generictracer/protocol_kafka.h code
and
 * adapted from it. The following functions:
 * static __always_inline u8 is_kafka(connection_info_t *conn_info,
                                   const unsigned char *data,
                                   u32 data_len,
                                   enum protocol_type *protocol_type,
                                   u8 direction) {...}

// static __always_inline int kafka_send_large_buffer(tcp_req_t *req,
                                                   pid_connection_info_t
*pid_conn, const void *u_buf, u32 bytes_len, u8 direction, enum large_buf_action
action) {
// and the internal functions are tested.
// Note: new types, structs, and functions have been defined that are ONLY
// used internally in the test.
*/

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DATA_LEN 30
#define MAX_ENTRIES 20

// This is the direction of the packet not the type!
#define TCP_SEND 1
#define TCP_RECV 0

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int16_t s16;
typedef int32_t s32;

// Similar to connection_info defined in connection_info.h
typedef struct connection_info {
  u32 src_ip;
  u32 dst_ip;
  u16 src_port;
  u16 dst_port;
} connection_info_t;

// message_size -> https://kafka.apache.org/protocol#protocol_common
// The message_size field in the Kafka protocol defines the size of the
// request/response payload excluding the 4 bytes used by the message_size field
// itself.

// Every kafka api packet is prefixed by an header
// https://kafka.apache.org/protocol#protocol_messages
struct kafka_request_hdr {
  s32 message_size;
  s16 request_api_key;     // The API key of this request
  s16 request_api_version; // The API version of this request
  s32 correlation_id;      // The correlation ID of this request
                           // client-id is a nullable string
};

struct kafka_response_hdr {
  s32 message_size;
  s32 correlation_id; // The correlation ID of this response
};

typedef struct kafka_state_data {
  s32 message_size;
} kafka_state_data_t;

typedef struct kafka_state_key {
  connection_info_t conn;
  u8 direction;
  u8 _pad[3];
} kafka_state_key_t;

typedef struct kafka_correlation_data {
  s32 correlation_id;
} kafka_correlation_data_t;

typedef struct kafka_state_entry_t {
  kafka_state_key_t key;
  kafka_state_data_t value;
  int used;
} kafka_state_entry_t;

// It simulates the kafka_state ebpf map
static kafka_state_entry_t kafka_state[MAX_ENTRIES];

typedef struct kafka_correlation_entry {
  connection_info_t key;
  kafka_correlation_data_t value;
  int used;
} kafka_correlation_entry_t;

// It simulates the kafka_ongoing_requests ebpf map
static kafka_correlation_entry_t kafka_ongoing_requests[MAX_ENTRIES];

enum {
  k_kafka_hdr_message_size = 4,
  k_kafka_hdr_request_api_key = 2,
  k_kafka_hdr_request_api_version = 2,
  k_kafka_hdr_correlation_id = 4,

  k_kafka_min_response_message_size_value = 4, // correlation_id (4)

  // https://kafka.apache.org/protocol#protocol_api_keys
  k_kafka_api_key_metadata = 3,
  // only versions 10-13 contain topic_id which we are interested in
  k_kafka_min_metadata_api_version = 10,
  k_kafka_max_metadata_api_version = 13,

  // Sanity checks
  k_kafka_message_size_max = 1 << 13, // 8K
};

// The following functions simulate the bpf_map_{update/delete/lookup}_elem
// helper functions
static int key_equal(const kafka_state_key_t *a, const kafka_state_key_t *b) {
  return memcmp(a, b, sizeof(*a)) == 0;
}

static kafka_state_data_t *kafka_state_lookup(const kafka_state_key_t *key) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (kafka_state[i].used && key_equal(&kafka_state[i].key, key)) {
      return &kafka_state[i].value;
    }
  }
  return NULL;
}

static void kafka_state_update(const kafka_state_key_t *key,
                               const kafka_state_data_t *val) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (!kafka_state[i].used) {
      kafka_state[i].used = 1;
      kafka_state[i].key = *key;
      kafka_state[i].value = *val;
      return;
    }
  }
}

static void kafka_state_delete(const kafka_state_key_t *key) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (kafka_state[i].used && key_equal(&kafka_state[i].key, key)) {
      kafka_state[i].used = 0;
      return;
    }
  }
}

static kafka_correlation_data_t *
kafka_correlation_lookup(const connection_info_t *key) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (kafka_ongoing_requests[i].used &&
        memcmp(&kafka_ongoing_requests[i].key, key, sizeof(*key)) == 0) {
      return &kafka_ongoing_requests[i].value;
    }
  }
  return NULL;
}

static void correlation_update(const connection_info_t *key,
                               const kafka_correlation_data_t *val) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (!kafka_ongoing_requests[i].used) {
      kafka_ongoing_requests[i].used = 1;
      kafka_ongoing_requests[i].key = *key;
      kafka_ongoing_requests[i].value = *val;
      return;
    }
  }
}

static void correlation_delete(const connection_info_t *key) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (kafka_ongoing_requests[i].used &&
        memcmp(&kafka_ongoing_requests[i].key, key, sizeof(*key)) == 0) {
      kafka_ongoing_requests[i].used = 0;
      return;
    }
  }
}

void assert_equal(int expected, int actual, const char *message) {
  if (expected != actual) {
    fprintf(stderr, "Assertion failed: %s\nExpected: %d\nActual: %d\n", message,
            expected, actual);
    exit(1);
  }
}

int kafka_read_message_size(const unsigned char *data, size_t data_len) {
  if (data_len < k_kafka_hdr_message_size) {
    return -1;
  }

  int message_size = 0;
  memcpy(&message_size, data, k_kafka_hdr_message_size);
  message_size = ntohl(message_size);

  // we can be in the case where we already have the first part
  // of the header saved in the map and we are reading the second
  // part so we think that is message_size but it is actually
  // key+version in case of request or the correlation id in case of
  // response

  if (message_size < k_kafka_min_response_message_size_value ||
      message_size > k_kafka_message_size_max) {
    return 0;
  }
  return message_size;
}

// This function is used to store the Kafka header if it comes in split packets
// from double send.
// Given the fact that we need to store this for the duration of the full
// request (split in potentially multiple packets), we will **not** process or
// preserve any actual payloads that are exactly 4 bytes long — they are
// intentionally dropped in favor of state storage.
int kafka_store_state_data(const connection_info_t *conn_info,
                           const unsigned char *data, size_t data_len,
                           u8 direction) {

  // we want to store only request/response of split sends that are 4 bytes long
  if (data_len != k_kafka_hdr_message_size) {
    return 0;
  }

  int message_size = kafka_read_message_size(data, data_len);
  if (message_size == -1) {
    return 0;
  }
  kafka_state_data_t new_state_data = {};
  new_state_data.message_size = message_size;
  kafka_state_key_t state_key = {.conn = *conn_info, .direction = direction};

  kafka_state_update(&state_key, &new_state_data);
  return -1;
}

// This function reads all fields in a request header, ignoring the first field
// (message_size). Specifically, it also checks whether the request_api_key is
// relevant to us (currently, we're only interested in the Metadata type),
// whether the request_api_version is valid, and whether the correlation_id is
// valid. Note: we are interested in request_api_version values ​​between 10
// and 13 because these versions contain the topic_id while versions < 9 have
// directly the topic_name.
int kafka_check_request_header_fields_without_message_size(
    struct kafka_request_hdr *hdr, const unsigned char *data) {

  u8 offset = 0;

  memcpy(&hdr->request_api_key, data, k_kafka_hdr_request_api_key);
  hdr->request_api_key = ntohs(hdr->request_api_key);
  if (hdr->request_api_key != k_kafka_api_key_metadata) {
    return -1;
  }

  offset += k_kafka_hdr_request_api_key;
  memcpy(&hdr->request_api_version, (const void *)(data + offset),
         k_kafka_hdr_request_api_version);
  hdr->request_api_version = ntohs(hdr->request_api_version);
  if (hdr->request_api_version < k_kafka_min_metadata_api_version ||
      hdr->request_api_version > k_kafka_max_metadata_api_version) {
    return -1;
  }

  offset += k_kafka_hdr_request_api_version;
  memcpy(&hdr->correlation_id, (const void *)(data + offset),
         k_kafka_hdr_correlation_id);
  hdr->correlation_id = ntohl(hdr->correlation_id);

  if (hdr->correlation_id < 0) {
    return -1;
  }
  return 0;
}

// Request header
// +--------------+-----------------+---------------------+----------------|
// | message_size | request_api_key | request_api_version | correlation_id |
// +--------------+-----------------+---------------------+----------------|
// |    4B        |     2B          |     2B              |      4B        |
// +--------------+-----------------+---------------------+----------------|
// This function parses the request header. First, it reads the value of the
// message_size field. If the value is equal to the size of the received data
// minus the size of message_size itself, then we've just received data that
// possibly indicates a healthy packet. Otherwise, we need to check if we have a
// valid message_size saved in the kafka_state map, and if the value of
// message_size is equal to the size of the received data, which means we've
// received the entire packet minus the message_size we already had. In both
// cases, we try to read all the remaining fields and see if it is a intersted
// and valid packet.
int kafka_parse_fixup_request_header(const connection_info_t *conn_info,
                                     struct kafka_request_hdr *hdr,
                                     const unsigned char *data, size_t data_len,
                                     u8 direction) {

  // Try to parse and validate the header first.
  hdr->message_size = kafka_read_message_size(data, data_len);
  if (hdr->message_size == -1) {
    return -1;
  }
  if (hdr->message_size == (data_len - k_kafka_hdr_message_size)) {
    // Header is valid and we have the full data, we can proceed.
    if (kafka_check_request_header_fields_without_message_size(
            hdr, data + k_kafka_hdr_message_size) < 0) {
      return -1;
    }
    return 0;
  }

  kafka_state_key_t state_key = {.conn = *conn_info, .direction = direction};
  kafka_state_data_t *state_data = kafka_state_lookup(&state_key);
  if (state_data != NULL && state_data->message_size == data_len) {
    // Prepend the header from state data.
    hdr->message_size = state_data->message_size;
    if (kafka_check_request_header_fields_without_message_size(hdr, data) < 0) {
      return -1;
    }
    return 0;
  }

  return -1;
}

// This function reads the response header correlation_id field and checks if it
// is a valid value
int kafka_check_response_header_correlation_id(struct kafka_response_hdr *hdr,
                                               const unsigned char *data) {

  memcpy(&hdr->correlation_id, data, k_kafka_hdr_correlation_id);
  hdr->correlation_id = ntohl(hdr->correlation_id);
  if (hdr->correlation_id < 0) {
    return -1;
  }
  return 0;
}

// Response header
// +--------------+----------------|
// | message_size | correlation_id |
// +--------------+----------------|
// |    4B        |       4B.      |
// +--------------+----------------|
// This function parses the response header. First, it reads the value of the
// message_size field. If the value is equal to the size of the received data
// minus the size of message_size itself, then we've just received data that
// possibly indicates a healthy packet. Otherwise, we need to check if we have a
// valid message_size saved in the kafka_state map, and if the value of
// message_size is equal to the size of the received data, which means we've
// received the entire packet minus the message_size we already had. In both
// cases, we need to check if the value of the correlation_id field is valid.
int kafka_parse_fixup_response_header(const connection_info_t *conn_info,
                                      struct kafka_response_hdr *hdr,
                                      const unsigned char *data,
                                      size_t data_len, u8 direction) {
  // Try to parse and validate the header first.
  hdr->message_size = kafka_read_message_size(data, data_len);
  if (hdr->message_size == -1) {
    return -1;
  }

  if (hdr->message_size == (data_len - k_kafka_hdr_message_size)) {
    // Header is valid and we have the full data, we can proceed.
    if (kafka_check_response_header_correlation_id(
            hdr, data + k_kafka_hdr_message_size) < 0) {
      return -1;
    }
    return 0;
  }
  // Prepend the header from state data.
  kafka_state_key_t state_key = {.conn = *conn_info, .direction = direction};
  kafka_state_data_t *state_data = kafka_state_lookup(&state_key);
  if (state_data != NULL && state_data->message_size == data_len) {
    // Prepend the header from state data.
    hdr->message_size = kafka_state->value.message_size;
    if (kafka_check_response_header_correlation_id(hdr, data) < 0) {
      return -1;
    }
    return 0;
  }

  return -1;
}

// Emit a large buffer event for Kafka protocol.
// The return value is used to control the flow for this specific protocol.
// -1: wait additional data; 0: continue, regardless of errors.
int kafka_send_large_buffer(connection_info_t *conn, const void *u_buf,
                            u32 bytes_len, u8 direction) {

  if (kafka_store_state_data(conn, u_buf, bytes_len, direction) < 0) {
    return -1;
  }

  // check if this event matches an ongoing request
  kafka_correlation_data_t *correlation_data = kafka_correlation_lookup(conn);
  if (!correlation_data) {
    return 0;
  }
  struct kafka_response_hdr hdr = {};
  if (kafka_parse_fixup_response_header(conn, &hdr, u_buf, bytes_len,
                                        direction) != 0) {
    return 0;
  }

  if (hdr.correlation_id != correlation_data->correlation_id) {
    return 0;
  }

  // remove all the large buffer code because
  // if we are here it means that the packet is for sure a good response because
  // we populated the hdr with message_size and correlation_id
  // we checked also in the map of ongoing requests if there was a related
  // ongoing request so we can hardcode the packet_type as response
  // **NOTE**: we only send the response as a large buffer event in userspace
  // because the topic_id and name are in the response.
  correlation_delete(conn);
  // modified version used only here in order to assert the result
  return 1;
}

// This function first checks whether the received event hasn't already been
// classified as Kafka; it then attempts to save the data in a map if and only
// if it's a 4 byte packet (we're interested in the message_size field). If the
// event is of interest to us, we try to parse it as if it were a request,
// because the sequence of bytes that characterizes a request is better than a
// response; if that fails, we try parsing it as a response. If we find a
// request, we save it in an ongoing request map. If we find a response (or at
// least something that looks like a response from the bytes), we need to
// perform a further check: see if we have an ongoing request related to this
// response using the correlation_id. In both cases, if we found a Kafka packet,
// we update the protocol_cache map and return.
int is_kafka(connection_info_t *conn_info, const unsigned char *data,
             u32 data_len, u8 direction) {

  if (kafka_store_state_data(conn_info, data, (size_t)data_len, direction) <
      0) {
    return 0;
  }

  struct kafka_request_hdr req_hdr = {};
  struct kafka_response_hdr res_hdr = {};
  if (kafka_parse_fixup_request_header(conn_info, &req_hdr, data, data_len,
                                       direction) == 0) {
    kafka_correlation_data_t correlation_data = {};
    correlation_data.correlation_id = req_hdr.correlation_id;
    correlation_update(conn_info, &correlation_data);
  } else {
    if (kafka_parse_fixup_response_header(conn_info, &res_hdr, data, data_len,
                                          direction) != 0) {
      return 0;
    }

    kafka_correlation_data_t *correlation_data =
        kafka_correlation_lookup(conn_info);
    if (!correlation_data) {
      return 0;
    }

    if (res_hdr.correlation_id != correlation_data->correlation_id) {
      return 0;
    }
  }
  return 1;
}

// NOTES
// The following tests aim to test different use cases for the kafka processing:
// test1: a complete metadata request and a complete metadata response related
// to the request test2: a metadata request split in two and a complete metadata
// response relating to the request test3: a split metadata request and a split
// metadata response related to the request test4: metadata request divided in 2
// and a metadata NOT related response

// A note on the connection passed to the is_kafka() function: it might seem
// strange to see the connection used to save the request in the
// kafka_ongoing_requests map, which is then used to check whether a request is
// ongoing for a given response event. This is because in OBI we track both send
// and receive connections, so the connection passed to the is_kafka() function
// is sorted using the following function: static __always_inline void
// sort_connection_info(connection_info_t *info) {...} which is called before
// calling the handle_buf_with_connection function.

// test1
// a complete metadata request and a complete metadata response related to the
// request
void test1() {
  int result = 0;
  printf("Test 1\n");

  connection_info_t conn = {
      .src_ip = 0x0a000001,
      .dst_ip = 0x0a000002,
      .src_port = 12345,
      .dst_port = 9092,
  };

  unsigned char req[DATA_LEN];

  s32 message_size =
      htonl(14); // key(2), version (2), correlation id(4), fake_payload(6)
  s16 request_api_key = htons(k_kafka_api_key_metadata);
  s16 request_api_version = htons(k_kafka_max_metadata_api_version);
  s32 correlation_id = htonl(1); // for both request and response
  char fake_payload[] = "Hello";

  int offset = 0;
  memcpy(req + offset, &message_size, k_kafka_hdr_message_size);
  offset += k_kafka_hdr_message_size;
  memcpy(req + offset, &request_api_key, k_kafka_hdr_request_api_key);
  offset += k_kafka_hdr_request_api_key;
  memcpy(req + offset, &request_api_version, k_kafka_hdr_request_api_version);
  offset += k_kafka_hdr_request_api_version;
  memcpy(req + offset, &correlation_id, k_kafka_hdr_correlation_id);
  offset += k_kafka_hdr_correlation_id;
  memcpy(req + offset, fake_payload, sizeof(fake_payload));
  offset += sizeof(fake_payload);

  result = is_kafka(&conn, req, offset, TCP_RECV);
  assert_equal(1, result,
               "The event should be classified as a Kafka metadata request");
  unsigned char res[DATA_LEN];

  result = kafka_send_large_buffer(&conn, req, offset, TCP_RECV);

  assert_equal(0, result, "The event should NOT be sent to userspace");

  offset = 0;
  message_size = htonl(10); // correlation id(4), fake_payload(6)
  memcpy(res + offset, &message_size, k_kafka_hdr_message_size);
  offset += k_kafka_hdr_message_size;
  memcpy(res + offset, &correlation_id, k_kafka_hdr_correlation_id);
  offset += k_kafka_hdr_correlation_id;
  memcpy(res + offset, fake_payload, sizeof(fake_payload));
  offset += sizeof(fake_payload);

  result = is_kafka(&conn, res, offset, TCP_SEND);
  assert_equal(
      1, result,
      "The event should be classified as a intersting Kafka metadata response");

  result = kafka_send_large_buffer(&conn, res, offset, TCP_SEND);
  assert_equal(1, result, "The event should be sent to userspace");
}

// test2
// a metadata request split in two and a complete metadata response relating to
// the request
void test2() {
  int result = 0;
  printf("Test 2\n");

  connection_info_t conn = {
      .src_ip = 0x0a000003,
      .dst_ip = 0x0a000004,
      .src_port = 12345,
      .dst_port = 9092,
  };

  // build the first piece of a kafka request
  unsigned char first[DATA_LEN];
  s32 message_size =
      htonl(14); // key(2), version (2), correlation id(4), fake_payload(6)
  memcpy(first, &message_size, k_kafka_hdr_message_size);
  result = is_kafka(&conn, first, k_kafka_hdr_message_size, TCP_RECV);
  assert_equal(0, result,
               "The event should simply be saved in the kafka state map");

  // build the second piece of a kafka request
  unsigned char second[DATA_LEN];
  s16 request_api_key = htons(k_kafka_api_key_metadata);
  s16 request_api_version = htons(k_kafka_max_metadata_api_version);
  s32 correlation_id = htonl(2); // for both request and response
  char fake_payload[] = "Hello";

  int offset = 0;
  memcpy(second + offset, &request_api_key, k_kafka_hdr_request_api_key);
  offset += k_kafka_hdr_request_api_key;
  memcpy(second + offset, &request_api_version,
         k_kafka_hdr_request_api_version);
  offset += k_kafka_hdr_request_api_version;
  memcpy(second + offset, &correlation_id, k_kafka_hdr_correlation_id);
  offset += k_kafka_hdr_correlation_id;
  memcpy(second + offset, fake_payload, sizeof(fake_payload));
  offset += sizeof(fake_payload);

  result = is_kafka(&conn, second, offset, TCP_RECV);
  assert_equal(1, result,
               "The event should be classified as a Kafka metadata request");

  result = kafka_send_large_buffer(&conn, second, offset, TCP_RECV);

  assert_equal(0, result, "The event should NOT be sent to userspace");

  unsigned char res[DATA_LEN];

  offset = 0;
  message_size = htonl(10); // correlation id(4), fake_payload(6)
  memcpy(res + offset, &message_size, k_kafka_hdr_message_size);
  offset += k_kafka_hdr_message_size;
  memcpy(res + offset, &correlation_id, k_kafka_hdr_correlation_id);
  offset += k_kafka_hdr_correlation_id;
  memcpy(res + offset, fake_payload, sizeof(fake_payload));
  offset += sizeof(fake_payload);

  result = is_kafka(&conn, res, offset, TCP_SEND);
  assert_equal(1, result,
               "The event should be classified as a interesting Kafka metadata "
               "response");

  result = kafka_send_large_buffer(&conn, res, offset, TCP_SEND);

  assert_equal(1, result, "The event should be sent to userspace");
}

// test3
// a split metadata request and a split metadata response related to the request
void test3() {
  int result = 0;
  printf("Test 3\n");

  connection_info_t conn = {
      .src_ip = 0x0a000005,
      .dst_ip = 0x0a000006,
      .src_port = 12345,
      .dst_port = 9092,
  };

  // build a piece of a kafka request
  unsigned char first_req[DATA_LEN];
  s32 message_size =
      htonl(14); // key(2), version (2), correlation id(4), fake_payload(6)
  memcpy(first_req, &message_size, k_kafka_hdr_message_size);
  result = is_kafka(&conn, first_req, k_kafka_hdr_message_size, TCP_RECV);
  assert_equal(0, result,
               "The event should simply be saved in the kafka state map");

  // build the second piece of a kafka request
  unsigned char second_req[DATA_LEN];
  s16 request_api_key = htons(k_kafka_api_key_metadata);
  s16 request_api_version = htons(k_kafka_max_metadata_api_version);
  s32 correlation_id = htonl(3); // for both request and response
  char fake_payload[] = "Hello";

  int offset = 0;
  memcpy(second_req + offset, &request_api_key, k_kafka_hdr_request_api_key);
  offset += k_kafka_hdr_request_api_key;
  memcpy(second_req + offset, &request_api_version,
         k_kafka_hdr_request_api_version);
  offset += k_kafka_hdr_request_api_version;
  memcpy(second_req + offset, &correlation_id, k_kafka_hdr_correlation_id);
  offset += k_kafka_hdr_correlation_id;
  memcpy(second_req + offset, fake_payload, sizeof(fake_payload));
  offset += sizeof(fake_payload);

  result = is_kafka(&conn, second_req, offset, TCP_RECV);
  assert_equal(1, result,
               "The event should be classified as a Kafka metadata request");

  result = kafka_send_large_buffer(&conn, second_req, offset, TCP_RECV);

  assert_equal(0, result, "The event should NOT be sent to userspace");
  // build a piece of kafka response
  unsigned char first_res[DATA_LEN];

  message_size = htonl(10); // correlation id(4), fake_payload(6)
  memcpy(first_res, &message_size, k_kafka_hdr_message_size);
  result = is_kafka(&conn, first_res, k_kafka_hdr_message_size, TCP_SEND);
  assert_equal(0, result,
               "The event should simply be saved in the kafka state map");

  offset = 0;
  unsigned char second_res[DATA_LEN];

  memcpy(second_res + offset, &correlation_id, k_kafka_hdr_correlation_id);
  offset += k_kafka_hdr_correlation_id;
  memcpy(second_res + offset, fake_payload, sizeof(fake_payload));
  offset += sizeof(fake_payload);
  result = is_kafka(&conn, second_res, offset, TCP_SEND);
  assert_equal(1, result,
               "The event should be classified as a interesting Kafka metadata "
               "response");

  result = kafka_send_large_buffer(&conn, second_res, offset, TCP_SEND);

  assert_equal(1, result, "The event should be sent to userspace");
}

// test4
// a split metadata request and a split metadata response NOT related to the
// request
void test4() {
  int result = 0;
  printf("Test 4\n");

  connection_info_t conn = {
      .src_ip = 0x0a000005,
      .dst_ip = 0x0a000006,
      .src_port = 12345,
      .dst_port = 9092,
  };

  // build a piece of a kafka request
  unsigned char first_req[DATA_LEN];
  s32 message_size =
      htonl(14); // key(2), version (2), correlation id(4), fake_payload(6)
  memcpy(first_req, &message_size, k_kafka_hdr_message_size);
  result = is_kafka(&conn, first_req, k_kafka_hdr_message_size, TCP_RECV);
  assert_equal(0, result,
               "The event should simply be saved in the kafka state map");

  // build the second piece of a kafka request
  unsigned char second_req[DATA_LEN];
  s16 request_api_key = htons(k_kafka_api_key_metadata);
  s16 request_api_version = htons(k_kafka_max_metadata_api_version);
  s32 correlation_id = htonl(4); // ONLY for the request
  char fake_payload[] = "Hello";

  int offset = 0;
  memcpy(second_req + offset, &request_api_key, k_kafka_hdr_request_api_key);
  offset += k_kafka_hdr_request_api_key;
  memcpy(second_req + offset, &request_api_version,
         k_kafka_hdr_request_api_version);
  offset += k_kafka_hdr_request_api_version;
  memcpy(second_req + offset, &correlation_id, k_kafka_hdr_correlation_id);
  offset += k_kafka_hdr_correlation_id;
  memcpy(second_req + offset, fake_payload, sizeof(fake_payload));
  offset += sizeof(fake_payload);

  result = is_kafka(&conn, second_req, offset, TCP_RECV);
  assert_equal(1, result,
               "The event should be classified as a Kafka metadata request");

  result = kafka_send_large_buffer(&conn, second_req, offset, TCP_RECV);

  assert_equal(0, result, "The event should NOT be sent to userspace");

  // build a piece of kafka response
  unsigned char first_res[DATA_LEN];

  message_size = htonl(10); // correlation id(4), fake_payload(6)
  memcpy(first_res, &message_size, k_kafka_hdr_message_size);
  result = is_kafka(&conn, first_res, k_kafka_hdr_message_size, TCP_SEND);
  assert_equal(0, result,
               "The event should simply be saved in the kafka state map");

  offset = 0;
  unsigned char second_res[DATA_LEN];

  correlation_id = htonl(5); // ONLY for the response
  memcpy(second_res + offset, &correlation_id, k_kafka_hdr_correlation_id);
  offset += k_kafka_hdr_correlation_id;
  memcpy(second_res + offset, fake_payload, sizeof(fake_payload));
  offset += sizeof(fake_payload);
  result = is_kafka(&conn, second_res, offset, TCP_SEND);
  assert_equal(0, result,
               "The event should be classified as a Kafka metadata response "
               "not related to a request");

  result = kafka_send_large_buffer(&conn, second_res, offset, TCP_SEND);

  assert_equal(0, result, "The event should NOT be sent to userspace");
}

int main(int argc, char **argv) {
  test1();
  test2();
  test3();
  test4();

  printf("\nAll tests PASSED!");
  return 0;
}
