# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Small HPACK (RFC 7541) encoder and decoder, without Huffman coding.

Written by hand instead of using a library, so the test decides which fields go
into the dynamic table and which are sent as an index. That is the point of the
test: a value sent only as an index decodes right only if the reader saw every
earlier block on the connection, in order.
"""

STATIC_TABLE = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
]

STATIC_ENTRIES = len(STATIC_TABLE)
DYNAMIC_TABLE_LIMIT = 4096
ENTRY_OVERHEAD = 32  # RFC 7541 section 4.1


def _encode_int(value, prefix_bits, flags):
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([flags | value])

    out = bytearray([flags | limit])
    value -= limit
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _decode_int(buf, pos, prefix_bits):
    limit = (1 << prefix_bits) - 1
    value = buf[pos] & limit
    pos += 1
    if value < limit:
        return value, pos

    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


class _Table:
    """The dynamic table both sides keep, newest entry first."""

    def __init__(self):
        self.entries = []
        self.size = 0

    def add(self, name, value):
        entry_size = len(name) + len(value) + ENTRY_OVERHEAD
        self.entries.insert(0, (name, value))
        self.size += entry_size
        while self.size > DYNAMIC_TABLE_LIMIT and self.entries:
            evicted = self.entries.pop()
            self.size -= len(evicted[0]) + len(evicted[1]) + ENTRY_OVERHEAD

    def get(self, index):
        return self.entries[index - STATIC_ENTRIES - 1]


class Encoder:
    """Encodes header blocks, sending every field it sent before as an index.

    One encoder covers one direction of one connection, so keep it for the whole
    life of that connection, like a real HTTP/2 implementation does.
    """

    def __init__(self):
        self.table = _Table()

    def encode(self, headers):
        out = bytearray()
        for name, value in headers:
            out += self._encode_field(name, value)
        return bytes(out)

    def _encode_field(self, name, value):
        for index, entry in enumerate(STATIC_TABLE, start=1):
            if entry == (name, value):
                return _encode_int(index, 7, 0x80)
        for index, entry in enumerate(self.table.entries):
            if entry == (name, value):
                return _encode_int(STATIC_ENTRIES + 1 + index, 7, 0x80)

        name_index = self._name_index(name)
        self.table.add(name, value)

        if name_index:
            return _encode_int(name_index, 6, 0x40) + _encode_string(value)
        return _encode_int(0, 6, 0x40) + _encode_string(name) + _encode_string(value)

    def _name_index(self, name):
        for index, entry in enumerate(STATIC_TABLE, start=1):
            if entry[0] == name:
                return index
        for index, entry in enumerate(self.table.entries):
            if entry[0] == name:
                return STATIC_ENTRIES + 1 + index
        return 0


class Decoder:
    """Decodes what Encoder writes; also one per direction per connection."""

    def __init__(self):
        self.table = _Table()

    def decode(self, block):
        headers = []
        pos = 0
        while pos < len(block):
            byte = block[pos]

            if byte & 0x80:
                index, pos = _decode_int(block, pos, 7)
                headers.append(self._entry(index))
                continue

            if byte & 0xE0 == 0x20:  # dynamic table size update
                _, pos = _decode_int(block, pos, 5)
                continue

            indexed = bool(byte & 0x40)
            prefix_bits = 6 if indexed else 4
            name_index, pos = _decode_int(block, pos, prefix_bits)

            if name_index:
                name = self._entry(name_index)[0]
            else:
                name, pos = _decode_string(block, pos)
            value, pos = _decode_string(block, pos)

            if indexed:
                self.table.add(name, value)
            headers.append((name, value))

        return headers

    def _entry(self, index):
        if index <= STATIC_ENTRIES:
            return STATIC_TABLE[index - 1]
        return self.table.get(index)


def _encode_string(value):
    raw = value.encode()
    return _encode_int(len(raw), 7, 0x00) + raw


def _decode_string(buf, pos):
    if buf[pos] & 0x80:
        raise ValueError("huffman-coded strings are not produced by this codec")
    length, pos = _decode_int(buf, pos, 7)
    return buf[pos:pos + length].decode(), pos + length
