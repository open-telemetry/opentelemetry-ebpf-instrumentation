// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"math/bits"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

type iso8583FieldFormat struct {
	width        int // fixed width, or maximum width for a variable field
	lengthDigits int // LLVAR or LLLVAR prefix, zero for a fixed field
	unit         iso8583FieldUnit
}

type iso8583FieldUnit uint8

const (
	isoDigits iso8583FieldUnit = iota
	isoBytes
)

// Wire layouts up to DE39 in the jPOS ISO87 and ISO93 ASCII/binary packagers.
// Text fields retain their byte width in a packed message. The 1987 signed
// fees (DE28–31) occupy one sign byte and four packed amount bytes.
var iso8583OutcomeFields = [39][2]iso8583FieldFormat{
	//      1987                   1993
	12: {{6, 0, isoDigits}, {12, 0, isoDigits}},
	13: {{4, 0, isoDigits}, {4, 0, isoDigits}},
	14: {{4, 0, isoDigits}, {4, 0, isoDigits}},
	15: {{4, 0, isoDigits}, {6, 0, isoDigits}},
	16: {{4, 0, isoDigits}, {4, 0, isoDigits}},
	17: {{4, 0, isoDigits}, {4, 0, isoDigits}},
	18: {{4, 0, isoDigits}, {4, 0, isoDigits}},
	19: {{3, 0, isoDigits}, {3, 0, isoDigits}},
	20: {{3, 0, isoDigits}, {3, 0, isoDigits}},
	21: {{3, 0, isoDigits}, {3, 0, isoDigits}},
	22: {{3, 0, isoDigits}, {12, 0, isoBytes}},
	23: {{3, 0, isoDigits}, {3, 0, isoDigits}},
	24: {{3, 0, isoDigits}, {3, 0, isoDigits}},
	25: {{2, 0, isoDigits}, {4, 0, isoDigits}},
	26: {{2, 0, isoDigits}, {4, 0, isoDigits}},
	27: {{1, 0, isoDigits}, {1, 0, isoDigits}},
	28: {{9, 0, isoDigits}, {6, 0, isoDigits}},
	29: {{9, 0, isoDigits}, {3, 0, isoDigits}},
	30: {{9, 0, isoDigits}, {24, 0, isoDigits}},
	31: {{9, 0, isoDigits}, {99, 2, isoBytes}},
	32: {{11, 2, isoDigits}, {11, 2, isoDigits}},
	33: {{11, 2, isoDigits}, {11, 2, isoDigits}},
	34: {{28, 2, isoBytes}, {28, 2, isoBytes}},
	35: {{37, 2, isoDigits}, {37, 2, isoBytes}},
	36: {{104, 3, isoBytes}, {104, 3, isoBytes}},
	37: {{12, 0, isoBytes}, {12, 0, isoBytes}},
	38: {{6, 0, isoBytes}, {6, 0, isoBytes}},
}

func (m *iso8583Message) readAuthOutcome(buf *largebuf.LargeBuffer, offset, frameEnd, laterFields int) request.ISO8583AuthOutcome {
	version := m.mti[0] - '0'
	end := min(frameEnd, buf.Len())
	fields := m.bitmap & (iso8583FieldBit(11) - iso8583FieldBit(38))
	for fields != 0 {
		field := bits.LeadingZeros64(fields) + 1
		fields &^= iso8583FieldBit(field)
		format := iso8583OutcomeFields[field][version]
		width := format.width

		if format.lengthDigits != 0 {
			var length [3]byte
			n := format.lengthDigits
			if m.packed {
				n = (n + 1) / 2
			}

			if offset+n > end {
				return request.ISO8583Unknown
			}

			_ = buf.CopyAt(offset, length[:n])

			width = iso8583DecimalLength(length[:n], m.packed)
			if width < 0 || width > format.width {
				return request.ISO8583Unknown
			}

			offset += n
		}
		if m.packed && format.unit == isoDigits {
			width = (width + 1) / 2
		}

		offset += width
	}

	// In the 1987 layouts DE39 is text even when numeric fields use BCD.
	n := 2
	if version == iso8583Version1993 && !m.packed {
		n = 3
	}

	after := frameEnd - (offset + n)
	if offset+n > end || after < laterFields || (laterFields == 0 && after != 0) {
		return request.ISO8583Unknown
	}

	var code [3]byte
	_ = buf.CopyAt(offset, code[:n])
	if version == iso8583Version1993 && m.packed {
		// The ISO93 binary packager right-pads the three digits with a zero nibble.
		a, b := code[0], code[1]
		if b&15 != 0 || a>>4 > 9 || a&15 > 9 || b>>4 > 9 {
			return request.ISO8583Unknown
		}

		code = [3]byte{'0' + a>>4, '0' + a&15, '0' + b>>4}
		n = 3
	}
	return iso8583ClassifyOutcome(code[:n])
}

// Processor-specific and ambiguous codes retain the unknown outcome.
func iso8583ClassifyOutcome(code []byte) request.ISO8583AuthOutcome {
	switch string(code) {
	case "00", "08", "11", "000", "001", "003", "004", "005", "007":
		return request.ISO8583Approved
	case "10", "002", "006":
		return request.ISO8583PartiallyApproved
	case "01", "02", "03", "04", "05", "07", "12", "13", "14", "33", "34", "36", "38", "41", "43",
		"51", "54", "55", "56", "57", "58", "59", "61", "62", "63", "65", "75":
		return request.ISO8583Declined
	case "06", "28", "30", "68", "90", "91", "92", "96", "904", "906", "907", "908", "909", "910", "911", "912":
		return request.ISO8583TechnicalError
	}

	// Defined 1993 issuer denials, with or without a card pickup. Reserved
	// national and private ranges can have different meanings across switches.
	if len(code) == 3 {
		n := iso8583DecimalLength(code, false)
		if (n >= 100 && n <= 129) || (n >= 200 && n <= 210) {
			return request.ISO8583Declined
		}
	}

	return request.ISO8583Unknown
}
