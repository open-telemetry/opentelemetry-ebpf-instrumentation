// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/hex"
	"time"
)

const (
	iso8583TransmissionField = 7
	iso8583STANField         = 11
	iso8583MaxResponseTime   = 2 * time.Minute
)

func iso8583FieldBit(field int) uint64 {
	return uint64(1) << (64 - field)
}

// iso8583DecimalLength returns -1 for a non-decimal digit in a length prefix.
func iso8583DecimalLength(data []byte, packed bool) int {
	size := 0
	for _, b := range data {
		if packed {
			hi, lo := b>>4, b&15
			if hi > 9 || lo > 9 {
				return -1
			}

			size = size*100 + int(hi)*10 + int(lo)
		} else {
			if b < '0' || b > '9' {
				return -1
			}

			size = size*10 + int(b-'0')
		}
	}
	return size
}

func readISO8583Digits(encoded, digits []byte, packed bool) {
	if packed {
		hex.Encode(digits, encoded)
	} else {
		copy(digits, encoded)
	}

	for _, d := range digits {
		if d < '0' || d > '9' {
			clear(digits)
			return
		}
	}
}

// readTimingFields returns the byte offset after DE11, or -1 for an incomplete prefix.
func (m *iso8583Message) readTimingFields(bitmap uint64, data []byte) int {
	initialSize := len(data)

	// DE2 is LLVAR. Only its length is needed to skip the account number.
	if bitmap&iso8583FieldBit(2) != 0 {
		size := 2
		if m.packed {
			size = 1
		}

		if len(data) < size {
			return -1
		}

		panLen := iso8583DecimalLength(data[:size], m.packed)
		if panLen <= 0 || panLen > 19 {
			return -1
		}

		if m.packed {
			panLen = (panLen + 1) / 2
		}

		if len(data) < size+panLen {
			return -1
		}

		data = data[size+panLen:]
	}

	// Fixed numeric widths in digits for DE3 through DE11 in these packagers.
	for i, width := range [...]int{6, 12, 12, 12, 10, 8, 8, 8, 6} {
		field := i + 3
		if bitmap&iso8583FieldBit(field) == 0 {
			continue
		}

		if m.packed {
			width /= 2
		}

		if width > len(data) {
			return -1
		}

		switch field {
		case iso8583TransmissionField:
			readISO8583Digits(data[:width], m.transmission[:], m.packed)
		case iso8583STANField:
			readISO8583Digits(data[:width], m.stan[:], m.packed)
		}

		data = data[width:]
	}

	return initialSize - len(data)
}

func iso8583Number(pair []byte) int {
	return int(pair[0]-'0')*10 + int(pair[1]-'0')
}

func iso8583ResponseTime(field [10]byte, observed time.Time, zone *time.Location) (time.Duration, bool) {
	if field[0] == 0 || observed.IsZero() {
		return 0, false
	}

	if zone == nil {
		zone = time.UTC
	}

	observed = observed.In(zone)
	second := iso8583Number(field[8:])
	if second >= 60 {
		return 0, false
	}

	// DE7 has no year and only whole seconds. Test the at most three matching
	// seconds in the window, including across midnight or a timezone transition.
	back := (observed.Second() - second + 60) % 60
	at := observed.Truncate(time.Second).Add(-time.Duration(back) * time.Second)
	for age := observed.Sub(at); age <= iso8583MaxResponseTime; age += time.Minute {
		if int(at.Month()) == iso8583Number(field[0:]) && at.Day() == iso8583Number(field[2:]) &&
			at.Hour() == iso8583Number(field[4:]) && at.Minute() == iso8583Number(field[6:]) {
			return age, true
		}
		at = at.Add(-time.Minute)
	}

	return 0, false
}
