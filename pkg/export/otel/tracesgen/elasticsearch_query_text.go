// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	elasticsearchSanitizedValue = `"?"`
	// elasticsearchBodySeparator joins the values of NDJSON bodies, such as
	// those of _msearch and _bulk.
	elasticsearchBodySeparator = ";"
)

// sanitizeElasticsearchBody replaces every string, number, boolean and null in
// a JSON or NDJSON request body with "?", keeping field names and structure.
// It returns an empty string when the body is not valid JSON, so that no part
// of it is exported unsanitized.
func sanitizeElasticsearchBody(body string) string {
	if !utf8.ValidString(body) {
		return ""
	}

	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()

	var values []string
	var valueEnd int64
	for dec.More() {
		// More skips whitespace, so InputOffset is now the start of the next
		// value. NDJSON values must be on separate lines.
		if len(values) > 0 && !strings.Contains(body[valueEnd:dec.InputOffset()], "\n") {
			return ""
		}

		var out strings.Builder
		if err := writeSanitizedJSONValue(dec, &out); err != nil {
			return ""
		}
		values = append(values, out.String())
		valueEnd = dec.InputOffset()
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ""
	}
	return strings.Join(values, elasticsearchBodySeparator)
}

func writeSanitizedJSONValue(dec *json.Decoder, out *strings.Builder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}

	switch token {
	case json.Delim('{'):
		return writeSanitizedJSONObject(dec, out)
	case json.Delim('['):
		return writeSanitizedJSONArray(dec, out)
	}

	out.WriteString(elasticsearchSanitizedValue)
	return nil
}

func writeSanitizedJSONObject(dec *json.Decoder, out *strings.Builder) error {
	out.WriteByte('{')
	for i := 0; dec.More(); i++ {
		if i > 0 {
			out.WriteByte(',')
		}

		key, err := dec.Token()
		if err != nil {
			return err
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			return err
		}
		out.Write(encodedKey)
		out.WriteByte(':')

		if err := writeSanitizedJSONValue(dec, out); err != nil {
			return err
		}
	}

	if _, err := dec.Token(); err != nil {
		return err
	}
	out.WriteByte('}')
	return nil
}

func writeSanitizedJSONArray(dec *json.Decoder, out *strings.Builder) error {
	out.WriteByte('[')
	for i := 0; dec.More(); i++ {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := writeSanitizedJSONValue(dec, out); err != nil {
			return err
		}
	}

	if _, err := dec.Token(); err != nil {
		return err
	}
	out.WriteByte(']')
	return nil
}
