// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"

import (
	"encoding/binary"
	"errors"
)

const (
	Int8Len            = 1
	Int16Len           = 2
	Int32Len           = 4
	Int64Len           = 8
	UUIDLen            = 16
	MinKafkaRequestLen = // 14
	Int32Len +         // MessageSize
		Int16Len + // APIKey
		Int16Len + // APIVersion
		Int32Len + // CorrelationID
		Int16Len // Length of ClientID
	MinKafkaResponseLen = Int32Len + // MessageSize
		Int32Len // CorrelationID
	KafkaMaxPayloadLen = 20 * 1024 * 1024 // 20 MB max, 1MB is default for most Kafka installations
)

type KafkaAPIKey int8

const (
	APIKeyProduce  KafkaAPIKey = 0
	APIKeyFetch    KafkaAPIKey = 1
	APIKeyMetadata KafkaAPIKey = 3
)

type UUID [UUIDLen]byte

type KafkaRequestHeader struct {
	MessageSize   int32
	APIKey        KafkaAPIKey
	APIVersion    int16
	CorrelationID int32
	ClientID      string
}

type KafkaResponseHeader struct {
	MessageSize   int32
	CorrelationID int32
}

// byteReader is the sequential-read interface satisfied by *LargeBuffer.
// Defined here so sub-packages don't need to import ebpfcommon (which would be circular).
type byteReader interface {
	ReadN(n int) ([]byte, error)
	Peek(n int) ([]byte, error)
	Skip(n int) error
	Remaining() int
}

func ParseKafkaRequestHeader(r byteReader) (*KafkaRequestHeader, error) {
	if r.Remaining() < MinKafkaRequestLen {
		return nil, errors.New("packet too short for Kafka request header")
	}

	msgSizeBytes, err := r.ReadN(Int32Len)
	if err != nil {
		return nil, err
	}
	apiKeyBytes, err := r.ReadN(Int16Len)
	if err != nil {
		return nil, err
	}
	apiVersionBytes, err := r.ReadN(Int16Len)
	if err != nil {
		return nil, err
	}
	correlationIDBytes, err := r.ReadN(Int32Len)
	if err != nil {
		return nil, err
	}
	header := &KafkaRequestHeader{
		MessageSize:   int32(binary.BigEndian.Uint32(msgSizeBytes)),
		APIKey:        KafkaAPIKey(int16(binary.BigEndian.Uint16(apiKeyBytes))),
		APIVersion:    int16(binary.BigEndian.Uint16(apiVersionBytes)),
		CorrelationID: int32(binary.BigEndian.Uint32(correlationIDBytes)),
	}

	clientIDSizeBytes, err := r.ReadN(Int16Len)
	if err != nil {
		return nil, err
	}
	clientIDSize := int16(binary.BigEndian.Uint16(clientIDSizeBytes))

	if err := validateKafkaRequestHeader(header); err != nil {
		return nil, err
	}
	if clientIDSize < 0 {
		return nil, errors.New("invalid client ID size")
	}
	if clientIDSize == 0 {
		header.ClientID = ""
		return header, nil
	}
	if r.Remaining() < int(clientIDSize) {
		return nil, errors.New("packet too short for client ID")
	}
	clientIDBytes, err := r.ReadN(int(clientIDSize))
	if err != nil {
		return nil, err
	}
	header.ClientID = string(clientIDBytes)

	if err := skipTaggedFields(r, header); err != nil {
		return nil, err
	}
	return header, nil
}

func ParseKafkaResponseHeader(r byteReader, requestHeader *KafkaRequestHeader) (*KafkaResponseHeader, error) {
	if r.Remaining() < MinKafkaResponseLen {
		return nil, errors.New("packet too short for Kafka response header")
	}
	msgSizeBytes, err := r.ReadN(Int32Len)
	if err != nil {
		return nil, err
	}
	correlationIDBytes, err := r.ReadN(Int32Len)
	if err != nil {
		return nil, err
	}
	header := &KafkaResponseHeader{
		MessageSize:   int32(binary.BigEndian.Uint32(msgSizeBytes)),
		CorrelationID: int32(binary.BigEndian.Uint32(correlationIDBytes)),
	}

	if err := validateKafkaResponseHeader(header, requestHeader); err != nil {
		return nil, err
	}
	if err := skipTaggedFields(r, requestHeader); err != nil {
		return nil, err
	}
	return header, nil
}

func skipTaggedFields(r byteReader, header *KafkaRequestHeader) error {
	if !isFlexible(header) {
		return nil // no tagged fields to skip for non-flexible versions
	}
	taggedFieldsLen, err := readUnsignedVarint(r)
	if err != nil {
		return err
	}
	for range taggedFieldsLen {
		if _, err = readUnsignedVarint(r); err != nil { // read tag ID
			return err
		}
		tagLen, err := readUnsignedVarint(r) // read tag length
		if err != nil {
			return err
		}
		if err = r.Skip(tagLen); err != nil { // skip tag value
			return err
		}
	}
	return nil
}

func validateKafkaRequestHeader(header *KafkaRequestHeader) error {
	if header.MessageSize < int32(MinKafkaRequestLen) || header.APIVersion < 0 {
		return errors.New("invalid Kafka request header: size or version is negative")
	}

	if header.MessageSize > KafkaMaxPayloadLen {
		return errors.New("invalid Kafka request header: message size exceeds maximum payload length")
	}

	switch header.APIKey {
	case APIKeyFetch:
		if header.APIVersion > 18 { // latest: Fetch Request (Version: 17)
			return errors.New("invalid Kafka request header: unsupported API key version for Fetch")
		}
	case APIKeyProduce:
		if header.APIVersion > 13 { // latest: Produce Request (Version: 12)
			return errors.New("invalid Kafka request header: unsupported API key version for Produce")
		}
	case APIKeyMetadata:
		if header.APIVersion < 10 || header.APIVersion > 13 { // latest: Metadata Request (Version: 13), only versions 10-13 contain topic_id which we are interested in
			return errors.New("invalid Kafka request header: unsupported API key version for Metadata")
		}
	default:
		return errors.New("invalid Kafka request header: unsupported API key")
	}
	if header.CorrelationID < 0 {
		return errors.New("invalid Kafka request header: correlation ID is negative")
	}
	return nil
}

func validateKafkaResponseHeader(header *KafkaResponseHeader, requestHeader *KafkaRequestHeader) error {
	if header.MessageSize < MinKafkaResponseLen {
		return errors.New("invalid Kafka response header: size too small")
	}

	if header.MessageSize > KafkaMaxPayloadLen {
		return errors.New("invalid Kafka response header: message size exceeds maximum payload length")
	}

	if header.CorrelationID < 0 {
		return errors.New("invalid Kafka response header: correlation ID is negative")
	}
	if header.CorrelationID != requestHeader.CorrelationID {
		return errors.New("invalid Kafka response header: correlation ID does not match request header")
	}
	return nil
}

// isFlexible checks for each API key if the version is flexible.
// a flexible version uses a dynamic size for arrays and strings
func isFlexible(header *KafkaRequestHeader) bool {
	switch header.APIKey {
	// https://github.com/apache/kafka/blob/9983331d917fe8f57c37c88f0749b757e5af0c87/clients/src/main/resources/common/message/ProduceRequest.json#L51
	case APIKeyProduce:
		return header.APIVersion >= 9
	// https://github.com/apache/kafka/blob/9983331d917fe8f57c37c88f0749b757e5af0c87/clients/src/main/resources/common/message/FetchRequest.json#L62C4-L62C20
	case APIKeyFetch:
		return header.APIVersion >= 12
	// https://github.com/apache/kafka/blob/9983331d917fe8f57c37c88f0749b757e5af0c87/clients/src/main/resources/common/message/MetadataRequest.json#L22
	case APIKeyMetadata:
		return header.APIVersion >= 9
	default:
		return false
	}
}

func readArrayLength(r byteReader, header *KafkaRequestHeader) (int, error) {
	if isFlexible(header) {
		size, err := readUnsignedVarint(r)
		if err != nil {
			return 0, err
		}
		if size == 0 {
			return 0, nil // return 0 for null
		}
		return size - 1, nil
	}
	return readInt32(r)
}

func readUUID(r byteReader) (*UUID, error) {
	b, err := r.ReadN(UUIDLen)
	if err != nil {
		return nil, errors.New("packet too short for topic UUID")
	}
	var uuid UUID
	copy(uuid[:], b)
	return &uuid, nil
}

func readString(r byteReader, header *KafkaRequestHeader, nullable bool) (string, error) {
	size, err := readStringLength(r, header, nullable)
	if err != nil {
		return "", err
	}
	if nullable && size == 0 {
		return "", nil // return empty string for null
	}
	if r.Remaining() < size {
		return "", errors.New("string size exceeds packet size")
	}
	b, err := r.ReadN(size)
	if err != nil {
		return "", errors.New("string size exceeds packet size")
	}
	if !validateKafkaString(b, size) {
		return "", errors.New("invalid characters in string")
	}
	return string(b), nil
}

func validateKafkaString(pkt []byte, size int) bool {
	for j := range size {
		ch := pkt[j]
		if ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') || ('0' <= ch && ch <= '9') || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func readStringLength(r byteReader, header *KafkaRequestHeader, nullable bool) (int, error) {
	if !isFlexible(header) {
		// length is stored as a fixed size int16
		if r.Remaining() < Int16Len {
			return 0, errors.New("packet too short for string length")
		}
		b, err := r.ReadN(Int16Len)
		if err != nil {
			return 0, errors.New("packet too short for string length")
		}
		size := int16(binary.BigEndian.Uint16(b))
		if nullable && size == -1 {
			return 0, nil // return 0 for null
		}
		if size < 1 {
			return 0, errors.New("invalid string size")
		}
		return int(size), nil
	}

	// length is stored as a varint
	size, err := readUnsignedVarint(r)
	if err != nil {
		return 0, err
	}
	if nullable && size == 0 {
		return 0, nil // return 0 for null
	}
	if size <= 0 {
		return 0, errors.New("invalid string size")
	}
	size-- // size is stored as a varint, so we subtract 1
	if size < 0 {
		return 0, errors.New("invalid string size")
	}
	return size, nil
}

func readUnsignedVarint(r byteReader) (int, error) {
	value := 0
	i := 0
	for {
		if r.Remaining() == 0 {
			return 0, errors.New("data ended before varint was complete")
		}
		b, err := r.ReadN(1)
		if err != nil {
			return 0, err
		}
		if (b[0] & 0x80) == 0 {
			value |= int(b[0]) << i
			return value, nil
		}
		value |= int(b[0]&0x7F) << i
		i += 7
		if i > 28 {
			return 0, errors.New("illegal varint")
		}
	}
}

func readInt32(r byteReader) (int, error) {
	b, err := r.ReadN(Int32Len)
	if err != nil {
		return 0, errors.New("data too short for int32")
	}
	return int(binary.BigEndian.Uint32(b)), nil
}

func readInt64(r byteReader) (int64, error) {
	b, err := r.ReadN(Int64Len)
	if err != nil {
		return 0, errors.New("data too short for int64")
	}
	return int64(binary.BigEndian.Uint64(b)), nil
}
