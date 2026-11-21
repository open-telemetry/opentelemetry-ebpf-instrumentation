// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"debug/elf"
	_ "embed"
	"encoding/json"
	"sync"

	"go.opentelemetry.io/obi/internal/rustexec"
)

//go:embed rust_offsets.json
var rustOffsetData []byte

// The embedded database never changes, and layout selection only reads it,
// so every attachment shares one decoded copy.
var rustOffsetDatabase = sync.OnceValues(func() (rustexec.Database, error) {
	var database rustexec.Database
	err := json.Unmarshal(rustOffsetData, &database)
	return database, err
})

func resolveRustProtocolLayouts(f *elf.File, channels ...string) (*BpfRustProtocolConfigT, error) {
	build, err := rustexec.ReadBuild(f)
	if err != nil {
		return nil, err
	}
	database, err := rustOffsetDatabase()
	if err != nil {
		return nil, err
	}
	return selectRustProtocolLayouts(build, database, channels...)
}

func selectRustProtocolLayouts(build rustexec.Build, database rustexec.Database, channels ...string) (*BpfRustProtocolConfigT, error) {
	config, err := rustexec.SelectLayouts(build, database, channels...)
	if config == nil {
		return nil, err
	}
	return &BpfRustProtocolConfigT{
		VecPtr:              config.VecPtr,
		VecLen:              config.VecLen,
		VecCap:              config.VecCap,
		BytesPtr:            config.BytesPtr,
		BytesLen:            config.BytesLen,
		BytesCap:            config.BytesCap,
		LimitInner:          config.LimitInner,
		LimitRemaining:      config.LimitRemaining,
		H2StreamId:          config.H2StreamID,
		H2Fields:            config.H2Fields,
		H2Method:            config.H2Method,
		RequestHeaders:      config.RequestHeaders,
		HeaderEntries:       config.HeaderEntries,
		HeaderCount:         config.HeaderCount,
		BucketSize:          config.BucketSize,
		NamePtr:             config.NamePtr,
		NameLen:             config.NameLen,
		ValuePtr:            config.ValuePtr,
		ValueLen:            config.ValueLen,
		ReaderBuffer:        config.ReaderBuffer,
		TlsCommon:           config.TLSCommon,
		TlsClientDeframer:   config.TLSClientDeframer,
		TlsServerDeframer:   config.TLSServerDeframer,
		TlsDeframerPointer:  config.TLSDeframerPointer,
		TlsDeframerUsed:     config.TLSDeframerUsed,
		TlsPlaintext:        config.TLSPlaintext,
		TlsDecrypter:        config.TLSDecrypter,
		TlsEncrypter:        config.TLSEncrypter,
		TlsSendable:         config.TLSSendable,
		H2StoreStreamId:     config.H2StoreStreamID,
		H2StreamRefId:       config.H2StreamRefID,
		H2Prioritize:        config.H2Prioritize,
		ListHead:            config.ListHead,
		ListIndex:           config.ListIndex,
		SlotMask:            config.SlotMask,
		MessageTxTag:        config.MessageTxTag,
		MessageTxSome:       config.MessageTxSome,
		MessageTxPointer:    config.MessageTxPointer,
		MessageRxTag:        config.MessageRxTag,
		MessageRxSome:       config.MessageRxSome,
		MessageRxPointer:    config.MessageRxPointer,
		MessageRxHeaders:    config.MessageRxHeaders,
		Http1:               config.HTTP1,
		Http2:               config.HTTP2,
		Rustls:              config.Rustls,
		Inject:              config.Inject,
		H2Server:            config.H2Server,
		Message:             config.Message,
		TlsExternalDeframer: config.TLSExternalDeframer,
		H2Hpack:             config.H2Hpack,
	}, err
}
