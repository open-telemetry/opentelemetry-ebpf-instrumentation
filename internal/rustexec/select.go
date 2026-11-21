// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// select.go chooses recorded layouts for a binary's compiler, architecture,
// libraries, and channel types. It preserves supported probe groups when other
// layouts are missing or ambiguous.

package rustexec // import "go.opentelemetry.io/obi/internal/rustexec"

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	MessageCallback = 1
	MessageList     = 2
	MessageRequest  = 4
)

func selectGroup(build Build, profiles []Profile, name string, dependencies []string, project func(Profile) (Layouts, bool)) (Layouts, error) {
	var selected Layouts
	found := false
	covered := map[string][]string{}
	for _, profile := range profiles {
		matches := true
		for _, dependency := range dependencies {
			matches = matches && rustCrateMatches(build.Crates[dependency], profile.Crates[dependency])
		}

		if !matches {
			continue
		}

		candidate, ok := project(profile)
		if !ok {
			continue
		}

		if found && selected != candidate {
			return Layouts{}, fmt.Errorf("%s has ambiguous recorded layouts", name)
		}

		selected, found = candidate, true
		for _, dependency := range dependencies {
			covered[dependency] = append(covered[dependency], profile.Crates[dependency]...)
		}
	}

	for _, dependency := range dependencies {
		for _, version := range build.Crates[dependency] {
			if !slices.Contains(covered[dependency], version) {
				return Layouts{}, fmt.Errorf("%s: %s %s has no recorded offset profile", name, dependency, version)
			}
		}
	}

	return selected, nil
}

// SelectLayouts returns nil when the compiler and architecture have no profile.
// With a matching profile, individual groups can remain usable alongside an error.
func SelectLayouts(build Build, database Database, channels ...string) (*Layouts, error) {
	build = database.InferBuild(build)

	var profiles []Profile
	for _, profile := range database.Profiles {
		if profile.Arch == build.Arch && profile.Rustc == build.Rustc {
			profiles = append(profiles, profile)
		}
	}

	if len(profiles) == 0 {
		return nil, fmt.Errorf("rustc %q on %s has no recorded offset profile", build.Rustc, build.Arch)
	}

	vectors, vectorErr := selectVectorLayouts(build, profiles)
	headers, headerErr := selectHeaderLayouts(build, profiles)
	http2, http2Err := selectHTTP2Layouts(build, profiles)
	tls, tlsErr := selectRustlsLayouts(build, profiles)
	messages, messageErr := selectChannelLayouts(build, profiles, channels, headers.HTTP1 != 0)

	config := assembleLayouts(vectors, headers, http2, tls, messages)
	return &config, errors.Join(vectorErr, headerErr, http2Err, tlsErr, messageErr)
}

func selectVectorLayouts(build Build, profiles []Profile) (Layouts, error) {
	return selectGroup(build, profiles, "Rust vectors", nil, func(p Profile) (Layouts, bool) {
		c := p.Config
		return Layouts{VecPtr: c.VecPtr, VecLen: c.VecLen, VecCap: c.VecCap}, true
	})
}

func selectHeaderLayouts(build Build, profiles []Profile) (Layouts, error) {
	return selectGroup(build, profiles, "Rust HTTP headers", []string{"http", "bytes"}, func(p Profile) (Layouts, bool) {
		c := p.Config
		return Layouts{
			HTTP1:         c.HTTP1,
			HeaderEntries: c.HeaderEntries,
			HeaderCount:   c.HeaderCount,
			BucketSize:    c.BucketSize,
			NamePtr:       c.NamePtr,
			NameLen:       c.NameLen,
			ValuePtr:      c.ValuePtr,
			ValueLen:      c.ValueLen,
		}, c.HTTP1 != 0
	})
}

func selectHTTP2Layouts(build Build, profiles []Profile) (Layouts, error) {
	return selectGroup(build, profiles, "Rust HTTP/2", []string{"h2", "bytes"}, func(p Profile) (Layouts, bool) {
		c := p.Config
		return Layouts{
			HTTP2:           c.HTTP2,
			H2Server:        c.H2Server,
			H2Hpack:         c.H2Hpack,
			H2StreamID:      c.H2StreamID,
			H2Fields:        c.H2Fields,
			H2Method:        c.H2Method,
			RequestHeaders:  c.RequestHeaders,
			H2StoreStreamID: c.H2StoreStreamID,
			H2StreamRefID:   c.H2StreamRefID,
			H2Prioritize:    c.H2Prioritize,
			BytesPtr:        c.BytesPtr,
			BytesLen:        c.BytesLen,
			BytesCap:        c.BytesCap,
			LimitInner:      c.LimitInner,
			LimitRemaining:  c.LimitRemaining,
		}, c.HTTP2 != 0
	})
}

func selectRustlsLayouts(build Build, profiles []Profile) (Layouts, error) {
	config, err := selectGroup(build, profiles, "Rustls", []string{"rustls"}, func(p Profile) (Layouts, bool) {
		c := p.Config
		return Layouts{
			Rustls:              c.Rustls,
			ReaderBuffer:        c.ReaderBuffer,
			TLSCommon:           c.TLSCommon,
			TLSPlaintext:        c.TLSPlaintext,
			TLSDecrypter:        c.TLSDecrypter,
			TLSClientDeframer:   c.TLSClientDeframer,
			TLSServerDeframer:   c.TLSServerDeframer,
			TLSDeframerPointer:  c.TLSDeframerPointer,
			TLSDeframerUsed:     c.TLSDeframerUsed,
			TLSExternalDeframer: c.TLSExternalDeframer,
		}, c.Rustls != 0
	})

	// Buffered-write binding is optional; its absence must not disable plaintext capture.
	buffered, _ := selectGroup(build, profiles, "Rustls buffered writes", []string{"rustls"}, func(p Profile) (Layouts, bool) {
		c := p.Config
		return Layouts{TLSSendable: c.TLSSendable, TLSEncrypter: c.TLSEncrypter}, c.TLSSendable != 0 && c.TLSEncrypter != 0
	})

	config.TLSSendable = buffered.TLSSendable
	config.TLSEncrypter = buffered.TLSEncrypter

	return config, err
}

func assembleLayouts(vectors, headers, http2, tls, messages Layouts) Layouts {
	config := tls
	config.VecPtr = vectors.VecPtr
	config.VecLen = vectors.VecLen
	config.VecCap = vectors.VecCap

	config.HTTP1 = headers.HTTP1
	config.HeaderEntries = headers.HeaderEntries
	config.HeaderCount = headers.HeaderCount
	config.BucketSize = headers.BucketSize
	config.NamePtr = headers.NamePtr
	config.NameLen = headers.NameLen
	config.ValuePtr = headers.ValuePtr
	config.ValueLen = headers.ValueLen

	config.HTTP2 = http2.HTTP2
	config.H2Server = http2.H2Server
	config.H2Hpack = http2.H2Hpack
	config.H2StreamID = http2.H2StreamID
	config.H2Fields = http2.H2Fields
	config.H2Method = http2.H2Method
	config.RequestHeaders = http2.RequestHeaders
	config.H2StoreStreamID = http2.H2StoreStreamID
	config.H2StreamRefID = http2.H2StreamRefID
	config.H2Prioritize = http2.H2Prioritize
	config.BytesPtr = http2.BytesPtr
	config.BytesLen = http2.BytesLen
	config.BytesCap = http2.BytesCap
	config.LimitInner = http2.LimitInner
	config.LimitRemaining = http2.LimitRemaining

	config.Message = messages.Message
	config.ListHead = messages.ListHead
	config.ListIndex = messages.ListIndex
	config.SlotMask = messages.SlotMask
	config.MessageTxTag = messages.MessageTxTag
	config.MessageTxSome = messages.MessageTxSome
	config.MessageTxPointer = messages.MessageTxPointer
	config.MessageRxTag = messages.MessageRxTag
	config.MessageRxSome = messages.MessageRxSome
	config.MessageRxPointer = messages.MessageRxPointer
	config.MessageRxHeaders = messages.MessageRxHeaders

	// HTTP/2 decoding needs header layouts; HTTP/1 buffer access also needs Vec offsets.
	if headers.HTTP1 == 0 {
		config.HTTP2 = 0
		config.H2Server = 0
	}

	if vectors == (Layouts{}) {
		config.HTTP1 = 0
	}

	return config
}

func selectChannelLayouts(build Build, profiles []Profile, channels []string, headersAvailable bool) (Layouts, error) {
	if len(channels) == 0 {
		return Layouts{}, nil
	}

	config, slotErr := selectChannelSlotLayouts(build, profiles)
	callback, callbackErr := selectCallbackLayouts(build, profiles, channels)
	request, requestErr := selectRequestLayouts(build, profiles, channels)

	if callback.Message != 0 {
		config.Message |= MessageCallback
		config.MessageTxTag = callback.MessageTxTag
		config.MessageTxSome = callback.MessageTxSome
		config.MessageTxPointer = callback.MessageTxPointer
		config.MessageRxTag = callback.MessageRxTag
		config.MessageRxSome = callback.MessageRxSome
		config.MessageRxPointer = callback.MessageRxPointer
	}

	if request.Message != 0 && headersAvailable {
		config.Message |= MessageRequest
		config.MessageRxHeaders = request.MessageRxHeaders
		config.MessageRxTag = request.MessageRxTag
	}

	// Missing alternatives are harmless when another handoff identity remains usable.
	if config.Message != 0 {
		return config, nil
	}

	return config, errors.Join(slotErr, callbackErr, requestErr)
}

func selectChannelSlotLayouts(build Build, profiles []Profile) (Layouts, error) {
	return selectGroup(build, profiles, "Tokio channel slots", []string{"tokio"}, func(p Profile) (Layouts, bool) {
		var selected Layouts
		for _, layout := range p.Channels {
			candidate := Layouts{
				Message:   MessageList,
				ListHead:  layout.ListHead,
				ListIndex: layout.ListIndex,
				SlotMask:  layout.SlotMask,
			}
			if selected.Message != 0 && selected != candidate {
				return Layouts{}, false
			}
			selected = candidate
		}
		return selected, selected.Message != 0
	})
}

func selectCallbackLayouts(build Build, profiles []Profile, channels []string) (Layouts, error) {
	var message Layouts
	var failures []error
	compatible := true

	for _, channel := range channels {
		selected, err := selectGroup(build, profiles, "Hyper callback "+channel, []string{"tokio", "hyper", "reqwest"}, func(p Profile) (Layouts, bool) {
			layout, ok := p.Channels[channel]
			return Layouts{
				Message:          MessageCallback,
				MessageTxTag:     layout.TxTag,
				MessageTxSome:    layout.TxSome,
				MessageTxPointer: layout.TxPointer,
				MessageRxTag:     layout.RxTag,
				MessageRxSome:    layout.RxSome,
				MessageRxPointer: layout.RxPointer,
			}, ok
		})

		failures = append(failures, err)
		if selected.Message == 0 {
			compatible = false
		}

		if message.Message != 0 && selected != message {
			compatible = false
		}
		message = selected
	}

	if !compatible {
		return Layouts{}, errors.Join(failures...)
	}

	return message, errors.Join(failures...)
}

func selectRequestLayouts(build Build, profiles []Profile, channels []string) (Layouts, error) {
	var request Layouts
	var failures []error
	compatible := true
	for _, channel := range channels {
		dependencies := []string{"tokio", "hyper", "http", "bytes"}
		if strings.Contains(channel, "reqwest::") {
			dependencies = append(dependencies, "reqwest")
		}

		selected, err := selectGroup(build, profiles, "Hyper request identity "+channel, dependencies, func(p Profile) (Layouts, bool) {
			layout, ok := p.Channels[channel]
			return Layouts{
				Message:          MessageRequest,
				MessageRxTag:     layout.RxTag,
				MessageRxHeaders: layout.RxHeaders,
			}, ok && layout.Request
		})

		failures = append(failures, err)
		if selected.Message == 0 {
			compatible = false
		}

		if request.Message != 0 && selected != request {
			compatible = false
		}
		request = selected
	}

	if !compatible {
		return Layouts{}, errors.Join(failures...)
	}

	return request, errors.Join(failures...)
}
