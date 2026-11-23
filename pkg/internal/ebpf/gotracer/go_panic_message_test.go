// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"fmt"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoBoundsErrorMessageConversion(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    string
	}{
		{"go1.17.13", "runtime error: cannot convert slice with length 3 to pointer to array with length 5"},
		{"go1.19.13", "runtime error: cannot convert slice with length 3 to pointer to array with length 5"},
		{"go1.19.13 X:boringcrypto", "runtime error: cannot convert slice with length 3 to pointer to array with length 5"},
		{"go1.24.0 X:boringcrypto", "runtime error: cannot convert slice with length 3 to array or pointer to array with length 5"},
		{"go1.20", "runtime error: cannot convert slice with length 3 to array or pointer to array with length 5"},
		{"go1.27.3", "runtime error: cannot convert slice with length 3 to array or pointer to array with length 5"},
		{"", ""},
	} {
		t.Run(tc.version, func(t *testing.T) {
			require.Equal(t, tc.want, goBoundsErrorMessage(5, 3, true, goBoundsConvert, tc.version))
		})
	}
	for _, arrayValue := range []bool{false, true} {
		t.Run(fmt.Sprint("array value=", arrayValue), func(t *testing.T) {
			items := []int{1, 2, 3}
			var value any
			func() {
				defer func() { value = recover() }()
				if arrayValue {
					panic([5]int(items))
				}
				panic((*[5]int)(items))
			}()
			require.NotNil(t, value)
			require.Equal(t, fmt.Sprint(value), goBoundsErrorMessage(5, 3, true, goBoundsConvert, runtime.Version()))
		})
	}
}

func TestGoBoundsErrorMessageThreeIndexSlice(t *testing.T) {
	for _, tc := range []struct {
		name  string
		code  uint8
		y     uint64
		panic func(int64)
	}{
		{"array maximum", goBoundsSlice3Alen, 3, func(x int64) {
			items := [3]int{1, 2, 3}
			panic(items[0:1:x])
		}},
		{"slice maximum", goBoundsSlice3Acap, 3, func(x int64) {
			items := []int{1, 2, 3}
			panic(items[0:1:x])
		}},
		{"end", goBoundsSlice3B, 3, func(x int64) {
			items := []int{1, 2, 3}
			panic(items[0:x:3])
		}},
		{"start", goBoundsSlice3C, 1, func(x int64) {
			items := []int{1, 2, 3}
			panic(items[x:1:3])
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, x := range []int64{5, -1, -1 << 63} {
				t.Run(strconv.FormatInt(x, 10), func(t *testing.T) {
					var value any
					func() {
						defer func() { value = recover() }()
						tc.panic(x)
					}()
					require.NotNil(t, value)
					require.Equal(t, fmt.Sprint(value), goBoundsErrorMessage(uint64(x), tc.y, true, tc.code, runtime.Version()))
				})
			}
		})
	}
}

func TestGoBoundsErrorMessageIndex(t *testing.T) {
	for _, tc := range []struct {
		name   string
		x      uint64
		signed bool
	}{
		{name: "positive", x: 5, signed: true},
		{name: "negative", x: ^uint64(0), signed: true},
		{name: "minimum signed", x: 1 << 63, signed: true},
		{name: "maximum unsigned", x: ^uint64(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := []int{1, 2, 3}
			var value any
			func() {
				defer func() { value = recover() }()
				if tc.signed {
					panic(items[int64(tc.x)])
				}
				panic(items[tc.x])
			}()
			require.NotNil(t, value)
			require.Equal(t, fmt.Sprint(value), goBoundsErrorMessage(tc.x, uint64(len(items)), tc.signed, goBoundsIndex, runtime.Version()))
		})
	}
}

func TestGoBoundsErrorMessageSliceCapacity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		x      uint64
		signed bool
	}{
		{name: "positive", x: 5, signed: true},
		{name: "negative", x: ^uint64(0), signed: true},
		{name: "minimum signed", x: 1 << 63, signed: true},
		{name: "maximum unsigned", x: ^uint64(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := []int{1, 2, 3}
			var value any
			func() {
				defer func() { value = recover() }()
				if tc.signed {
					panic(items[:int64(tc.x)])
				}
				panic(items[:tc.x])
			}()
			require.NotNil(t, value)
			require.Equal(t, fmt.Sprint(value), goBoundsErrorMessage(tc.x, uint64(cap(items)), tc.signed, goBoundsSliceAcap, runtime.Version()))
		})
	}
}

func TestGoBoundsErrorMessageSliceStart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		x      uint64
		signed bool
	}{
		{name: "after end", x: 2, signed: true},
		{name: "negative", x: ^uint64(0), signed: true},
		{name: "minimum signed", x: 1 << 63, signed: true},
		{name: "maximum unsigned", x: ^uint64(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := []int{1, 2, 3}
			var value any
			func() {
				defer func() { value = recover() }()
				if tc.signed {
					panic(items[int64(tc.x):1])
				}
				panic(items[tc.x:1])
			}()
			require.NotNil(t, value)
			require.Equal(t, fmt.Sprint(value), goBoundsErrorMessage(tc.x, 1, tc.signed, goBoundsSliceB, runtime.Version()))
		})
	}
}

func TestGoBoundsErrorMessageSliceLength(t *testing.T) {
	for _, tc := range []struct {
		name   string
		x      uint64
		signed bool
	}{
		{name: "positive", x: 5, signed: true},
		{name: "negative", x: ^uint64(0), signed: true},
		{name: "minimum signed", x: 1 << 63, signed: true},
		{name: "maximum unsigned", x: ^uint64(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := "abc"
			var value any
			func() {
				defer func() { value = recover() }()
				if tc.signed {
					panic(text[:int64(tc.x)])
				}
				panic(text[:tc.x])
			}()
			require.NotNil(t, value)
			require.Equal(t, fmt.Sprint(value), goBoundsErrorMessage(tc.x, uint64(len(text)), tc.signed, goBoundsSliceAlen, runtime.Version()))
		})
	}
}
