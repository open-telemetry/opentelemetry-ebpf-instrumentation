/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package com.example;

public class Nested {
  public static final class Value {}

  public static String accept(Value value) {
    return "accepted";
  }
}
