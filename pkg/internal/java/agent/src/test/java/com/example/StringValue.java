/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package com.example;

import java.util.function.Supplier;

public class StringValue implements Supplier<String> {
  @Override
  public String get() {
    return "value";
  }
}
