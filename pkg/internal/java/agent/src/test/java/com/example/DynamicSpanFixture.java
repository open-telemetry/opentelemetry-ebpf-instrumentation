/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package com.example;

public class DynamicSpanFixture {
  public static String run() {
    return "run";
  }

  public static String runSibling() {
    return "sibling";
  }

  public static String overloaded(String value) {
    return value;
  }

  public static String overloaded(int value) {
    return Integer.toString(value);
  }

  public static String array(String[] values) {
    return values.length == 0 ? "empty" : values[0];
  }

  public static int nestedArray(Nested.ActiveValue[] values) {
    return values.length;
  }

  public static int primitiveArray(int[] values) {
    return values.length;
  }
}
