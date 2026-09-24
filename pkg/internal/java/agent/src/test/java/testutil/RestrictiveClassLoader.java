/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package testutil;

public class RestrictiveClassLoader extends ClassLoader {
  @Override
  public Class<?> loadClass(String name) throws ClassNotFoundException {
    if (name.startsWith("io.opentelemetry.obi.java.")) {
      throw new ClassNotFoundException(name);
    }
    return super.loadClass(name);
  }
}
