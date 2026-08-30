/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import org.junit.jupiter.api.Test;

/**
 * Guards the version marker OBI relies on to detect agents it cannot talk to. Losing the resource,
 * or renaming the property inside it, would silently disable that detection.
 */
class AgentVersionTest {

  @Test
  void readsTheVersionShippedWithTheAgent() throws IOException {
    String version = AgentVersion.read();

    assertFalse(version.isEmpty());
    assertEquals(version.trim(), version);
  }
}
