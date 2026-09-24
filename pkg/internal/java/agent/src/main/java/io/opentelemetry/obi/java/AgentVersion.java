/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Version of the contract between this agent and OBI.
 *
 * <p>A Java agent cannot be unloaded or replaced in a running JVM. When OBI finds one of its agents
 * already attached to a process, it compares {@link #PROPERTY} with the version of the agent it
 * would inject and reports an error when the two differ, rather than reporting telemetry through an
 * agent it no longer understands.
 */
public final class AgentVersion {

  /** JVM system property the agent publishes when it loads. */
  public static final String PROPERTY = "otel.obi.java.agent.version";

  private static final String RESOURCE = "/obi-java-agent-version.properties";

  private AgentVersion() {}

  /** Reads the version from the JAR resource that OBI also reads before injecting the agent. */
  public static String read() throws IOException {
    try (InputStream in = AgentVersion.class.getResourceAsStream(RESOURCE)) {
      if (in == null) {
        throw new IOException("missing " + RESOURCE + " in the agent jar");
      }

      Properties properties = new Properties();
      properties.load(in);

      String version = properties.getProperty(PROPERTY, "").trim();
      if (version.isEmpty()) {
        throw new IOException("missing " + PROPERTY + " in " + RESOURCE);
      }

      return version;
    }
  }
}
