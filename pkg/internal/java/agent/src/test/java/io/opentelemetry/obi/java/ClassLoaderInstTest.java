/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static net.bytebuddy.dynamic.loading.ClassInjector.UsingInstrumentation.Target.BOOTSTRAP;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.opentelemetry.obi.java.instrumentations.ClassLoaderInst;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.util.Collections;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.dynamic.loading.ClassInjector;
import org.junit.jupiter.api.Test;

class ClassLoaderInstTest {
  private static final String HELPER_NAME = "io.opentelemetry.obi.java.testutil.BootstrapHelper";

  @Test
  void restrictiveClassLoaderCanResolveBootstrapHelper() throws Exception {
    Instrumentation instrumentation = ByteBuddyAgent.install();
    Class<?> bootstrapHelper = injectBootstrapHelper(instrumentation);

    ClassLoader rejectingLoader =
        new ClassLoader() {
          @Override
          public Class<?> loadClass(String name) throws ClassNotFoundException {
            if (name.equals(HELPER_NAME)) {
              throw new ClassNotFoundException(name);
            }
            return super.loadClass(name);
          }
        };
    assertThrows(ClassNotFoundException.class, () -> rejectingLoader.loadClass(HELPER_NAME));

    ClassFileTransformer transformer =
        new AgentBuilder.Default()
            .disableClassFormatChanges()
            .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
            .type(named("testutil.RestrictiveClassLoader"))
            .transform(ClassLoaderInst.transformer())
            .installOn(instrumentation);

    try {
      ClassLoader loader =
          (ClassLoader)
              Class.forName("testutil.RestrictiveClassLoader")
                  .getDeclaredConstructor()
                  .newInstance();

      assertSame(bootstrapHelper, loader.loadClass(HELPER_NAME));
    } finally {
      instrumentation.removeTransformer(transformer);
    }
  }

  private static Class<?> injectBootstrapHelper(Instrumentation instrumentation) throws Exception {
    String resourceName = HELPER_NAME.replace('.', '/') + ".class";
    byte[] classBytes;
    try (InputStream input =
        ClassLoaderInstTest.class.getClassLoader().getResourceAsStream(resourceName)) {
      if (input == null) {
        throw new IllegalStateException("Missing test class resource " + resourceName);
      }
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      int read;
      while ((read = input.read(buffer)) != -1) {
        output.write(buffer, 0, read);
      }
      classBytes = output.toByteArray();
    }

    File tempDir = Files.createTempDirectory("obi-classloader-test").toFile();
    tempDir.deleteOnExit();
    ClassInjector.UsingInstrumentation.of(tempDir, BOOTSTRAP, instrumentation)
        .injectRaw(Collections.singletonMap(HELPER_NAME, classBytes));

    return Class.forName(HELPER_NAME, false, null);
  }
}
