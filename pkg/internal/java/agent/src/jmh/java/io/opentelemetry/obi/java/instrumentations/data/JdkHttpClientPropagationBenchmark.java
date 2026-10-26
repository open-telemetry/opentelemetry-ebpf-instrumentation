/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.*;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 2, time = 1)
@Measurement(iterations = 3, time = 1)
@Fork(1)
@State(Scope.Thread)
public class JdkHttpClientPropagationBenchmark {
  @Param({"128", "1024", "8192"})
  public int size;

  @Param({"false", "true"})
  public boolean applicationHeader;

  private List<ByteBuffer> buffers;

  @Setup
  public void setup() {
    char[] value = new char[size];
    Arrays.fill(value, 'x');
    byte[] bytes =
        ("GET / HTTP/1.1\r\nX-Value: "
                + new String(value)
                + "\r\n"
                + (applicationHeader ? "TrAcEpArEnT: application-owned\r\n" : "")
                + "\r\n")
            .getBytes(StandardCharsets.ISO_8859_1);
    int split = bytes.length / 2;
    buffers =
        Arrays.asList(
            ByteBuffer.wrap(bytes, 0, split), ByteBuffer.wrap(bytes, split, bytes.length - split));
  }

  @Benchmark
  public ByteBuffer prepareHeaders() {
    return JdkHttpClientPropagation.prepareHeaders(buffers);
  }

  @Benchmark
  public String prototypePreparation() {
    StringBuilder text = new StringBuilder();
    for (ByteBuffer buffer : buffers) {
      text.append(StandardCharsets.ISO_8859_1.decode(buffer.duplicate()));
    }
    String headers = text.toString();
    if (!headers.endsWith("\r\n\r\n")) {
      return null;
    }
    for (String line : headers.split("\r\n")) {
      int colon = line.indexOf(':');
      if (colon >= 0 && "traceparent".equalsIgnoreCase(line.substring(0, colon))) {
        return null;
      }
    }
    return headers.substring(0, headers.length() - 2);
  }
}
