/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class ByteBufferExtractor {
  public static final int MAX_SIZE = 1024;
  public static final int MAX_KEY_SIZE = 64;

  // Made for JDK8 support
  public static java.nio.Buffer b(ByteBuffer buffer) {
    return (java.nio.Buffer) buffer;
  }

  // This deals with buffers that have already been consumed, as in, the data we
  // want is from the start of the buffer up to the position.
  public static ByteBuffer flattenUsedByteBufferArray(ByteBuffer[] dsts, int len) {
    ByteBuffer dstBuffer = ByteBuffer.allocate(Math.min(len, MAX_SIZE));
    if (dsts == null) {
      return dstBuffer;
    }
    int consumed = 0;
    for (int i = 0; i < dsts.length && consumed <= b(dstBuffer).limit(); i++) {
      // Skip null buffers
      if (dsts[i] == null) {
        continue;
      }
      // we want to read 0 -> oldPos (the data that was just read)
      int oldPos = b(dsts[i]).position();

      // Create a duplicate to avoid modifying the original buffer
      ByteBuffer dup = dsts[i].duplicate();
      ((java.nio.Buffer) dup).position(0);
      ((java.nio.Buffer) dup).limit(oldPos);

      if (b(dup).remaining() <= b(dstBuffer).remaining()) {
        dstBuffer.put(dup);
      } else {
        ByteBuffer slice = dup.slice();
        b(slice).limit(Math.min(b(slice).remaining(), b(dstBuffer).remaining()));
        dstBuffer.put(slice);
      }

      // we'd read the full size (up to oldPos) or partial. It's ok to boost the
      // consumed value by oldPos, since we'll be done with the loop anyway if we
      // read up to the max.
      consumed += oldPos;
    }

    return dstBuffer;
  }

  // This deals with buffers that are about to be read, they are freshly made for
  // the Java program to consume. We want to read from their pos to the limit.
  public static ByteBuffer flattenFreshByteBufferArray(ByteBuffer[] srcs) {
    ByteBuffer dstBuffer = ByteBuffer.allocate(MAX_SIZE);
    if (srcs == null) {
      return dstBuffer;
    }
    int consumed = 0;
    for (int i = 0; i < srcs.length && consumed <= b(dstBuffer).limit(); i++) {
      // Skip null buffers
      if (srcs[i] == null) {
        continue;
      }
      // the remaining = limit - pos is how much we'll consume, unless the
      // destination buffer will fill up to the max.
      int remaining = b(srcs[i]).remaining();

      // Create a duplicate to avoid modifying the original buffer
      ByteBuffer dup = srcs[i].duplicate();

      if (b(dup).remaining() <= b(dstBuffer).remaining()) {
        dstBuffer.put(dup);
      } else {
        ByteBuffer slice = dup.slice();
        b(slice).limit(Math.min(b(slice).remaining(), b(dstBuffer).remaining()));
        dstBuffer.put(slice);
      }

      // bump the consumed by the original remaining, if we partially read we are
      // fine with over calculating, since we'll be done with the loop.
      consumed += remaining;
    }

    return dstBuffer;
  }

  // this is same as flattenFreshByteBufferArray, except we read only one buffer.
  public static ByteBuffer fromFreshBuffer(ByteBuffer src, int len) {
    int bufSize = (src == null) ? 0 : Math.min(b(src).remaining(), Math.min(len, MAX_SIZE));
    ByteBuffer dstBuffer = ByteBuffer.allocate(bufSize);
    if (src != null) {
      // save state
      int oldPos = b(src).position();
      int oldLimit = b(src).limit();
      // make a slice so that we can add limit to the max copied size
      ByteBuffer slice = src.slice();
      b(slice).limit(bufSize);
      dstBuffer.put(slice);
      // restore the position
      b(src).position(oldPos);
      b(src).limit(oldLimit);
    }

    return dstBuffer;
  }

  // same concept as reading used bytes, except we produce a string from
  // the values that we'll be using as unique keys
  public static String keyFromUsedBuffer(ByteBuffer buf) {
    // Save original state
    int oldPosition = b(buf).position();
    // we'll be reading 0 -> oldPosition
    int keySize = Math.min(oldPosition, MAX_KEY_SIZE);

    // Create a duplicate to avoid modifying the original buffer
    // duplicate() shares the same backing data but has independent position/limit
    ByteBuffer dup = buf.duplicate();
    b(dup).position(0);
    b(dup).limit(oldPosition);

    byte[] bytes = new byte[keySize];
    dup.get(bytes);

    return Arrays.toString(bytes);
  }

  // same concept as reading fresh (unconsumed) bytes, except we produce a string from
  // the values that we'll be using as unique keys
  public static String keyFromFreshBuffer(ByteBuffer buf) {
    // we are reading position -> limit
    int keySize = Math.min(b(buf).remaining(), MAX_KEY_SIZE);

    // Create a duplicate to avoid modifying the original buffer
    ByteBuffer dup = buf.duplicate();
    byte[] bytes = new byte[keySize];
    dup.get(bytes);

    return Arrays.toString(bytes);
  }
}
