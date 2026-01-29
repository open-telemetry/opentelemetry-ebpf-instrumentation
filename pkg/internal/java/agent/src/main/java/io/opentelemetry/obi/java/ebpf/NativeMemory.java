/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * A direct ByteBuffer wrapper that provides pointer-like operations for JNI interop. We initially
 * used JNA's Memory and Pointer classes, but moved to pure JNI after issues with complicated class
 * loaders.
 */
public class NativeMemory {
  private final ByteBuffer buffer;
  private final long address;

  public NativeMemory(int size) {
    this.buffer = ByteBuffer.allocateDirect(size);
    this.buffer.order(ByteOrder.nativeOrder());
    this.address = getDirectBufferAddress(buffer);
  }

  /**
   * Constructor for testing only - allows creating NativeMemory without JNI access.
   *
   * @param size the size of the buffer
   * @param testing unused parameter to differentiate from main constructor
   */
  @SuppressWarnings("unused")
  public NativeMemory(int size, boolean testing) {
    this.buffer = ByteBuffer.allocateDirect(size);
    this.buffer.order(ByteOrder.nativeOrder());
    this.address = 0L;
  }

  public long getAddress() {
    return address;
  }

  public void setByte(int offset, byte value) {
    buffer.put(offset, value);
  }

  public byte getByte(int offset) {
    return (byte) buffer.getChar(offset);
  }

  public void setShort(int offset, short value) {
    buffer.putShort(offset, value);
  }

  public short getShort(int offset) {
    return buffer.getShort(offset);
  }

  public void setInt(int offset, int value) {
    buffer.putInt(offset, value);
  }

  public int getInt(int offset) {
    return buffer.getInt(offset);
  }

  public void setLong(int offset, long value) {
    buffer.putLong(offset, value);
  }

  public long getLong(int offset) {
    return buffer.getLong(offset);
  }

  public void write(int offset, byte[] data, int srcOffset, int length) {
    int oldPosition = ((java.nio.Buffer) buffer).position();
    ((java.nio.Buffer) buffer).position(offset);
    buffer.put(data, srcOffset, length);
    ((java.nio.Buffer) buffer).position(oldPosition);
  }

  public ByteBuffer getBuffer() {
    return buffer;
  }

  // Done through JNI
  private static native long getDirectBufferAddress(ByteBuffer buffer);
}
