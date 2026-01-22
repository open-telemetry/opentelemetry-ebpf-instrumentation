/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * A direct ByteBuffer wrapper that provides pointer-like operations for JNI interop. This replaces
 * JNA's Memory and Pointer classes with pure JNI.
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

  /** Get the native memory address of this buffer. */
  public long getAddress() {
    return address;
  }

  /** Set a byte at the given offset. */
  public void setByte(int offset, byte value) {
    buffer.put(offset, value);
  }

  /** Get a byte at the given offset. */
  public byte getByte(int offset) {
    return (byte) buffer.getChar(offset);
  }

  /** Set a short at the given offset. */
  public void setShort(int offset, short value) {
    buffer.putShort(offset, value);
  }

  /** Set a short at the given offset. */
  public short getShort(int offset) {
    return buffer.getShort(offset);
  }

  /** Set an int at the given offset. */
  public void setInt(int offset, int value) {
    buffer.putInt(offset, value);
  }

  /** Get an int at the given offset. */
  public int getInt(int offset) {
    return buffer.getInt(offset);
  }

  /** Set a long at the given offset. */
  public void setLong(int offset, long value) {
    buffer.putLong(offset, value);
  }

  /** Get a long at the given offset. */
  public long getLong(int offset) {
    return buffer.getLong(offset);
  }

  /** Write a byte array to the buffer at the given offset. */
  public void write(int offset, byte[] data, int srcOffset, int length) {
    int oldPosition = ((java.nio.Buffer) buffer).position();
    ((java.nio.Buffer) buffer).position(offset);
    buffer.put(data, srcOffset, length);
    ((java.nio.Buffer) buffer).position(oldPosition);
  }

  /** Get the underlying ByteBuffer for advanced operations. */
  public ByteBuffer getBuffer() {
    return buffer;
  }

  /** Native method to get the address of a direct ByteBuffer. */
  private static native long getDirectBufferAddress(ByteBuffer buffer);
}
