/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

public enum OperationType {
  SEND((byte) 1),
  RECEIVE((byte) 2),
  THREAD((byte) 3),
  // virtual thread mounted on the calling carrier; payload = its logical id
  VT_MOUNT((byte) 4),
  // virtual thread unmounted from the calling carrier; payload unused
  VT_UNMOUNT((byte) 5);

  public final byte code;

  OperationType(byte code) {
    this.code = code;
  }
}
