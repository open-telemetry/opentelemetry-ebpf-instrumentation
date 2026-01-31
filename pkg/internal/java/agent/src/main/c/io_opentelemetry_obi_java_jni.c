/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <jni.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * Class:     io_opentelemetry_obi_java_ebpf_NativeMemory
 * Method:    getDirectBufferAddress
 * Signature: (Ljava/nio/ByteBuffer;)J
 */
JNIEXPORT jlong JNICALL
Java_io_opentelemetry_obi_java_ebpf_NativeMemory_getDirectBufferAddress(
    JNIEnv *env, jclass clazz, jobject buffer) {
  return (jlong)(*env)->GetDirectBufferAddress(env, buffer);
}

/*
 * Class:     io_opentelemetry_obi_java_Agent_NativeLib
 * Method:    ioctl
 * Signature: (IIJ)I
 */
JNIEXPORT jint JNICALL
Java_io_opentelemetry_obi_java_Agent_00024NativeLib_ioctl(JNIEnv *env,
                                                          jclass clazz, jint fd,
                                                          jint cmd,
                                                          jlong argp) {
  return ioctl(fd, cmd, argp);
}

/*
 * Class:     io_opentelemetry_obi_java_Agent_NativeLib
 * Method:    gettid
 * Signature: ()I
 */
JNIEXPORT jint JNICALL
Java_io_opentelemetry_obi_java_Agent_00024NativeLib_gettid(JNIEnv *env,
                                                           jclass clazz) {
  return (jint)syscall(SYS_gettid);
}
