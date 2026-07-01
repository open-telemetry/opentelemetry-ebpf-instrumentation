// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Minimal JNI shim over libstapsdt. Mirrors the python-stapsdt pattern so
// the integration test exercises custom_span_java:order USDT pairs the same
// way the C/Python/Ruby/Go samples do.

#include <jni.h>
#include <libstapsdt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static inline SDTProvider_t *to_provider(jlong h) {
  return (SDTProvider_t *)(intptr_t)h;
}
static inline SDTProbe_t *to_probe(jlong h) {
  return (SDTProbe_t *)(intptr_t)h;
}

JNIEXPORT jlong JNICALL Java_Stapsdt_providerInit(JNIEnv *env, jclass cls,
                                                  jstring jname) {
  (void)cls;
  const char *name = (*env)->GetStringUTFChars(env, jname, NULL);
  SDTProvider_t *p = providerInit(name);
  (*env)->ReleaseStringUTFChars(env, jname, name);
  return (jlong)(intptr_t)p;
}

JNIEXPORT jlong JNICALL Java_Stapsdt_addProbeU64U64(JNIEnv *env, jclass cls,
                                                    jlong jprov,
                                                    jstring jname) {
  (void)cls;
  const char *name = (*env)->GetStringUTFChars(env, jname, NULL);
  SDTProbe_t *probe =
      providerAddProbe(to_provider(jprov), name, 2, uint64, uint64);
  (*env)->ReleaseStringUTFChars(env, jname, name);
  return (jlong)(intptr_t)probe;
}

JNIEXPORT jlong JNICALL Java_Stapsdt_addProbeU64I32(JNIEnv *env, jclass cls,
                                                    jlong jprov,
                                                    jstring jname) {
  (void)cls;
  const char *name = (*env)->GetStringUTFChars(env, jname, NULL);
  SDTProbe_t *probe =
      providerAddProbe(to_provider(jprov), name, 2, uint64, int32);
  (*env)->ReleaseStringUTFChars(env, jname, name);
  return (jlong)(intptr_t)probe;
}

JNIEXPORT jlong JNICALL Java_Stapsdt_addProbeU64(JNIEnv *env, jclass cls,
                                                 jlong jprov, jstring jname) {
  (void)cls;
  const char *name = (*env)->GetStringUTFChars(env, jname, NULL);
  SDTProbe_t *probe = providerAddProbe(to_provider(jprov), name, 1, uint64);
  (*env)->ReleaseStringUTFChars(env, jname, name);
  return (jlong)(intptr_t)probe;
}

JNIEXPORT jint JNICALL Java_Stapsdt_providerLoad(JNIEnv *env, jclass cls,
                                                 jlong jprov) {
  (void)env;
  (void)cls;
  return providerLoad(to_provider(jprov));
}

// Fires order_start: (u64 order_id, char *customer).
JNIEXPORT void JNICALL Java_Stapsdt_fireU64Str(JNIEnv *env, jclass cls,
                                               jlong jprobe, jlong arg0,
                                               jbyteArray jbytes) {
  (void)cls;
  SDTProbe_t *probe = to_probe(jprobe);
  if (probe == NULL || jbytes == NULL) {
    return;
  }
  jsize n = (*env)->GetArrayLength(env, jbytes);
  // libstapsdt's argFmt for arg 1 is uint64 — we pass a NUL-terminated
  // byte pointer; the BPF custom_span rewriter coerces the slot to a
  // user-memory deref at uprobe attach time.
  jbyte *raw = (*env)->GetByteArrayElements(env, jbytes, NULL);
  char *buf = (char *)malloc((size_t)n + 1);
  if (!buf) {
    (*env)->ReleaseByteArrayElements(env, jbytes, raw, JNI_ABORT);
    return;
  }
  memcpy(buf, raw, (size_t)n);
  buf[n] = '\0';
  (*env)->ReleaseByteArrayElements(env, jbytes, raw, JNI_ABORT);
  probeFire(probe, (uint64_t)arg0, buf);
  free(buf);
}

JNIEXPORT void JNICALL Java_Stapsdt_fireU64I32(JNIEnv *env, jclass cls,
                                               jlong jprobe, jlong arg0,
                                               jint arg1) {
  (void)env;
  (void)cls;
  SDTProbe_t *probe = to_probe(jprobe);
  if (probe == NULL) {
    return;
  }
  probeFire(probe, (uint64_t)arg0, (int32_t)arg1);
}

JNIEXPORT void JNICALL Java_Stapsdt_fireStr(JNIEnv *env, jclass cls,
                                            jlong jprobe, jbyteArray jbytes) {
  (void)cls;
  SDTProbe_t *probe = to_probe(jprobe);
  if (probe == NULL || jbytes == NULL) {
    return;
  }
  jsize n = (*env)->GetArrayLength(env, jbytes);
  jbyte *raw = (*env)->GetByteArrayElements(env, jbytes, NULL);
  char *buf = (char *)malloc((size_t)n + 1);
  if (!buf) {
    (*env)->ReleaseByteArrayElements(env, jbytes, raw, JNI_ABORT);
    return;
  }
  memcpy(buf, raw, (size_t)n);
  buf[n] = '\0';
  (*env)->ReleaseByteArrayElements(env, jbytes, raw, JNI_ABORT);
  probeFire(probe, (uint64_t)(uintptr_t)buf);
  free(buf);
}
