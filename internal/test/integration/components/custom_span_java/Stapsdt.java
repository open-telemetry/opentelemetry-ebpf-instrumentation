// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Minimal JNI binding to libstapsdt. Mirrors the python-stapsdt + ruby-stapsdt
// + go salp pattern: register a provider + probes at startup, fire them per
// request. Strings are passed as NUL-terminated byte arrays so OBI's
// custom_span BPF rewriter can deref the pointer at probe fire time.
public class Stapsdt {
    static {
        System.loadLibrary("jstapsdt");
    }

    static native long providerInit(String name);
    static native long addProbeU64U64(long provider, String name);
    static native long addProbeU64I32(long provider, String name);
    static native long addProbeU64(long provider, String name);
    static native int providerLoad(long provider);
    static native void fireU64Str(long probe, long arg0, byte[] arg1);
    static native void fireU64I32(long probe, long arg0, int arg1);
    static native void fireStr(long probe, byte[] arg0);
}
