// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Minimal Node-API addon wrapping libstapsdt. Mirrors the JNI bridge used by
// the Java sample so the same custom_span integration patterns (paired USDT
// for /order, single-shot USDT for /cache) exercise the same OBI code path
// on Node.js.

#include <napi.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

extern "C" {
#include <libstapsdt.h>
}

namespace {

inline SDTProvider_t *to_provider(double h) {
    return reinterpret_cast<SDTProvider_t *>(static_cast<uintptr_t>(h));
}
inline SDTProbe_t *to_probe(double h) {
    return reinterpret_cast<SDTProbe_t *>(static_cast<uintptr_t>(h));
}

Napi::Value ProviderInit(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    std::string name = info[0].As<Napi::String>().Utf8Value();
    SDTProvider_t *p = providerInit(name.c_str());
    return Napi::Number::New(env, static_cast<double>(reinterpret_cast<uintptr_t>(p)));
}

Napi::Value AddProbeU64U64(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    double provh = info[0].As<Napi::Number>().DoubleValue();
    std::string name = info[1].As<Napi::String>().Utf8Value();
    SDTProbe_t *probe = providerAddProbe(to_provider(provh), name.c_str(), 2, uint64, uint64);
    return Napi::Number::New(env, static_cast<double>(reinterpret_cast<uintptr_t>(probe)));
}

Napi::Value AddProbeU64I32(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    double provh = info[0].As<Napi::Number>().DoubleValue();
    std::string name = info[1].As<Napi::String>().Utf8Value();
    SDTProbe_t *probe = providerAddProbe(to_provider(provh), name.c_str(), 2, uint64, int32);
    return Napi::Number::New(env, static_cast<double>(reinterpret_cast<uintptr_t>(probe)));
}

Napi::Value AddProbeU64(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    double provh = info[0].As<Napi::Number>().DoubleValue();
    std::string name = info[1].As<Napi::String>().Utf8Value();
    SDTProbe_t *probe = providerAddProbe(to_provider(provh), name.c_str(), 1, uint64);
    return Napi::Number::New(env, static_cast<double>(reinterpret_cast<uintptr_t>(probe)));
}

Napi::Value ProviderLoad(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    double provh = info[0].As<Napi::Number>().DoubleValue();
    return Napi::Number::New(env, providerLoad(to_provider(provh)));
}

Napi::Value FireU64Str(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    double probeh = info[0].As<Napi::Number>().DoubleValue();
    uint64_t a0 = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
    std::string s = info[2].As<Napi::String>().Utf8Value();
    SDTProbe_t *probe = to_probe(probeh);
    if (probe != nullptr) {
        probeFire(probe, a0, s.c_str());
    }
    return env.Undefined();
}

Napi::Value FireU64I32(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    double probeh = info[0].As<Napi::Number>().DoubleValue();
    uint64_t a0 = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
    int32_t a1 = info[2].As<Napi::Number>().Int32Value();
    SDTProbe_t *probe = to_probe(probeh);
    if (probe != nullptr) {
        probeFire(probe, a0, a1);
    }
    return env.Undefined();
}

Napi::Value FireStr(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    double probeh = info[0].As<Napi::Number>().DoubleValue();
    std::string s = info[1].As<Napi::String>().Utf8Value();
    SDTProbe_t *probe = to_probe(probeh);
    if (probe != nullptr) {
        probeFire(probe, reinterpret_cast<uint64_t>(s.c_str()));
    }
    return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("providerInit", Napi::Function::New(env, ProviderInit));
    exports.Set("addProbeU64U64", Napi::Function::New(env, AddProbeU64U64));
    exports.Set("addProbeU64I32", Napi::Function::New(env, AddProbeU64I32));
    exports.Set("addProbeU64", Napi::Function::New(env, AddProbeU64));
    exports.Set("providerLoad", Napi::Function::New(env, ProviderLoad));
    exports.Set("fireU64Str", Napi::Function::New(env, FireU64Str));
    exports.Set("fireU64I32", Napi::Function::New(env, FireU64I32));
    exports.Set("fireStr", Napi::Function::New(env, FireStr));
    return exports;
}

} // namespace

NODE_API_MODULE(node_stapsdt, Init)
