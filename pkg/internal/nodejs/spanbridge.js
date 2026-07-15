// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// OBI Node.js manual-span bridge.
//
// Captures spans created through @opentelemetry/api when the application has
// no OpenTelemetry SDK registered — the Node.js analog of the Go support in
// bpf/gotracer/go_sdk.c, which hooks the no-op global-API tracer and bails
// out when a real SDK delegate is installed.
//
// It registers a minimal, dependency-free TracerProvider + context manager
// directly into the API's cross-copy global registry
// (globalThis[Symbol.for('opentelemetry.js.api.1')]), which every copy of
// @opentelemetry/api in the process shares. Finished spans are serialized to
// JSON and signalled to the eBPF layer through the same channel fdextractor.js
// uses: a sentinel uv_fs_access() path read by the obi_uv_fs_access uprobe
// (bpf/generictracer/nodejs.c). The BPF side attaches the current request's
// trace context (traces_ctx_v1), so manual spans parent under OBI's automatic
// server spans.
//
// If the application registers its own SDK, this bridge stays inert: spans
// are then exported by the app's SDK and OBI's SDK-overlap detection applies.

(() => {
  'use strict';

  const API_KEY = Symbol.for('opentelemetry.js.api.1');
  // Must track the newest published @opentelemetry/api 1.x minor: an api copy
  // newer than this rejects the global registration (isCompatible allows
  // callers with minor <= registered minor only).
  const API_VERSION = '1.9.0';
  // Same Symbol.for key the api uses internally (createContextKey).
  const SPAN_KEY = Symbol.for('OpenTelemetry Context Key SPAN');
  const SENTINEL_PREFIX = '/dev/null/obi-span/';
  // Field size budgets. Attribute key/value budgets must match the fixed
  // BPF/Go otel_attribute_t buffers on the reader side (key[32], value[128]),
  // minus one byte for the NUL terminator the decoder relies on — otherwise
  // the userspace decoder silently re-truncates and we waste payload space.
  const MAX_PAYLOAD = 1900; // whole serialized span; keeps the sentinel path under the BPF buffer
  const MAX_ATTRS = 16;
  const MAX_NAME_LEN = 128;
  const MAX_ATTR_KEY_LEN = 31; // otel_attribute_t key[32] - 1 (NUL)
  const MAX_ATTR_VALUE_LEN = 127; // otel_attribute_t value[128] - 1 (NUL)
  const MAX_STATUS_MSG_LEN = 128;

  const g = globalThis;
  if (g.__obiSpanBridgeLoaded) return;
  g.__obiSpanBridgeLoaded = true;

  const fs = require('fs');
  const crypto = require('crypto');
  const { AsyncLocalStorage } = require('async_hooks');

  // Diagnostics are OFF by default: this code runs inside the customer's
  // process, so it must never write to their stdout/stderr in normal
  // operation. Set OTEL_EBPF_NODEJS_DEBUG=1 to surface why the
  // bridge failed to activate when troubleshooting an injection.
  const DEBUG = !!process.env.OTEL_EBPF_NODEJS_DEBUG;
  const debug = (msg, err) => {
    if (!DEBUG) return;
    try {
      const reason = err ? ': ' + (err.stack || err.message || String(err)) : '';
      console.error('[obi-span-bridge] ' + msg + reason);
    } catch (_) {
      // never let diagnostics throw into the app
    }
  };

  const truncate = (s, max) => (s.length > max ? s.slice(0, max) : s);

  // App-provided values (span names, attribute values, status messages) may be
  // objects whose toString()/Symbol.toPrimitive throws. This code runs inside
  // the customer's process on the hot path (span.end() is often in a finally
  // block), so a raw String(value) that throws would surface as an app-level
  // exception where an unregistered SDK would have been a silent no-op. Coerce
  // defensively and never let stringification escape.
  const safeStr = (v) => {
    try {
      return String(v);
    } catch (_) {
      return '';
    }
  };

  // IMPORTANT: do not create or modify the registry until every guard has
  // passed — a registry object we create carries a version string, and any
  // app api copy with a different exact version would then fail its own
  // setGlobalTracerProvider (registerGlobal requires an exact version match
  // between registrants).
  const existing = g[API_KEY];
  // An SDK (or another agent) already registered a provider or context
  // manager — stay inert rather than fight it.
  if (existing && (existing.trace || existing.context)) {
    debug('staying inert: a tracer provider/context manager is already registered');
    return;
  }
  // NOTE: Our reliable signals to skip the bridge are:
  //   1. the registry guard above (SDK already registered by injection time);
  //   2. the step-aside below (SDK registers AFTER we did) — we yield.
  // If some api copy already initialized the registry (e.g. via diag), keep
  // its version and only add our entries; otherwise create it with ours.
  const registry = (g[API_KEY] = existing ?? { version: API_VERSION });

  // Step-aside state: once the application registers its own provider, we
  // unregister ourselves and stop emitting so its SDK owns the API surface.
  let yielded = false;
  const yieldToApp = (why) => {
    if (yielded) return;
    yielded = true;
    // Remove our registration entirely so the app's registerGlobal succeeds.
    // We must drop the WHOLE registry object, not just .trace/.context: the
    // registry also carries a `version`, and registerGlobal requires an exact
    // version match — leaving our version behind would block an app whose api
    // is even a patch different. Deleting the key lets the app recreate the
    // registry with its own version.
    delete g[API_KEY];
    debug('yielded to application-registered SDK: ' + why);
  };

  // --- transport -----------------------------------------------------------

  // The span payload is smuggled to the eBPF layer as the argument of a
  // deliberately-failing uv_fs_access() call: the obi_uv_fs_access uprobe
  // reads the path string on syscall entry, then the syscall itself fails
  // because the path does not exist. So the throw here is the EXPECTED,
  // every-span outcome (ENOENT/ENOTDIR) — not an error, and not something we
  // can log per span without flooding the app. It also does not tell us
  // whether OBI actually consumed the event: an attached uprobe and a
  // not-attached OBI produce the identical failure. Only a genuinely
  // unexpected error (e.g. a malformed payload rejected before the syscall)
  // is worth surfacing, and only under the debug flag.
  const emit = (payload) => {
    if (yielded) return; // the app's own SDK owns telemetry now
    try {
      fs.accessSync(SENTINEL_PREFIX + payload);
    } catch (err) {
      if (DEBUG && err && err.code !== 'ENOENT' && err.code !== 'ENOTDIR') {
        debug('unexpected error emitting span', err);
      }
    }
  };

  // --- minimal context implementation --------------------------------------

  class Context {
    constructor(entries) {
      this._entries = entries ?? new Map();
    }
    getValue(key) {
      return this._entries.get(key);
    }
    setValue(key, value) {
      const m = new Map(this._entries);
      m.set(key, value);
      return new Context(m);
    }
    deleteValue(key) {
      const m = new Map(this._entries);
      m.delete(key);
      return new Context(m);
    }
  }

  const ROOT_CONTEXT = new Context();
  const als = new AsyncLocalStorage();

  const contextManager = {
    active() {
      return als.getStore() ?? ROOT_CONTEXT;
    },
    with(context, fn, thisArg, ...args) {
      return als.run(context ?? ROOT_CONTEXT, () => fn.call(thisArg, ...args));
    },
    bind(context, target) {
      if (typeof target === 'function') {
        const self = this;
        return function (...args) {
          return self.with(context, target, this, ...args);
        };
      }
      return target;
    },
    enable() {
      return this;
    },
    disable() {
      return this;
    },
  };

  // --- minimal recording span ----------------------------------------------

  const nowNs = () => {
    // Wall-clock start anchor + monotonic offset for sub-ms durations.
    return BigInt(Date.now()) * 1000000n;
  };
  const hrNs = () => process.hrtime.bigint();

  class Span {
    constructor(name, kind, parentSpanContext) {
      this.name = safeStr(name);
      this.kind = kind ?? 0;
      this._parent = parentSpanContext;
      this._spanContext = {
        traceId: parentSpanContext
          ? parentSpanContext.traceId
          : crypto.randomBytes(16).toString('hex'),
        spanId: crypto.randomBytes(8).toString('hex'),
        traceFlags: 1,
        traceState: undefined,
      };
      this.attributes = {};
      this.status = { code: 0 };
      this._events = [];
      this._startWallNs = nowNs();
      this._startHrNs = hrNs();
      this._ended = false;
    }
    spanContext() {
      return this._spanContext;
    }
    setAttribute(key, value) {
      if (!this._ended && typeof key === 'string') this.attributes[key] = value;
      return this;
    }
    setAttributes(attrs) {
      for (const k of Object.keys(attrs ?? {})) this.setAttribute(k, attrs[k]);
      return this;
    }
    addEvent(name) {
      if (!this._ended && this._events.length < 8) this._events.push(safeStr(name));
      return this;
    }
    addLink() {
      return this;
    }
    addLinks() {
      return this;
    }
    setStatus(status) {
      if (!this._ended && status && typeof status.code === 'number') {
        this.status = { code: status.code, message: status.message };
      }
      return this;
    }
    updateName(name) {
      if (!this._ended) this.name = safeStr(name);
      return this;
    }
    recordException(err) {
      const msg = err && (err.message ?? safeStr(err));
      if (msg !== undefined) this.setAttribute('exception.message', safeStr(msg));
      return this;
    }
    isRecording() {
      return !this._ended;
    }
    end() {
      if (this._ended) return;
      this._ended = true;
      const durNs = hrNs() - this._startHrNs;
      // span.end() is idiomatically called from a finally block. It must never
      // throw into the app: with no SDK registered the alternative is a silent
      // NoopSpan, so any escape here is a regression. safeStr guards the field
      // coercions; this catch is the last line of defense (e.g. an exotic
      // JSON.stringify failure).
      try {
        this._emit(durNs);
      } catch (err) {
        debug('failed to emit span (dropped)', err);
      }
    }
    // Serialize at most MAX_ATTRS attributes into a plain object, truncating
    // keys/values and coercing unsupported value types to strings, to match
    // what the BPF-side fixed-size attribute layout can carry.
    _serializeAttributes() {
      const out = {};
      let count = 0;
      for (const [rawKey, value] of Object.entries(this.attributes)) {
        if (count >= MAX_ATTRS) break;
        count++;
        const key = truncate(rawKey, MAX_ATTR_KEY_LEN);
        if (typeof value === 'string') {
          out[key] = truncate(value, MAX_ATTR_VALUE_LEN);
        } else if (typeof value === 'number' || typeof value === 'boolean') {
          out[key] = value;
        } else {
          out[key] = truncate(safeStr(value), MAX_ATTR_VALUE_LEN);
        }
      }
      return out;
    }
    _emit(durNs) {
      const rec = {
        v: 1,
        name: truncate(this.name, MAX_NAME_LEN),
        tid: this._spanContext.traceId,
        sid: this._spanContext.spanId,
        psid: this._parent ? this._parent.spanId : undefined,
        kind: this.kind,
        startNs: this._startWallNs.toString(),
        durNs: durNs.toString(),
        status: this.status.code,
        statusMsg: this.status.message ? truncate(safeStr(this.status.message), MAX_STATUS_MSG_LEN) : undefined,
        attrs: this._serializeAttributes(),
      };
      let payload = JSON.stringify(rec);
      // Measure UTF-8 bytes, not String#length (UTF-16 code units): the BPF
      // side reads the sentinel path as bytes into a fixed buffer, so a
      // multi-byte payload that looks short by .length could still overflow.
      if (Buffer.byteLength(payload, 'utf8') > MAX_PAYLOAD) {
        rec.attrs = {};
        payload = JSON.stringify(rec);
      }
      if (Buffer.byteLength(payload, 'utf8') > MAX_PAYLOAD) {
        debug('dropping span: core payload exceeds transport limit');
        return;
      }
      emit(payload);
    }
  }

  // --- tracer / provider ----------------------------------------------------

  // After we have yielded, the application's own provider owns the global.
  // Tracers the app acquired-and-used before injection cached OUR tracer
  // (OTel ProxyTracer caches the first real delegate), so route them through
  // to the app's current tracer instead of producing dead bridge spans.
  const activeAppTracer = (scope, version) => {
    if (!yielded) return null;
    const reg = g[API_KEY];
    const prov = reg && reg.trace;
    if (prov && typeof prov.getTracer === 'function') return prov.getTracer(scope, version);
    return null;
  };

  class Tracer {
    constructor(scopeName) {
      this._scope = scopeName;
    }
    startSpan(name, options, context) {
      const at = activeAppTracer(this._scope);
      if (at) return at.startSpan(name, options, context);
      const ctx = context ?? contextManager.active();
      const opts = options ?? {};
      let parent;
      if (opts.root !== true) {
        const parentSpan = ctx.getValue(SPAN_KEY);
        if (parentSpan && typeof parentSpan.spanContext === 'function') {
          const sc = parentSpan.spanContext();
          if (sc && typeof sc.traceId === 'string' && /^[0-9a-f]{32}$/.test(sc.traceId)) {
            parent = sc;
          }
        }
      }
      const span = new Span(name, opts.kind, parent);
      span._scope = this._scope;
      if (opts.attributes) span.setAttributes(opts.attributes);
      return span;
    }
    startActiveSpan(name, arg2, arg3, arg4) {
      const at = activeAppTracer(this._scope);
      if (at) return at.startActiveSpan(name, arg2, arg3, arg4);
      let options, context, fn;
      if (typeof arg2 === 'function') {
        fn = arg2;
      } else if (typeof arg3 === 'function') {
        options = arg2;
        fn = arg3;
      } else {
        options = arg2;
        context = arg3;
        fn = arg4;
      }
      if (typeof fn !== 'function') return undefined;
      const parentCtx = context ?? contextManager.active();
      const span = this.startSpan(name, options, parentCtx);
      const ctx = parentCtx.setValue(SPAN_KEY, span);
      return contextManager.with(ctx, fn, undefined, span);
    }
  }

  const tracerProvider = {
    getTracer(name, _version, _options) {
      return new Tracer(name || 'unknown');
    },
  };

  // --- register into the shared api global registry -------------------------

  // Wrap a global setter on an api namespace so that, if the application ever
  // registers its own provider/manager, we yield first (removing our registry
  // entry) and then let the real registration proceed — so the app's SDK wins
  // instead of hitting the API's "duplicate registration" refusal.
  const wrapSetter = (apiObj, method, why) => {
    if (!apiObj || typeof apiObj[method] !== 'function' || apiObj[method].__obiWrapped) {
      return;
    }
    const orig = apiObj[method].bind(apiObj);
    const wrapped = function (...args) {
      yieldToApp(why);
      return orig(...args);
    };
    wrapped.__obiWrapped = true;
    apiObj[method] = wrapped;
  };

  // Wire a single @opentelemetry/api copy to the bridge:
  //   - point its ProxyTracerProvider at our provider, so tracers already
  //     acquired through this copy (a ProxyTracer caches the first delegate and
  //     never re-consults the registry) resolve to us; and
  //   - wrap its global setters so the app's own SDK registration makes us
  //     yield instead of being refused as a duplicate.
  // A copy whose version is compatible with our registration resolves its
  // provider straight from the global registry (registry.trace, set below), so
  // getTracerProvider() returns our provider and setDelegate is skipped — for
  // those copies the setter-wrapping is the part that matters.
  const wiredApis = new WeakSet();
  const wireApiCopy = (exp) => {
    if (yielded || !exp || wiredApis.has(exp)) return;
    const traceApi = exp.trace;
    const contextApi = exp.context;
    if (!traceApi || typeof traceApi.getTracerProvider !== 'function') return;
    wiredApis.add(exp);
    const proxy = traceApi.getTracerProvider();
    if (proxy && proxy !== tracerProvider && typeof proxy.setDelegate === 'function') {
      proxy.setDelegate(tracerProvider);
    }
    // Yield when the app registers its own tracer provider / context manager.
    wrapSetter(traceApi, 'setGlobalTracerProvider', 'setGlobalTracerProvider');
    wrapSetter(contextApi, 'setGlobalContextManager', 'setGlobalContextManager');
  };

  // Copies already loaded before us (present in require.cache).
  for (const key of Object.keys(require.cache ?? {})) {
    if (!/[\\/]@opentelemetry[\\/]api[\\/]/.test(key)) continue;
    try {
      wireApiCopy(require.cache[key] && require.cache[key].exports);
    } catch (err) {
      // never let bridge wiring break the app; surface only under debug
      debug('failed to wire pre-loaded @opentelemetry/api copy ' + key, err);
    }
  }

  // Copies of the api loaded after this point resolve through the registry.
  registry.trace = tracerProvider;
  registry.context = contextManager;

  // Cover @opentelemetry/api copies loaded AFTER injection. Without this, an
  // app that lazily requires the api (and its SDK) only after we injected would
  // call an unwrapped setGlobalTracerProvider: it would see our registry.trace,
  // be refused as a duplicate registration, and the app's exporter would never
  // take over — spans would keep flowing through OBI. Hook the CommonJS module
  // loader and wire each api copy as it loads. We call the original loader
  // first and guard everything, so this composes with other loader patches
  // (e.g. import-in-the-middle) and can never break a require. NOTE: this
  // covers CommonJS require() only; an api pulled in purely through the native
  // ESM loader is not intercepted here.
  try {
    const Module = require('module');
    const origLoad = Module._load;
    if (typeof origLoad === 'function' && !origLoad.__obiWrapped) {
      const patchedLoad = function (request) {
        const exported = origLoad.apply(this, arguments);
        try {
          if (!yielded && /(?:^|[\\/])@opentelemetry[\\/]api(?:[\\/]|$)/.test(String(request))) {
            wireApiCopy(exported);
          }
        } catch (err) {
          debug('module-load api wiring failed', err);
        }
        return exported;
      };
      patchedLoad.__obiWrapped = true;
      Module._load = patchedLoad;
    }
  } catch (err) {
    debug('failed to install module-load hook', err);
  }

  g.__obiSpanBridge = { version: 1 };
  debug('span bridge activated (pid ' + process.pid + ')');
})();
