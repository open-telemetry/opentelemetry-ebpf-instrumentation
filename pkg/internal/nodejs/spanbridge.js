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
  // Field size budgets. These mirror the fixed key/value/name buffers of the
  // BPF-side otel_attribute_t / node_span_event_t layout the reader decodes
  // into, so anything longer would be truncated there anyway.
  const MAX_PAYLOAD = 1900; // whole serialized span; keeps the sentinel path under the BPF buffer
  const MAX_ATTRS = 16;
  const MAX_NAME_LEN = 128;
  const MAX_ATTR_KEY_LEN = 64;
  const MAX_ATTR_VALUE_LEN = 256;
  const MAX_STATUS_MSG_LEN = 128;

  const g = globalThis;
  if (g.__obiSpanBridgeLoaded) return;
  g.__obiSpanBridgeLoaded = true;

  const fs = require('fs');
  const crypto = require('crypto');
  const { AsyncLocalStorage } = require('async_hooks');

  // Diagnostics are OFF by default: this code runs inside the customer's
  // process, so it must never write to their stdout/stderr in normal
  // operation. Set OTEL_EBPF_NODEJS_SPAN_BRIDGE_DEBUG=1 to surface why the
  // bridge failed to activate when troubleshooting an injection.
  const DEBUG = !!process.env.OTEL_EBPF_NODEJS_SPAN_BRIDGE_DEBUG;
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
  // An OTel SDK is loaded but has not registered yet (e.g. it initializes
  // lazily, after we were injected). Registering ours first would make the
  // app's later registration fail and starve its exporters — stay inert and
  // let the app's SDK own the API surface.
  const sdkLoaded = Object.keys(require.cache ?? {}).some(
    (p) => p.includes('@opentelemetry/sdk-trace') || p.includes('@opentelemetry/sdk-node')
  );
  if (sdkLoaded) {
    debug('staying inert: the application loads its own @opentelemetry SDK');
    return;
  }
  // If some api copy already initialized the registry (e.g. via diag), keep
  // its version and only add our entries; otherwise create it with ours.
  const registry = (g[API_KEY] = existing ?? { version: API_VERSION });

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
      this.name = String(name);
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
      if (!this._ended && this._events.length < 8) this._events.push(String(name));
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
      if (!this._ended) this.name = String(name);
      return this;
    }
    recordException(err) {
      const msg = err && (err.message ?? String(err));
      if (msg !== undefined) this.setAttribute('exception.message', String(msg));
      return this;
    }
    isRecording() {
      return !this._ended;
    }
    end() {
      if (this._ended) return;
      this._ended = true;
      const durNs = hrNs() - this._startHrNs;
      this._emit(durNs);
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
          out[key] = truncate(String(value), MAX_ATTR_VALUE_LEN);
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
        statusMsg: this.status.message ? truncate(String(this.status.message), MAX_STATUS_MSG_LEN) : undefined,
        attrs: this._serializeAttributes(),
        events: this._events.length ? this._events : undefined,
        scope: this._scope,
      };
      let payload = JSON.stringify(rec);
      if (payload.length > MAX_PAYLOAD) {
        // The BPF payload buffer is fixed-size. If a span with many/large
        // attributes overflows it, drop the variable-length parts (attributes
        // and events) so the core span still reaches OBI rather than being
        // dropped entirely.
        rec.attrs = {};
        rec.events = undefined;
        payload = JSON.stringify(rec);
      }
      emit(payload);
    }
  }

  // --- tracer / provider ----------------------------------------------------

  class Tracer {
    constructor(scopeName) {
      this._scope = scopeName;
    }
    startSpan(name, options, context) {
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

  // Wire up @opentelemetry/api copies that were loaded BEFORE this bridge:
  // tracers the app already acquired are ProxyTracers that resolve through
  // their api copy's singleton ProxyTracerProvider._delegate — they never
  // consult the global registry. Point each loaded copy's proxy at our
  // provider (getTracerProvider() returns the copy's own proxy as long as
  // nothing is registered globally yet, which the guards above ensured).
  for (const key of Object.keys(require.cache ?? {})) {
    if (!/[\\/]@opentelemetry[\\/]api[\\/]/.test(key)) continue;
    try {
      const exp = require.cache[key] && require.cache[key].exports;
      const traceApi = exp && exp.trace;
      if (traceApi && typeof traceApi.getTracerProvider === 'function') {
        const proxy = traceApi.getTracerProvider();
        if (proxy && typeof proxy.setDelegate === 'function') {
          proxy.setDelegate(tracerProvider);
        }
      }
    } catch (err) {
      // never let bridge wiring break the app; surface only under debug
      debug('failed to wire pre-loaded @opentelemetry/api copy ' + key, err);
    }
  }

  // Copies of the api loaded after this point resolve through the registry.
  registry.trace = tracerProvider;
  registry.context = contextManager;

  g.__obiSpanBridge = { version: 1 };
  debug('span bridge activated (pid ' + process.pid + ')');
})();
