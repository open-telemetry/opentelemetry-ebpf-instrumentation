// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

(() => {
  'use strict';

  const injectedRules = __OBI_DYNAMIC_SPAN_RULES__;
  if (!Array.isArray(injectedRules) || injectedRules.length === 0) return;

  const stateKey = Symbol.for('obi.dynamicSpanState');
  const existingState = globalThis[stateKey];
  if (existingState) {
    if (existingState.addRules(injectedRules)) existingState.rescan();
    return;
  }

  const rules = [];
  const bridge = globalThis.__obiSpanBridge;
  const Module = require('module');
  const { types } = require('util');
  const originalLoad = Module._load;
  const wrappedFunctions = new WeakMap();
  const wrappedOriginals = new WeakMap();
  let scannedModules = new WeakMap();
  const diagnosedRules = new Set();
  const state = {};
  globalThis[stateKey] = state;
  state.addRules = (newRules) => {
    let changed = false;
    for (const rule of newRules) {
      if (rules.some((existing) => existing.name === rule.name && existing.reference === rule.reference)) continue;
      rules.push(rule);
      changed = true;
    }
    return changed;
  };
  const diagnose = (index, message, err) => {
    if (diagnosedRules.has(index)) return;
    diagnosedRules.add(index);
    try {
      const details = process.env.OTEL_EBPF_NODEJS_DEBUG
        ? `: ${message}${err ? `: ${err.stack || err.message || String(err)}` : ''}`
        : '';
      process.emitWarning(`Node.js dynamic span rule ${rules[index].name} could not be applied${details}`, {
        code: 'OBI_DYNAMIC_SPAN_TARGET',
      });
    } catch (_) {
      // Diagnostics must not affect application behavior.
    }
  };

  const withSpan = (name, fn, thisArg, args) => {
    if (bridge && typeof bridge.withSpan === 'function') {
      return bridge.withSpan(name, fn, thisArg, args);
    }
    return Reflect.apply(fn, thisArg, args || []);
  };

  const MAX_EXPORT_DEPTH = 4;
  const MAX_EXPORTS_PER_MODULE = 4096;
  const MAX_VISITED_EXPORTS_PER_MODULE = 16384;
  const matchesGlob = (pattern, value) => {
    if (pattern === value) return true;
    let patternIndex = 0;
    let valueIndex = 0;
    let starPatternIndex = -1;
    let starValueIndex = -1;
    while (valueIndex < value.length) {
      if (patternIndex < pattern.length && (pattern[patternIndex] === '?' || pattern[patternIndex] === value[valueIndex])) {
        patternIndex++;
        valueIndex++;
      } else if (pattern[patternIndex] === '*') {
        const recursiveStar = pattern[patternIndex + 1] === '*';
        starPatternIndex = patternIndex + (recursiveStar ? 2 : 1);
        starValueIndex = valueIndex;
        patternIndex = starPatternIndex;
      } else if (starPatternIndex !== -1) {
        valueIndex = ++starValueIndex;
        patternIndex = starPatternIndex;
      } else {
        return false;
      }
    }
    while (pattern[patternIndex] === '*') patternIndex += pattern[patternIndex + 1] === '*' ? 2 : 1;
    return patternIndex === pattern.length;
  };

  const discoverExports = (moduleId, exports) => {
    const found = [];
    const ancestors = new WeakSet();
    let visited = 0;
    const walk = (value, symbol, depth) => {
      if (depth >= MAX_EXPORT_DEPTH || visited >= MAX_VISITED_EXPORTS_PER_MODULE || found.length >= MAX_EXPORTS_PER_MODULE) return;
      if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return;
      if (types.isProxy(value)) {
        value = wrappedOriginals.get(value);
        if (!value) return;
      }
      if (types.isProxy(value) || ancestors.has(value)) return;
      ancestors.add(value);
      try {
        // Object.keys includes only enumerable own properties. The visit limit
        // bounds descriptor inspection; the engine may still allocate the key list.
        const keys = Object.keys(value);
        for (const key of keys) {
          if (visited >= MAX_VISITED_EXPORTS_PER_MODULE || found.length >= MAX_EXPORTS_PER_MODULE) break;
          visited++;
          let descriptor;
          try {
            descriptor = Object.getOwnPropertyDescriptor(value, key);
          } catch (_) {
            continue;
          }
          if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) continue;
          const child = descriptor.value;
          const childSymbol = `${symbol}.${key}`;
          if (typeof child === 'function') {
            if (descriptor.writable || descriptor.configurable) {
              found.push({ symbol: childSymbol, parent: value, key, descriptor, original: child });
            }
            walk(child, childSymbol, depth + 1);
          }
          if (child && typeof child === 'object') walk(child, childSymbol, depth + 1);
        }
      } catch (_) {
        // Export discovery must not interfere with module loading.
      }
      ancestors.delete(value);
    };
    walk(exports, `${moduleId}:exports`, 0);
    return found;
  };

  const instrumentExport = (target, rule) => {
    const currentDescriptor = Object.getOwnPropertyDescriptor(target.parent, target.key);
    if (!currentDescriptor || !Object.prototype.hasOwnProperty.call(currentDescriptor, 'value')) return false;
    if (wrappedFunctions.has(currentDescriptor.value)) {
      const names = wrappedFunctions.get(currentDescriptor.value);
      if (!names.includes(rule.name)) names.push(rule.name);
      return true;
    }
    target = { ...target, descriptor: currentDescriptor, original: currentDescriptor.value };
    const original = target.original;
    const spanNames = [];
    const invokeWithSpans = (invoke) => {
      const invokeAt = (index) => {
        if (index === spanNames.length) return invoke();
        return withSpan(spanNames[index], () => invokeAt(index + 1), undefined, []);
      };
      return invokeAt(0);
    };
    const wrapper = new Proxy(original, {
      apply(fn, thisArg, args) {
        return invokeWithSpans(() => Reflect.apply(fn, thisArg, args));
      },
      construct(fn, args, newTarget) {
        return invokeWithSpans(() => Reflect.construct(fn, args, newTarget === wrapper ? fn : newTarget));
      },
    });
    wrappedFunctions.set(wrapper, spanNames);
    wrappedOriginals.set(wrapper, original);
    target.descriptor.value = wrapper;
    try {
      Object.defineProperty(target.parent, target.key, target.descriptor);
    } catch (_) {
      return false;
    }
    if (!spanNames.includes(rule.name)) spanNames.push(rule.name);
    return true;
  };

  const instrumentResolved = (moduleId, exports, explicitBuiltin = false, moduleRecord = null) => {
    if (!explicitBuiltin && !moduleId.includes('/') && !moduleId.includes('\\')) return;
    if (moduleRecord && moduleRecord.loaded && scannedModules.get(moduleRecord) === exports) return;
    const candidates = discoverExports(moduleId, exports);
    for (const [index, rule] of rules.entries()) {
      try {
        for (const candidate of candidates) {
          if (explicitBuiltin && !rule.reference.startsWith(`${moduleId}:exports.`)) continue;
          if (!matchesGlob(rule.reference, candidate.symbol)) continue;
          if (!instrumentExport(candidate, rule)) {
            diagnose(index, `matched export ${candidate.symbol} could not be wrapped`);
          }
        }
      } catch (err) {
        diagnose(index, `failed to inspect or instrument selector ${rule.reference}`, err);
      }
    }
    if (moduleRecord && moduleRecord.loaded) scannedModules.set(moduleRecord, exports);
  };

  const scanCache = () => {
    for (const loaded of Object.values(require.cache)) {
      if (!loaded) continue;
      try {
        instrumentResolved(loaded.filename, loaded.exports, false, loaded);
      } catch (_) {
        // Export discovery must not interfere with module loading.
      }
    }
  };
  const builtinParent = require.main || null;
  const loadedBuiltins = new Set();
  const scanBuiltins = () => {
    for (const rule of rules) {
      const marker = ':exports.';
      const markerIndex = rule.reference.indexOf(marker);
      if (markerIndex < 0 || markerIndex !== rule.reference.lastIndexOf(marker)) continue;
      const moduleName = rule.reference.slice(0, markerIndex);
      const requestedName = moduleName.startsWith('node:') ? moduleName.slice(5) : moduleName;
      if (!Module.builtinModules.includes(requestedName) || loadedBuiltins.has(moduleName)) continue;
      loadedBuiltins.add(moduleName);
      try {
        const exports = originalLoad.call(Module, moduleName, builtinParent, false);
        instrumentResolved(moduleName, exports, true);
      } catch (err) {
        const index = rules.indexOf(rule);
        diagnose(index, `failed to load built-in module ${moduleName}`, err);
      }
    }
  };
  state.addRules(injectedRules);
  state.rescan = () => {
    scannedModules = new WeakMap();
    loadedBuiltins.clear();
    scanCache();
    scanBuiltins();
  };
  scanCache();
  scanBuiltins();
  if (originalLoad && !originalLoad.__obiDynamicSpanWrapped) {
    const load = function (request, parent, isMain) {
      const exports = originalLoad.apply(this, arguments);
      try {
        const moduleId = Module._resolveFilename(request, parent, isMain);
        instrumentResolved(moduleId, exports, false, Module._cache[moduleId]);
      } catch (_) {
        // A module-load hook must not affect application module loading.
      }
      return exports;
    };
    load.__obiDynamicSpanWrapped = true;
    Module._load = load;
  }
})();
