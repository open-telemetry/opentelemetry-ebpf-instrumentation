// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

(() => {
  'use strict';

  const rules = __OBI_DYNAMIC_SPAN_RULES__;
  const bridge = globalThis.__obiSpanBridge;
  if (!Array.isArray(rules) || rules.length === 0) return;

  const Module = require('module');
  const originalLoad = Module._load;
  const wrappedFunctions = new WeakMap();
  const diagnosedRules = new Set();
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

  const getExport = (exports, path) => {
    let parent = exports;
    for (let index = 0; index < path.length - 1; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(parent, path[index]);
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) return null;
      parent = descriptor.value;
      if (parent === null || (typeof parent !== 'object' && typeof parent !== 'function')) return null;
    }
    const key = path[path.length - 1];
    const descriptor = Object.getOwnPropertyDescriptor(parent, key);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value') || typeof descriptor.value !== 'function') {
      return null;
    }
    return { parent, key, descriptor, original: descriptor.value };
  };

  const instrumentExport = (exports, rule) => {
    const target = getExport(exports, rule.exportPath);
    if (!target) return false;

    let spanNames = wrappedFunctions.get(target.original);
    if (Array.isArray(spanNames)) {
      if (!spanNames.includes(rule.name)) spanNames.push(rule.name);
      return true;
    }

    const original = target.original;
    spanNames = [];
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
    target.descriptor.value = wrapper;
    try {
      Object.defineProperty(target.parent, target.key, target.descriptor);
    } catch (_) {
      return false;
    }
    if (!spanNames.includes(rule.name)) spanNames.push(rule.name);
    return true;
  };

  const resolveId = (specifier, parent, isMain) => {
    try {
      return Module._resolveFilename(specifier, parent, isMain);
    } catch (_) {
      return null;
    }
  };

  const isBuiltin = (specifier) => {
    if (typeof Module.isBuiltin === 'function') return Module.isBuiltin(specifier);
    const normalized = specifier.startsWith('node:') ? specifier.slice(5) : specifier;
    return Module.builtinModules.includes(normalized);
  };

  const instrumentResolved = (moduleId, exports, parent, isMain) => {
    for (const [index, rule] of rules.entries()) {
      const targetId = resolveId(rule.moduleSpecifier, parent, isMain);
      if (targetId === null || targetId !== moduleId) continue;
      try {
        if (!instrumentExport(exports, rule)) {
          diagnose(index, `export path ${rule.exportPath.join('.')} is missing or is not an own data-property function`);
        }
      } catch (err) {
        diagnose(index, `failed to inspect or instrument export path ${rule.exportPath.join('.')}`, err);
      }
    }
  };

  for (const loaded of Object.values(require.cache)) {
    if (!loaded) continue;
    instrumentResolved(loaded.filename, loaded.exports, loaded.parent || require.main || module, false);
  }

  // Built-ins are absent from require.cache. Load and instrument configured
  // built-in exports now so references held by the application before
  // injection point at the same, instrumented export object.
  const parent = require.main || module;
  for (const rule of rules) {
    if (!isBuiltin(rule.moduleSpecifier)) continue;
    const moduleId = resolveId(rule.moduleSpecifier, parent, false);
    if (moduleId === null) continue;
    try {
      const exports = originalLoad.call(Module, rule.moduleSpecifier, parent, false);
      instrumentResolved(moduleId, exports, parent, false);
    } catch (err) {
      const index = rules.indexOf(rule);
      diagnose(index, `failed to load built-in module ${rule.moduleSpecifier}`, err);
    }
  }

  if (originalLoad && !originalLoad.__obiDynamicSpanWrapped) {
    const load = function (request, parent, isMain) {
      const exports = originalLoad.apply(this, arguments);
      try {
        const moduleId = Module._resolveFilename(request, parent, isMain);
        instrumentResolved(moduleId, exports, parent, isMain);
      } catch (_) {
        // A module-load hook must not affect application module loading.
      }
      return exports;
    };
    load.__obiDynamicSpanWrapped = true;
    Module._load = load;
  }
})();
