'use strict';

exports.sync = (value) => value + 1;
exports.async = async (value) => {
  await new Promise((resolve) => setImmediate(resolve));
  return value + 2;
};
const promiseWithThenGetter = Promise.resolve('promise result');
let thenGetterReads = 0;
Object.defineProperty(promiseWithThenGetter, 'then', {
  configurable: true,
  get() {
    thenGetterReads++;
    throw new Error('then getter must not be read by instrumentation');
  },
});
exports.promiseResult = promiseWithThenGetter;
exports.promiseWithThenGetter = () => promiseWithThenGetter;
exports.thenGetterReads = () => thenGetterReads;
exports.fail = () => {
  throw new Error('expected failure');
};
let proxyTraps = 0;
exports.proxyContainer = new Proxy({ failure: () => 'proxy failure target' }, {
  ownKeys(target) {
    proxyTraps++;
    return Reflect.ownKeys(target);
  },
  getOwnPropertyDescriptor(target, property) {
    proxyTraps++;
    return Reflect.getOwnPropertyDescriptor(target, property);
  },
});
exports.proxyTrapCount = () => proxyTraps;
let proxyPrototypeTraps = 0;
const proxyPrototype = new Proxy({}, {
  getPrototypeOf() {
    proxyPrototypeTraps++;
    return null;
  },
  ownKeys() {
    proxyPrototypeTraps++;
    return [];
  },
});
exports.proxyInPrototype = Object.create(proxyPrototype);
exports.proxyInPrototype.failure = () => 'proxy prototype target';
exports.proxyPrototypeTrapCount = () => proxyPrototypeTraps;
let callableProxyApplyCalls = 0;
let callableProxyPrototypeTraps = 0;
exports.callableProxy = new Proxy(() => 'callable proxy target', {
  apply(target, thisArg, args) {
    callableProxyApplyCalls++;
    return Reflect.apply(target, thisArg, args);
  },
  getPrototypeOf(target) {
    callableProxyPrototypeTraps++;
    return Reflect.getPrototypeOf(target);
  },
});
exports.callableProxyApplyCalls = () => callableProxyApplyCalls;
exports.callableProxyPrototypeTraps = () => callableProxyPrototypeTraps;
exports.callable = function () {
  return 'callable parent';
};
exports.callable.marker = 'callable marker';
exports.callable.nested = {
  work: () => 'callable nested',
};

function ExampleConstructor(value) {
  this.value = value;
  this.constructedWith = new.target;
}
ExampleConstructor.marker = 'constructor marker';
ExampleConstructor.prototype.describe = function () {
  return `example:${this.value}`;
};
exports.ExampleConstructor = ExampleConstructor;
