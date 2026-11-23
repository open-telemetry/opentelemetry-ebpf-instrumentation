'use strict';

exports.sync = (value) => value + 1;
exports.async = async (value) => {
  await new Promise((resolve) => setImmediate(resolve));
  return value + 2;
};
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
