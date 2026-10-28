'use strict';

exports.sync = (value) => value + 1;
exports.async = async (value) => {
  await new Promise((resolve) => setImmediate(resolve));
  return value + 2;
};
exports.fail = () => {
  throw new Error('expected failure');
};
exports.proxyFailure = () => 'proxy failure target';
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

module.exports = new Proxy(exports, {
  getOwnPropertyDescriptor(target, property) {
    if (property === 'proxyFailure') throw new Error('expected descriptor trap failure');
    return Reflect.getOwnPropertyDescriptor(target, property);
  },
});
