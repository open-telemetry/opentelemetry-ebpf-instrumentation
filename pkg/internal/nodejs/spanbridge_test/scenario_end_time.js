'use strict';
// A valid explicit span.end(t) must be emitted as endWallNs (epoch ns);
// a missing or unusable argument must omit the field.

const fs = require('fs');
const path = require('path');

const records = [];
const origAccess = fs.accessSync;
fs.accessSync = (p, ...rest) => {
  if (typeof p === 'string' && p.startsWith('/dev/null/obi-span/')) {
    records.push(JSON.parse(p.slice('/dev/null/obi-span/'.length)));
    const err = new Error('ENOTDIR');
    err.code = 'ENOTDIR';
    throw err;
  }
  return origAccess(p, ...rest);
};

const src = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
// eslint-disable-next-line no-eval
eval(src);

const api = require('@opentelemetry/api');
const tracer = api.trace.getTracer('app');

const dateEnd = new Date('2026-08-19T12:00:00.250Z');
tracer.startSpan('end-date').end(dateEnd);

// Epoch milliseconds must be >= performance.timeOrigin: below it a number is
// a performance.now()-style offset (matching @opentelemetry/core).
const millisEnd = Date.now() + 1000;
tracer.startSpan('end-millis').end(millisEnd);

const hrEnd = [1786968001, 456789]; // [seconds, nanoseconds]
tracer.startSpan('end-hrtime').end(hrEnd);

tracer.startSpan('end-none').end();

tracer.startSpan('end-bogus').end('not a time');

// performance.now()-style offset (below performance.timeOrigin): must resolve
// against timeOrigin like @opentelemetry/core does.
const perfEnd = performance.now();
tracer.startSpan('end-perf').end(perfEnd);

// Fractional epoch millis must keep sub-ms precision.
const fracEnd = Date.now() + 2000 + 0.456;
tracer.startSpan('end-frac').end(fracEnd);

// Epoch millis just below performance.timeOrigin (possible after a clock
// adjustment) must still be read as epoch, not as an offset.
const nearOriginEnd = Math.trunc(performance.timeOrigin) - 1;
tracer.startSpan('end-near-origin').end(nearOriginEnd);

// A finite number too large for the decoder's int64 must be rejected.
tracer.startSpan('end-huge').end(1e21);

fs.accessSync = origAccess;

const byName = {};
for (const r of records) byName[r.name] = r;

process.stdout.write(
  JSON.stringify({
    names: records.map((r) => r.name).sort(),
    date: byName['end-date'] && byName['end-date'].endWallNs,
    dateExpected: (BigInt(dateEnd.getTime()) * 1000000n).toString(),
    millis: byName['end-millis'] && byName['end-millis'].endWallNs,
    millisExpected: (BigInt(millisEnd) * 1000000n).toString(),
    hrtime: byName['end-hrtime'] && byName['end-hrtime'].endWallNs,
    hrtimeExpected: (BigInt(hrEnd[0]) * 1000000000n + BigInt(hrEnd[1])).toString(),
    none: byName['end-none'] && byName['end-none'].endWallNs,
    bogus: byName['end-bogus'] && byName['end-bogus'].endWallNs,
    perf: byName['end-perf'] && byName['end-perf'].endWallNs,
    perfLowerBoundNs: (BigInt(Math.trunc(performance.timeOrigin)) * 1000000n).toString(),
    frac: byName['end-frac'] && byName['end-frac'].endWallNs,
    fracWholeMsNs: (BigInt(Math.trunc(fracEnd)) * 1000000n).toString(),
    huge: byName['end-huge'] && byName['end-huge'].endWallNs,
    nearOrigin: byName['end-near-origin'] && byName['end-near-origin'].endWallNs,
    nearOriginExpected: (BigInt(nearOriginEnd) * 1000000n).toString(),
  })
);
