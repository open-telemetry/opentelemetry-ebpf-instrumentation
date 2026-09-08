'use strict';
// Multibyte truncation boundary: attribute keys/values (and
// name/status message) are truncated to UTF-8 BYTE budgets because the Go side
// copies them into fixed byte arrays (key[32], value[128], NUL-terminated).
// A UTF-16 code-unit budget would let e.g. sixteen 'é' (16 units, 32 bytes)
// pass the 31-unit key check and then be split mid-sequence by the 31-byte
// copy, exporting invalid UTF-8. The bridge must truncate on a valid UTF-8
// sequence boundary so every emitted string fits its byte budget intact.
//
// Runs in its own process (the api global registry is a process singleton).

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

// Key: 16 x 'é' = 16 UTF-16 units but 32 UTF-8 bytes. Budget is 31 bytes, so
// a unit-based check passes it through and the fixed 31-byte copy would split
// the last 2-byte sequence. Byte-boundary truncation must yield 15 x 'é' (30B).
const key = 'é'.repeat(16);
// Value: 43 x '€' (3 bytes each = 129B) over the 127B budget; boundary
// truncation must yield 42 x '€' (126B), never a split sequence.
const value = '€'.repeat(43);
// Name: 128B budget; 43 x '€' = 129B -> 42 x '€' (126B).
const name = '€'.repeat(43);

const span = tracer.startSpan(name);
span.setAttribute(key, value);
span.end();

fs.accessSync = origAccess;

const rec = records[0] || {};
const attrKeys = Object.keys(rec.attrs || {});
const emittedKey = attrKeys[0] || '';
const emittedValue = rec.attrs ? rec.attrs[emittedKey] : '';

const bytes = (s) => Buffer.byteLength(s || '', 'utf8');
// A split sequence would surface as U+FFFD after the JSON round-trip.
const clean = (s) => !String(s || '').includes('�');

process.stdout.write(
  JSON.stringify({
    keyBytes: bytes(emittedKey),
    keyOK: emittedKey === 'é'.repeat(15) && clean(emittedKey),
    valueBytes: bytes(emittedValue),
    valueOK: emittedValue === '€'.repeat(42) && clean(emittedValue),
    nameBytes: bytes(rec.name),
    nameOK: rec.name === '€'.repeat(42) && clean(rec.name),
  })
);
