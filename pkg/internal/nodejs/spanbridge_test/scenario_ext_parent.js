'use strict';
// External-parent flagging: when the app supplies a parent
// context the bridge does NOT own (a remote/app SpanContext set via
// trace.setSpan / setSpanContext), the emitted record must carry
// `extParent: true` so user space can flatten the span under the OBI request
// parent instead of exporting a parent id that belongs to a different trace.
// A NESTED bridge span (parent is the bridge's own active span) must NOT be
// flagged — its parent chain survives re-anchoring and must be kept.
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

// Inject the bridge, then load the api (wired via the module-load hook).
const src = fs.readFileSync(path.join(__dirname, '..', 'spanbridge.js'), 'utf8');
// eslint-disable-next-line no-eval
eval(src);

const api = require('@opentelemetry/api');
const tracer = api.trace.getTracer('app');

// 1. External parent: a remote SpanContext the bridge never created.
const EXT_TRACE = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const EXT_SPAN = 'bbbbbbbbbbbbbbbb';
const extCtx = api.trace.setSpanContext(api.context.active(), {
  traceId: EXT_TRACE,
  spanId: EXT_SPAN,
  traceFlags: 1,
});
tracer.startSpan('with-ext-parent', undefined, extCtx).end();

// 2. Nested bridge spans: parent is the bridge's own span.
tracer.startActiveSpan('bridge-root', (root) => {
  tracer.startSpan('bridge-child').end();
  root.end();
});

// 3. No parent at all.
tracer.startSpan('orphan').end();

fs.accessSync = origAccess;

const byName = {};
for (const r of records) byName[r.name] = r;

process.stdout.write(
  JSON.stringify({
    names: records.map((r) => r.name),
    ext: {
      extParent: byName['with-ext-parent'] && byName['with-ext-parent'].extParent,
      psid: byName['with-ext-parent'] && byName['with-ext-parent'].psid,
      tid: byName['with-ext-parent'] && byName['with-ext-parent'].tid,
    },
    child: {
      extParent: byName['bridge-child'] && byName['bridge-child'].extParent,
      psid: byName['bridge-child'] && byName['bridge-child'].psid,
    },
    root: {
      sid: byName['bridge-root'] && byName['bridge-root'].sid,
      extParent: byName['bridge-root'] && byName['bridge-root'].extParent,
    },
    orphan: {
      extParent: byName['orphan'] && byName['orphan'].extParent,
      psid: byName['orphan'] && byName['orphan'].psid,
    },
  })
);
