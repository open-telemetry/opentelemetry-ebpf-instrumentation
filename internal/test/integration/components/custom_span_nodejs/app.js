// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Node.js HTTP server emitting custom_span_nodejs:order_start/_end + cache_hit
// USDT probes through a libstapsdt N-API binding. Mirrors the Python/Ruby/Go
// samples so the integration test exercises the same OBI custom_span code
// path on a fourth runtime.

const http = require('http');
const url = require('url');
const stapsdt = require('./build/Release/node_stapsdt.node');

const provider = stapsdt.providerInit('custom_span_nodejs');
const orderStart = stapsdt.addProbeU64U64(provider, 'order_start');
const orderEnd = stapsdt.addProbeU64I32(provider, 'order_end');
const cacheHit = stapsdt.addProbeU64(provider, 'cache_hit');
const loadRc = stapsdt.providerLoad(provider);
if (loadRc !== 0) {
    throw new Error(`providerLoad failed rc=${loadRc}`);
}

function processOrder(orderId, customer) {
    stapsdt.fireU64Str(orderStart, orderId, customer);
    const deadline = Date.now() + 5;
    while (Date.now() < deadline) {
        // small interpreted busy-wait so the span has measurable duration.
    }
    stapsdt.fireU64I32(orderEnd, orderId, 0);
}

function reply(res, code, body) {
    res.writeHead(code, { 'content-type': 'text/plain' });
    res.end(body);
}

const port = parseInt(process.env.PORT || '8396', 10);
http.createServer((req, res) => {
    const parsed = url.parse(req.url, true);
    if (parsed.pathname === '/smoke') {
        return reply(res, 200, 'ok');
    }
    if (parsed.pathname === '/order') {
        const orderId = Number(parsed.query.id || 1);
        const customer = String(parsed.query.customer || 'anonymous');
        processOrder(orderId, customer);
        return reply(res, 200, 'ok');
    }
    if (parsed.pathname === '/cache') {
        const key = String(parsed.query.key || '');
        stapsdt.fireStr(cacheHit, key);
        return reply(res, 200, 'ok');
    }
    reply(res, 404, 'not found');
}).listen(port, '0.0.0.0', () => {
    console.log(`custom_span_nodejs listening on ${port}`);
});
