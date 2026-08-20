// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// The Node.js counterpart of client.py: one outbound TLS request per inbound request.
// Node's TLSWrap is a memory BIO too, so the ciphertext leaves OpenSSL into a buffer
// and the event loop writes it to the socket afterwards, with no socket syscall inside
// the SSL_write uprobe window.

const http = require('http');
const https = require('https');

const listenPort = parseInt(process.env.LISTEN_PORT || '8080', 10);
const upstreamHost = process.env.UPSTREAM_HOST || 'tlsupstream';
const upstreamPort = parseInt(process.env.UPSTREAM_PORT || '8380', 10);
const upstreamPath = process.env.UPSTREAM_PATH || '/greeting';

// The upstream certificate is self-signed with a bare CN, so it can only be
// reached without verification. The peer a span must name comes from the socket.
const options = {
    host: upstreamHost,
    port: upstreamPort,
    path: upstreamPath,
    rejectUnauthorized: false,
    agent: new https.Agent({ keepAlive: false, rejectUnauthorized: false }),
};

http.createServer((req, res) => {
    req.resume();
    const upstream = https.get(options, (upstreamRes) => {
        upstreamRes.resume();
        upstreamRes.on('end', () => {
            res.writeHead(200, { 'Content-Length': 2, Connection: 'close' });
            res.end('ok');
        });
    });
    upstream.on('error', (err) => {
        console.error(`request failed: ${err.message}`);
        res.writeHead(502, { 'Content-Length': 3, Connection: 'close' });
        res.end('err');
    });
}).listen(listenPort, () => {
    console.log(`listening on ${listenPort}, calling https://${upstreamHost}:${upstreamPort}${upstreamPath}`);
});
