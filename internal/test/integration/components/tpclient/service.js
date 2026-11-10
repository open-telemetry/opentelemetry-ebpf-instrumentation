const express = require('express');
const axios = require('axios');

const app = express();

/**
 * Traceparent Test Client Service
 *
 * CLI Usage:
 * node service.js <route> <port> [upstreamURL]
 *
 * Creates a chain: /no-tp or /with-tp -> forwards -> forwards -> end
 */

// largeUpstream: next hop of the /large chain, which goes through the Go service
const [route = 'a', port = 6000, upstream, largeUpstream] = process.argv.slice(2);

// Predefined traceparent for extraction testing (easy to spot)
// Span ID starts at 0000000000000001 and increments by 0x10 on each downstream call
const STATIC_TRACEPARENT = '00-12345678901234567890123456789012-0000000000000001-01';

// Forwarded traceparent for proxy detection testing (span ID: 1111111111111111)
// This traceparent is forwarded unchanged through the chain to trigger eBPF proxy detection
const FORWARDED_TRACEPARENT = '00-12345678901234567890123456789012-1111111111111111-01';

// Pushes a traceparent written after it well past the first 4 KiB of headers
const LARGE_COOKIE = 'session=' + 'a'.repeat(12 * 1024);

// Keeps the trace and increments the span ID by 0x10 for the downstream call
function nextTraceparent(traceparent) {
  const parts = traceparent.split('-');
  if (parts.length !== 4) {
    return traceparent;
  }
  const spanId = parseInt(parts[2], 16);
  parts[2] = (spanId + 0x10).toString(16).padStart(16, '0');
  return parts.join('-');
}

// rawHeaders keeps the wire order, so it tells where the first traceparent was
function receivedTraceparents(req) {
  let offset = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`.length;
  let traceparentOffset = -1;
  const traceparents = [];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const name = req.rawHeaders[i];
    const value = req.rawHeaders[i + 1];
    if (name.toLowerCase() === 'traceparent') {
      if (traceparentOffset < 0) {
        traceparentOffset = offset;
      }
      traceparents.push(value);
    }
    offset += `${name}: ${value}\r\n`.length;
  }
  return { traceparents, traceparentOffset };
}

// Endpoint: request with a large cookie, forwarded with the cookie and no
// traceparent of our own, which OBI must inject
app.get('/large', async (req, res) => {
  const received = { service: route, ...receivedTraceparents(req) };
  if (!largeUpstream) {
    res.json(received);
    return;
  }
  try {
    const downstreamURL = `${largeUpstream}/large`;
    console.log(`[${route}/large] Making client call to ${downstreamURL} with a large cookie`);
    const response = await axios.get(downstreamURL, { headers: { Cookie: LARGE_COOKIE } });
    res.json({ ...received, downstream: response.data });
  } catch (err) {
    console.error(`[${route}/large] Error:`, err.message);
    res.status(500).send(`Error: ${err.message}`);
  }
});

// Endpoint: Request WITHOUT traceparent (eBPF should generate)
app.get('/no-tp', async (req, res) => {
  if (upstream) {
    try {
      const downstreamURL = `${upstream}/no-tp`;
      console.log(`[${route}/no-tp] Making client call to ${downstreamURL} WITHOUT traceparent`);
      // DO NOT add traceparent - let eBPF generate it
      const response = await axios.get(downstreamURL);
      res.send(`${route}/no-tp → ${response.data}`);
    } catch (err) {
      console.error(`[${route}/no-tp] Error:`, err.message);
      res.status(500).send(`Error: ${err.message}`);
    }
  } else {
    res.send(`End of chain (${route})`);
  }
});

// Endpoint: Request WITH static traceparent (eBPF should extract)
app.get('/with-tp', async (req, res) => {
  if (upstream) {
    try {
      const downstreamURL = `${upstream}/with-tp`;

      // Get traceparent from incoming request or use base
      const traceparent = nextTraceparent(req.headers.traceparent || STATIC_TRACEPARENT);

      console.log(`[${route}/with-tp] Making client call to ${downstreamURL} WITH traceparent: ${traceparent}`);

      // Add traceparent to outgoing request - eBPF should extract it
      const response = await axios.get(downstreamURL, {
        headers: { 'traceparent': traceparent }
      });
      res.send(`${route}/with-tp → ${response.data}`);
    } catch (err) {
      console.error(`[${route}/with-tp] Error:`, err.message);
      res.status(500).send(`Error: ${err.message}`);
    }
  } else {
    res.send(`End of chain (${route})`);
  }
});

// Endpoint: Request WITH forwarded traceparent (eBPF should detect proxy and override span ID)
app.get('/with-forwarded-tp', async (req, res) => {
  if (upstream) {
    try {
      const downstreamURL = `${upstream}/with-forwarded-tp`;

      // Always forward the SAME traceparent unchanged (simulating a proxy)
      // This should trigger eBPF's proxy detection logic which will override the span ID
      console.log(`[${route}/with-forwarded-tp] Making client call to ${downstreamURL} WITH forwarded traceparent: ${FORWARDED_TRACEPARENT}`);

      const response = await axios.get(downstreamURL, {
        headers: { 'traceparent': FORWARDED_TRACEPARENT }
      });
      res.send(`${route}/with-forwarded-tp → ${response.data}`);
    } catch (err) {
      console.error(`[${route}/with-forwarded-tp] Error:`, err.message);
      res.status(500).send(`Error: ${err.message}`);
    }
  } else {
    res.send(`End of chain (${route})`);
  }
});

app.get('/smoke', (req, res) => {
  res.sendStatus(200);
});

app.listen(port, () => {
  console.log(`Service ${route.toUpperCase()} running on port ${port}`);
  console.log(upstream ? `Upstream: ${upstream}` : `End of chain`);
});
