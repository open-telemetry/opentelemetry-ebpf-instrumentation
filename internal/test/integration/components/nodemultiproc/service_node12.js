// Dependency-free twin of service.js for the Node.js 12 image, where express 5
// and axios do not install. Same CLI, routes and upstream chaining.
const http = require('http');

/**
 * CLI Usage:
 * node service.js <route> <port> [upstreamURL]
 */
const [route = 'a', port = 5000, upstream] = process.argv.slice(2);

function forward(res) {
  http.get(upstream, (up) => {
    let body = '';
    up.on('data', (chunk) => { body += chunk; });
    up.on('end', () => res.end(`Service ${route.toUpperCase()} → ${body} <br>`));
  }).on('error', (err) => {
    console.error(`Error forwarding in Service ${route.toUpperCase()}:`, err.message);
    res.statusCode = 500;
    res.end(`Error forwarding to upstream: ${err.message}`);
  });
}

http.createServer((req, res) => {
  if (req.url === '/smoke') {
    res.statusCode = 200;
    res.end();
    return;
  }
  if (req.url !== `/${route}`) {
    res.statusCode = 404;
    res.end();
    return;
  }
  if (!upstream) {
    res.end(`Hello from Service ${route.toUpperCase()}`);
    return;
  }
  forward(res);
}).listen(port, () => {
  console.log(`Service ${route.toUpperCase()} running on port ${port}`);
  console.log(upstream ? `Forwarding to: ${upstream}` : `No upstream; responding directly`);
});
