// start-all.js
const { spawn } = require('child_process');

const services = [
  { route: 'c', port: 6002 }, // End of chain
  { route: 'b', port: 6001, upstream: 'http://localhost:6002' }, // Middle - base URL only
  // Start - base URL only. The /large chain goes a -> Go service instead.
  { route: 'a', port: 6000, upstream: 'http://localhost:6001', largeUpstream: 'http://tpclient-go:6003' },
  // OTel SDK instrumented: its /large chain goes sdk -> b
  { route: 'sdk', port: 6004, largeUpstream: 'http://localhost:6001', preload: './otel.js' },
];

services.forEach(({ route, port, upstream = '', largeUpstream = '', preload }) => {
  const args = preload ? ['--require', preload] : [];
  args.push('service.js', route, port.toString(), upstream, largeUpstream);

  const proc = spawn('node', args, { stdio: 'inherit' });

  proc.on('exit', code => {
    console.log(`Service ${route.toUpperCase()} exited with code ${code}`);
  });
});
