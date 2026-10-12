// Live verifier for the sc304 CA bundle.
//
// Dials the sc304 proxy, opens a CONNECT tunnel to a redirected host, performs a
// real TLS handshake against the bundle in NODE_EXTRA_CA_CERTS, and issues an
// HTTP/1.1 GET. Exit 0 = trusted and reachable, 1 = failed.
//
// Usage: NODE_EXTRA_CA_CERTS=<bundle> node Test-S302CaBundle.js [host] [path]
const net = require('net');
const tls = require('tls');

const host = process.argv[2] || 'api.github.com';
const urlPath = process.argv[3] || '/rate_limit';
const bundle = process.env.NODE_EXTRA_CA_CERTS;
const proxyPort = Number(process.env.S302_PROXY_PORT || 80);
const timeoutMs = Number(process.env.S302_TIMEOUT_MS || 20000);

if (!bundle) {
  console.error('NODE_EXTRA_CA_CERTS is not set; nothing to verify against.');
  process.exit(1);
}

const sock = net.connect(proxyPort, '127.0.0.1');
let settled = false;
const finish = (code) => { if (!settled) { settled = true; try { sock.destroy(); } catch {} process.exit(code); } };

sock.setTimeout(timeoutMs, () => { console.error(`FAIL  timeout after ${timeoutMs}ms`); finish(1); });
sock.on('error', (e) => { console.error(`FAIL  cannot reach proxy 127.0.0.1:${proxyPort}: ${e.code || e.message}`); finish(1); });
sock.on('connect', () => sock.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n\r\n`));

let header = '';
let started = false;
sock.on('data', function onData(chunk) {
  if (started) return;
  header += chunk.toString('latin1');
  if (!header.includes('\r\n\r\n')) return;
  started = true;
  sock.removeListener('data', onData);

  const reply = header.slice(0, header.indexOf('\r\n\r\n'));
  if (!/^HTTP\/1\.[01] 200/.test(reply)) {
    console.error(`FAIL  proxy refused CONNECT: ${reply.split('\r\n')[0]}`);
    return finish(1);
  }

  const t = tls.connect({ socket: sock, servername: host });
  t.on('error', (e) => {
    const code = e.code || e.name;
    console.error(`FAIL  TLS rejected by ${host}: ${code}`);
    if (code === 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' || code === 'UNABLE_TO_GET_ISSUER_CERT') {
      console.error('      The bundle does not contain the root sc304 is currently signing with.');
    }
    finish(1);
  });
  t.on('secureConnect', () => {
    if (!t.authorized) {
      console.error(`FAIL  certificate not trusted: ${t.authorizationError}`);
      return finish(1);
    }
    t.write(`GET ${urlPath} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: dsh-s302-verify\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
  });

  let body = '';
  t.on('data', (d) => { body += d.toString('utf8'); });
  t.on('end', () => {
    const status = (body.split('\r\n')[0] || '').trim();
    if (/^HTTP\/1\.[01] 200/.test(status)) {
      console.log(`OK    ${host}${urlPath} -> ${status} (certificate trusted via ${bundle})`);
      return finish(0);
    }
    console.error(`FAIL  ${host}${urlPath} -> ${status || 'no response'}`);
    finish(1);
  });
});
