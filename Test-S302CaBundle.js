/**
 * Live verifier for the sc304 CA bundle.
 *
 * Dials the sc304 proxy, opens a CONNECT tunnel, performs a real TLS handshake
 * against the bundle named by NODE_EXTRA_CA_CERTS, and issues an HTTP request.
 * The question being answered is "is the intercepted certificate trusted?", so
 * ANY HTTP status counts as success -- a 404 only means that path does not exist
 * on that host, not that the bundle is wrong. Only a failed tunnel or a rejected
 * certificate fails the run.
 *
 * Usage:
 *   NODE_EXTRA_CA_CERTS=<bundle> node Test-S302CaBundle.js [host] [path]
 *
 * Environment:
 *   S302_PROXY_PORT  proxy port (default 80)
 *   S302_TIMEOUT_MS  timeout in ms (default 20000)
 *
 * Exit codes: 0 trusted and reachable | 1 failed.
 */
'use strict';

const fs = require('fs');
const net = require('net');
const tls = require('tls');

const host = process.argv[2] || 'api.github.com';
const urlPath = process.argv[3] || '/rate_limit';
const bundle = process.env.NODE_EXTRA_CA_CERTS;
const proxyPort = Number(process.env.S302_PROXY_PORT || 80);
const timeoutMs = Number(process.env.S302_TIMEOUT_MS || 20000);

// Buffer the report and hand it to the OS synchronously on the way out: a
// graceful teardown after TLS over a manual socket has been seen to trip a
// native access violation, which would otherwise discard buffered output.
const lines = [];
const say = (message) => lines.push(message);
function finish(code) {
  try { fs.writeSync(1, lines.join('\n') + '\n'); } catch { /* nothing else to do */ }
  process.exit(code);
}

if (!bundle) {
  say('FAIL  NODE_EXTRA_CA_CERTS is not set; nothing to verify against.');
  finish(1);
}

const sock = net.connect(proxyPort, '127.0.0.1');
let header = '';
let settled = false;

function settle(code, message) {
  if (settled) return;
  settled = true;
  if (message !== undefined) say(message);
  try { sock.destroy(); } catch { /* already gone */ }
  finish(code);
}

sock.setTimeout(timeoutMs, () => settle(1, `FAIL  timeout after ${timeoutMs}ms`));
sock.on('error', (e) => settle(1, `FAIL  cannot reach the proxy on 127.0.0.1:${proxyPort} (${e.code || e.message}); is sc304 running?`));
sock.on('connect', () => sock.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n\r\n`));

sock.on('data', function onHeader(chunk) {
  if (settled) return;
  header += chunk.toString('latin1');
  if (!header.includes('\r\n\r\n')) return;
  sock.removeListener('data', onHeader);

  const reply = header.slice(0, header.indexOf('\r\n\r\n'));
  if (!/^HTTP\/1\.[01] 200/.test(reply)) {
    return settle(1, `FAIL  the proxy refused CONNECT: ${reply.split('\r\n')[0]}`);
  }

  const t = tls.connect({ socket: sock, servername: host });

  t.on('error', (e) => {
    const code = e.code || e.name;
    say(`FAIL  TLS rejected for ${host}: ${code}`);
    if (code === 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' || code === 'UNABLE_TO_GET_ISSUER_CERT') {
      say('      The bundle does not cover the chain sc304 is currently signing with.');
      say('      Re-run Update-S302CaBundle.ps1 (sc304 may have installed a new root).');
    }
    settle(1);
  });

  t.on('secureConnect', () => {
    if (!t.authorized) {
      return settle(1, `FAIL  certificate not trusted: ${t.authorizationError}`);
    }
    // Trusted. Now just prove the tunnel carries traffic; any status is fine.
    t.write(`GET ${urlPath} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: dsh-s302-verify\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
  });

  let body = '';
  t.on('data', (d) => { body += d.toString('utf8'); });
  t.on('end', () => {
    const status = (body.split('\r\n')[0] || '').trim() || 'no response';
    say(`OK    ${host}${urlPath} -> ${status} (certificate trusted via ${bundle})`);
    settle(0);
  });
});
