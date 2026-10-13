/**
 * Print the certificates a sc304-style intercepting proxy presents ABOVE the
 * leaf, as PEM on stdout.
 *
 * Why this exists: a trust bundle holding only roots is normally enough, because
 * the server sends its intermediate on every handshake. If the proxy ever omits
 * it -- for example while it is rotating its signing certificate -- that
 * handshake fails with UNABLE_TO_GET_ISSUER_CERT_LOCALLY even though the root is
 * trusted. Shipping the current intermediate alongside the roots covers both
 * cases; extra trusted certificates are harmless.
 *
 * The leaf itself is deliberately excluded: it is host-specific and rotates
 * every few days, so baking it into a bundle would age badly.
 *
 * Usage:
 *   node Get-S302Chain.js [host] [proxyPort]
 *
 * Environment:
 *   S302_TIMEOUT_MS  handshake timeout in ms (default 15000)
 *
 * Exit codes: 0 printed one or more certificates | 1 nothing usable.
 * Diagnostics go to stderr; stdout carries PEM only.
 */
'use strict';

const fs = require('fs');
const net = require('net');
const tls = require('tls');

const host = process.argv[2] || 'api.github.com';
const proxyPort = Number(process.argv[3] || 80);
const timeoutMs = Number(process.env.S302_TIMEOUT_MS || 15000);

let settled = false;

function fail(message) {
  finish();
  process.stderr.write(`Get-S302Chain: ${message}\n`);
  process.exit(1);
}

const sock = net.connect(proxyPort, '127.0.0.1');

function finish() {
  settled = true;
  try { sock.destroy(); } catch { /* already gone */ }
}

function emit(chain) {
  const pem = chain
    .map((der) => {
      const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n').trim();
      return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
    })
    .join('');

  // writeSync, then exit without a graceful teardown: running TLS over a
  // manually built socket has been observed to trip a native access violation in
  // some Node builds during teardown, which would otherwise lose a buffered
  // asynchronous write.
  fs.writeSync(1, pem);
  process.exit(0);
}

sock.setTimeout(timeoutMs, () => fail(`timeout after ${timeoutMs}ms waiting for the proxy`));
sock.on('error', (e) => fail(`cannot reach proxy 127.0.0.1:${proxyPort} (${e.code || e.message}); is sc304 running?`));
sock.on('connect', () => sock.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n\r\n`));

let header = '';
sock.on('data', function onHeader(chunk) {
  if (settled) return;
  header += chunk.toString('latin1');
  if (!header.includes('\r\n\r\n')) return;
  sock.removeListener('data', onHeader);

  const reply = header.slice(0, header.indexOf('\r\n\r\n'));
  if (!/^HTTP\/1\.[01] 200/.test(reply)) {
    return fail(`proxy refused CONNECT: ${reply.split('\r\n')[0]}`);
  }

  const t = tls.connect({ socket: sock, servername: host });
  t.on('error', (e) => fail(`TLS handshake for ${host} failed: ${e.code || e.message}`));
  t.on('secureConnect', () => {
    const chain = [];
    const seen = new Set();
    const leaf = t.getPeerCertificate(true);

    // Walk upward from the leaf's issuer, stopping at a self-signed repeat.
    let node = leaf && leaf.issuerCertificate;
    while (node && node.raw && !seen.has(node.fingerprint256)) {
      seen.add(node.fingerprint256);
      chain.push(node.raw);
      const next = node.issuerCertificate;
      node = next && next !== node ? next : null;
    }

    if (chain.length === 0) {
      return fail(`the proxy presented no certificate above the leaf for ${host}`);
    }
    settled = true;
    try { t.destroy(); } catch { /* ignore */ }
    emit(chain);
  });
});
