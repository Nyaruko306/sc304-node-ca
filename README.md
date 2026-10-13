# sc304 CA bundle for Node/Electron apps

Generate a PEM trust bundle from the **Steamcommunity302 (sc304)** certificates
installed in the Windows certificate store, so that Node-based and Electron-based
applications can reach hosts that sc304 redirects.

The bundle holds every sc304 **root** plus the **intermediate** the proxy presents
in a live handshake.

## The problem

sc304 redirects hosts (GitHub, Steam, Spotify, …) to `127.0.0.1` and serves them
through a local proxy that **intercepts TLS**. Every intercepted host therefore
presents a certificate signed by a sc304 intermediate:

```
leaf (api.github.com)                       valid ~3 days
 └─ Steamcommunity302 - ECC Intermediate    valid ~7 days
     └─ Steamcommunity302 - ... Root        valid until 2035/2036
```

Browsers and Windows tools accept this because sc304 installs its root into the
Windows certificate store. **Node and Electron do not read that store** — they
trust their own built-in Mozilla root list — so requests fail with:

```
UNABLE_TO_GET_ISSUER_CERT_LOCALLY: unable to get local issuer certificate
```

The fix is to point `NODE_EXTRA_CA_CERTS` at a bundle containing the sc304 CA.
Node treats this variable as *additional* trust anchors; your built-in roots are
left untouched.

A useful symptom split: if plain-tunneled hosts work while sc304-intercepted
hosts fail **in the same process at the same moment**, the problem is certificate
trust, not connectivity or proxy configuration.

## What this repo gives you

| File | Purpose |
|---|---|
| `Update-S302CaBundle.ps1` | Build the bundle: every sc304 root from the cert store, plus the live intermediate |
| `Get-S302Chain.js` | Helper: print the certificates the proxy presents above the leaf, as PEM |
| `Test-S302CaBundle.js` | Verify the bundle against the live proxy with a real request |

## Usage

```powershell
# Build the bundle (default: ~/.dsh/s302-ca.pem)
powershell -ExecutionPolicy Bypass -File .\Update-S302CaBundle.ps1

# Custom location
powershell -ExecutionPolicy Bypass -File .\Update-S302CaBundle.ps1 -BundlePath D:\certs\s302-ca.pem

# Roots only, no handshake
powershell -ExecutionPolicy Bypass -File .\Update-S302CaBundle.ps1 -SkipChain
```

Then make the variable visible to the target application:

```powershell
setx NODE_EXTRA_CA_CERTS "C:\Users\<you>\.dsh\s302-ca.pem"
```

Sign out and back in (or set the variable in the shell that launches the app) —
`setx` does not affect already-running processes or Explorer.

> **Restart the application after the bundle changes.** Node reads
> `NODE_EXTRA_CA_CERTS` and caches the result when a process first uses TLS, so a
> running app keeps using the file it loaded at startup.

Verify independently:

```powershell
$env:NODE_EXTRA_CA_CERTS = "$env:USERPROFILE\.dsh\s302-ca.pem"
node .\Test-S302CaBundle.js
# OK    api.github.com/rate_limit -> HTTP/1.1 200 OK (certificate trusted via ...)
```

The verifier asks whether the **certificate is trusted**, so any HTTP status
counts as success — `404` on `github.com/rate_limit` means that path does not
exist, not that the bundle is wrong. Only a failed tunnel or a rejected
certificate fails the run.

### Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `-BundlePath` | `~/.dsh/s302-ca.pem` | Where to write the bundle |
| `-NamePattern` | `Steamcommunity302` | Subject substring to match (raise this to `Root` to grab every root, or point it at another MITM tool's CA to bundle several) |
| `-ProbeHost` | `api.github.com` | Host used to capture the live chain and to verify |
| `-ProxyPort` | `80` | Port the intercepting proxy listens on |
| `-SkipChain` | off | Roots only; skip the handshake |
| `-SkipVerify` | off | Skip the live request check |

Exit codes: `0` ok · `1` no matching certificate · `2` write failed ·
`3` live verification failed.

`Get-S302Chain.js` is a normal Node script and can be used alone:

```powershell
node .\Get-S302Chain.js api.github.com 80     # PEM on stdout, diagnostics on stderr
```

## Design notes

**Keep every distinct root, do not group by subject.** sc304 ships several roots
that share a subject but are different keys. Grouping by subject and keeping one
per group silently drops roots, which then breaks whichever host is signed by a
dropped one. Extra trusted certificates are harmless, so all unique thumbprints
are kept.

**Ship the intermediate as well as the roots.** Roots alone are normally enough,
because the server sends its intermediate on every handshake. If the proxy ever
omits it — for example while rotating its signing certificate — that handshake
fails even with the root trusted, so the current intermediate is included too.
It is captured live rather than hard-coded, because it rotates on the order of a
week. The **leaf is deliberately excluded**: it is host-specific and rotates
every few days, so baking it in would age badly.

**Write atomically.** The bundle is written to `<path>.tmp` and then moved into
place. A half-written trust bundle would break every HTTPS request from the app.

**Capture failures are not fatal.** If Node is missing, the proxy is down, or the
handshake fails, the script warns and still writes a roots-only bundle, which
works whenever the proxy sends its intermediate.

**PowerShell 5.1 compatible.** `[Convert]::ToBase64String($bytes,
'InsertLineBreaks')` is unavailable in 5.1, so the base64 is wrapped by hand. The
`.ps1` files are ASCII-only on purpose: 5.1 reads BOM-less script files as ANSI,
so non-ASCII literals can corrupt string terminators.

**Explicit process exit after TLS.** Running TLS over a manually built socket has
been observed to trip a native access violation (`0xC0000005`) during teardown in
some Node builds. Both Node scripts therefore write their report synchronously
with `fs.writeSync(1, ...)` and exit immediately, so the output survives.

## Scope and caveats

- Windows only (uses the `Cert:` provider). For macOS/Linux, export sc304's CA
  from the system trust store instead and point `NODE_EXTRA_CA_CERTS` at it.
- Adding a CA to the trust store means that CA can sign certificates your app
  will accept. Only do this for a proxy you control and trust. To undo:
  `setx NODE_EXTRA_CA_CERTS ""`.
- Certificates are only half the story: an HTTP proxy configured via
  `HTTP_PROXY` / `HTTPS_PROXY` still has to point at a live port. If you switch
  from sc304 to a TUN-mode proxy, remove those variables — a TUN captures
  traffic at the network layer and needs no HTTP proxy setting.
- This tool never reads or writes private keys; it exports public certificates
  only.

## License

MIT — see [LICENSE](LICENSE).
