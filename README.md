# sc304 CA bundle for Node/Electron apps

Generate a PEM trust bundle from the **Steamcommunity302 (sc304)** root
certificates installed in the Windows certificate store, so that Node-based and
Electron-based applications can reach hosts that sc304 redirects.

## The problem

sc304 redirects hosts (GitHub, Steam, Spotify, …) to `127.0.0.1` and serves them
through a local proxy that **intercepts TLS**. Every intercepted host therefore
presents a certificate signed by a sc304 intermediate:

```
leaf (api.github.com)              valid ~3 days
 └─ Steamcommunity302 - ECC Intermediate   valid ~7 days
     └─ Steamcommunity302 - ... Root       valid until 2035/2036
```

Browsers and Windows tools accept this because sc304 installs its root into the
Windows certificate store. **Node and Electron do not read that store** — they
trust their own built-in Mozilla root list — so requests fail with:

```
UNABLE_TO_GET_ISSUER_CERT_LOCALLY: unable to get local issuer certificate
```

The fix is to point `NODE_EXTRA_CA_CERTS` at the sc304 roots. Node treats this
variable as *additional* trust anchors; your built-in roots are left untouched.

## What this repo gives you

| File | Purpose |
|---|---|
| `Update-S302CaBundle.ps1` | Export all sc304 roots from the cert store into a PEM bundle |
| `Test-S302CaBundle.js` | Verify the bundle against the live proxy with a real request |

## Usage

```powershell
# Generate the bundle (default: ~/.dsh/s302-ca.pem)
powershell -ExecutionPolicy Bypass -File .\Update-S302CaBundle.ps1

# Custom location
powershell -ExecutionPolicy Bypass -File .\Update-S302CaBundle.ps1 -BundlePath D:\certs\s302-ca.pem
```

Then make the variable visible to the target application:

```powershell
setx NODE_EXTRA_CA_CERTS "C:\Users\<you>\.dsh\s302-ca.pem"
```

Sign out and back in (or set the variable in the shell that launches the app) —
`setx` does not affect already-running processes or Explorer.

Verify independently:

```powershell
$env:NODE_EXTRA_CA_CERTS = "$env:USERPROFILE\.dsh\s302-ca.pem"
node .\Test-S302CaBundle.js
# OK    api.github.com/rate_limit -> HTTP/1.1 200 OK (certificate trusted via ...)
```

### Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `-BundlePath` | `~/.dsh/s302-ca.pem` | Where to write the bundle |
| `-NamePattern` | `Steamcommunity302` | Subject substring to match (raise this to `Root` to grab every root, or point it at another MITM tool's CA to bundle several) |
| `-SkipVerify` | off | Skip the live request check |

Exit codes: `0` ok · `1` no matching certificate · `2` write failed ·
`3` live verification failed.

## Design notes

**Keep every distinct root, do not group by subject.** sc304 ships several roots
that share a subject but are different keys. Grouping by subject and keeping one
per group silently drops roots, which then breaks whichever host is signed by a
dropped one. Extra trusted roots are harmless, so all unique thumbprints are kept.

**Write atomically.** The bundle is written to `<path>.tmp` and then moved into
place. A half-written trust bundle would break every HTTPS request from the app.

**Only roots are needed.** The leaf rotates every ~3 days and the intermediate
every ~7, but both are sent by the server on each handshake. Trusting the
long-lived roots is sufficient, so the bundle does not need regenerating on
certificate rotation — only when sc304 installs a **new root**.

**PowerShell 5.1 compatible.** `[Convert]::ToBase64String($bytes,
'InsertLineBreaks')` is unavailable in 5.1, so the base64 is wrapped by hand.

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
