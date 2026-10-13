# Refresh the sc304 CA trust bundle for Node-based applications.
#
# Why this exists: the sc304 (Steamcommunity302) proxy performs TLS interception,
# signing every redirected host with its own CA. Node and Electron do not read the
# Windows certificate store, so such requests fail with
# UNABLE_TO_GET_ISSUER_CERT_LOCALLY until NODE_EXTRA_CA_CERTS points at a bundle
# containing that CA.
#
# What goes in the bundle:
#   * every sc304 root in the certificate store (one root per key type; sc304
#     ships several, and they stay valid into 2035/2036);
#   * the intermediate certificate the proxy presents in a live handshake.
#
# The intermediate is normally redundant -- the server sends it on every
# handshake -- but if the proxy ever omits it (for example mid rotation) a
# roots-only bundle fails that handshake. Shipping it as well covers both cases,
# and extra trusted certificates are harmless. The leaf is deliberately NOT
# included: it is host-specific and rotates every few days.
#
# Re-run this only when sc304 installs a new root, or when a bundle that used to
# work starts failing on intercepted hosts.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\Update-S302CaBundle.ps1
#   powershell -ExecutionPolicy Bypass -File .\Update-S302CaBundle.ps1 -BundlePath "D:\certs\s302-ca.pem"
#   powershell -ExecutionPolicy Bypass -File .\Update-S302CaBundle.ps1 -SkipChain   # roots only
#
# Exit codes: 0 ok | 1 no matching cert | 2 export failed | 3 verification failed
[CmdletBinding()]
param(
    [string]$BundlePath = (Join-Path $env:USERPROFILE '.dsh\s302-ca.pem'),
    [string]$NamePattern = 'Steamcommunity302',
    [string]$ProbeHost = 'api.github.com',
    [int]$ProxyPort = 80,
    [switch]$SkipChain,
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "    $msg" -ForegroundColor Yellow }

# Wrap one certificate as a PEM block. The base64 is broken into 64-char lines by
# hand: [Convert]::ToBase64String(...,'InsertLineBreaks') does not exist under
# Windows PowerShell 5.1.
function Get-PemBlock($cert) {
    $flat = [Convert]::ToBase64String($cert.RawData)
    $lines = for ($i = 0; $i -lt $flat.Length; $i += 64) {
        $flat.Substring($i, [Math]::Min(64, $flat.Length - $i))
    }
    return "-----BEGIN CERTIFICATE-----`n" + ($lines -join "`n") + "`n-----END CERTIFICATE-----"
}

# Parse PEM blocks coming back from Get-S302Chain.js into certificate objects.
function ConvertFrom-Pem($text) {
    $result = @()
    $rx = [regex]'-----BEGIN CERTIFICATE-----(?<body>[\s\S]*?)-----END CERTIFICATE-----'
    foreach ($m in $rx.Matches($text)) {
        $b64 = ($m.Groups['body'].Value -replace '\s', '')
        if ($b64.Length -eq 0) { continue }
        try {
            $der = [Convert]::FromBase64String($b64)
            $result += New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$der)
        } catch {
            Write-Warn2 'skipped an unparsable certificate from the chain output'
        }
    }
    return ,$result
}

# ---------------------------------------------------------------- collect roots
Write-Step "Enumerating '$NamePattern' roots in the certificate store"

# Match on Subject; LocalMachine is also read so this works when sc304 was
# installed for all users. Deduplicate by thumbprint afterwards, not by subject:
# sc304 ships several roots that share a subject but hold different keys.
$certs = @()
foreach ($store in @('Cert:\CurrentUser\Root', 'Cert:\LocalMachine\Root')) {
    if (-not (Test-Path $store)) { continue }
    $found = Get-ChildItem $store -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match [regex]::Escape($NamePattern) }
    if ($found) {
        Write-Ok "$store -> $($found.Count) certificate(s)"
        $certs += $found
    }
}

if ($certs.Count -eq 0) {
    Write-Host "No '$NamePattern' certificate found. Is sc304 running / has it been installed?" -ForegroundColor Red
    exit 1
}

$seen = @{}
$roots = @()
foreach ($cert in ($certs | Sort-Object NotAfter -Descending)) {
    if ($seen.ContainsKey($cert.Thumbprint)) { continue }
    $seen[$cert.Thumbprint] = $true
    $roots += $cert
    Write-Ok ("root         {0}  (to {1:yyyy-MM-dd}, thumb {2})" -f $cert.Subject, $cert.NotAfter, $cert.Thumbprint.Substring(0, 8))
}

# ------------------------------------------------- capture the live intermediate
$chain = @()
if ($SkipChain) {
    Write-Step 'Skipping intermediate capture (-SkipChain)'
} else {
    Write-Step "Capturing the certificate chain the proxy presents for $ProbeHost"
    $node = Get-Command node -ErrorAction SilentlyContinue
    $helper = Join-Path $PSScriptRoot 'Get-S302Chain.js'
    if (-not $node) {
        Write-Warn2 'node is not on PATH; writing a roots-only bundle'
    } elseif (-not (Test-Path $helper)) {
        Write-Warn2 "helper not found at $helper; writing a roots-only bundle"
    } else {
        # Best effort: a roots-only bundle still works whenever the proxy sends
        # its intermediate, so a capture failure must not fail the run.
        $raw = & $node.Source $helper $ProbeHost $ProxyPort 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warn2 "chain capture failed (exit $LASTEXITCODE); writing a roots-only bundle"
            $raw | ForEach-Object { if ("$_".Trim().Length -gt 0) { Write-Warn2 "  $_" } }
        } else {
            $parsed = ConvertFrom-Pem ($raw -join "`n")
            foreach ($cert in ($parsed | Sort-Object NotAfter -Descending)) {
                if ($seen.ContainsKey($cert.Thumbprint)) {
                    Write-Ok ("intermediate {0}  (already present as a root)" -f $cert.Subject)
                    continue
                }
                $seen[$cert.Thumbprint] = $true
                $chain += $cert
                Write-Ok ("intermediate {0}  (to {1:yyyy-MM-dd}, thumb {2})" -f $cert.Subject, $cert.NotAfter, $cert.Thumbprint.Substring(0, 8))
            }
            if ($chain.Count -eq 0) {
                Write-Warn2 'the proxy presented no intermediate above the leaf; nothing to add'
            }
        }
    }
}

# ------------------------------------------------------------------- write file
$blocks = @()
foreach ($cert in $roots) { $blocks += Get-PemBlock $cert }
foreach ($cert in $chain) { $blocks += Get-PemBlock $cert }
$pemText = ($blocks -join "`n") + "`n"
$total = $roots.Count + $chain.Count

$dir = Split-Path -Parent $BundlePath
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Write-Ok "created $dir"
}

# Write atomically: a half-written trust bundle would break every HTTPS request.
$tmp = "$BundlePath.tmp"
try {
    Set-Content -LiteralPath $tmp -Value $pemText -Encoding Ascii
    Move-Item -LiteralPath $tmp -Destination $BundlePath -Force
} catch {
    if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    Write-Host "Failed to write $BundlePath : $_" -ForegroundColor Red
    Write-Host 'If the harness is running as another user, run this script elevated.' -ForegroundColor Yellow
    exit 2
}
Write-Ok "wrote $total certificate(s) ($($roots.Count) root, $($chain.Count) intermediate) -> $BundlePath"

# -------------------------------------------------------------- verify + report
if (-not $SkipVerify) {
    Write-Step 'Verifying against the live proxy'
    $node = Get-Command node -ErrorAction SilentlyContinue
    if (-not $node) {
        Write-Warn2 'node not on PATH; skipping live check (bundle written anyway)'
    } else {
        $script = Join-Path $PSScriptRoot 'Test-S302CaBundle.js'
        if (Test-Path $script) {
            $env:NODE_EXTRA_CA_CERTS = $BundlePath
            & $node.Source $script $ProbeHost 2>&1 | ForEach-Object { Write-Host "    $_" }
            if ($LASTEXITCODE -ne 0) {
                Write-Host 'Live verification failed. If sc304 introduced a new root, restart sc304 and re-run.' -ForegroundColor Red
                exit 3
            }
        } else {
            Write-Warn2 "verifier not found at $script; skipping live check"
        }
    }
}

# ---------------------------------------------------------------------- report
Write-Step 'Current configuration'
$envVal = (Get-ItemProperty 'HKCU:\Environment' -ErrorAction SilentlyContinue).NODE_EXTRA_CA_CERTS
if ($envVal) {
    Write-Ok "HKCU\Environment NODE_EXTRA_CA_CERTS = $envVal"
} else {
    Write-Warn2 'NODE_EXTRA_CA_CERTS is NOT persisted in HKCU\Environment.'
    Write-Warn2 "Make it permanent with:  setx NODE_EXTRA_CA_CERTS `"$BundlePath`""
    Write-Warn2 'then sign out/in (or restart) so Explorer picks it up.'
}
Write-Host ''
Write-Host 'Done. Restart the applications that read this bundle: NODE_EXTRA_CA_CERTS is' -ForegroundColor Green
Write-Host 'read and cached when a process first uses TLS, so a running app keeps the old file.' -ForegroundColor Green
exit 0
