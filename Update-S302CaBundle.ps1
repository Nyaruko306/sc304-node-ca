# Refresh the sc304 CA trust bundle for DeepSeek Harness.
#
# Why this exists: the sc304 (Steamcommunity302) proxy performs TLS interception,
# signing every redirected host with its own CA. Node/Electron does not read the
# Windows certificate store, so the harness rejects those certificates with
# UNABLE_TO_GET_ISSUER_CERT_LOCALLY until NODE_EXTRA_CA_CERTS points at the CA.
#
# You normally only need to run this when sc304 installs a NEW ROOT. The leaf
# certificate rotates every ~3 days and the intermediate every ~7, but those are
# sent by the server on every handshake -- only the roots must be trusted
# locally, and they are valid until 2035/2036.
#
# Usage:
#   pwsh -File Update-S302CaBundle.ps1
#   pwsh -File Update-S302CaBundle.ps1 -BundlePath "D:\certs\s302-ca.pem"
#
# Exit codes: 0 ok | 1 no matching cert | 2 export failed | 3 verification failed
[CmdletBinding()]
param(
    [string]$BundlePath = (Join-Path $env:USERPROFILE '.dsh\s302-ca.pem'),
    [string]$NamePattern = 'Steamcommunity302',
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "    $msg" -ForegroundColor Yellow }

# ---------------------------------------------------------------- collect certs
Write-Step "Enumerating '$NamePattern' roots in Cert:\CurrentUser\Root"

# Match on Subject; also accept the LocalMachine store as a fallback so this
# works when sc304 was installed for all users.
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

# --------------------------------------------------------------- build the PEM
# Keep every distinct root. Deliberately NOT grouped by Subject: sc304 ships
# several roots that share a subject but are different keys (and rotas over
# time), and dropping one would make the bundle fail for hosts signed by it.
# Trusting extra roots is harmless, so keep them all, newest first.
$unique = $certs | Sort-Object Thumbprint -Unique |
    Sort-Object NotAfter -Descending

$pem = New-Object System.Text.StringBuilder
$written = 0
foreach ($cert in $unique) {
    # Break the base64 into 64-char lines. Done by hand rather than with
    # [Convert]::ToBase64String(...,'InsertLineBreaks') because that overload is
    # unavailable under Windows PowerShell 5.1.
    $flat = [Convert]::ToBase64String($cert.RawData)
    $b64 = for ($i = 0; $i -lt $flat.Length; $i += 64) {
        $flat.Substring($i, [Math]::Min(64, $flat.Length - $i))
    }
    [void]$pem.AppendLine('-----BEGIN CERTIFICATE-----')
    [void]$pem.AppendLine($b64)
    [void]$pem.AppendLine('-----END CERTIFICATE-----')
    $written++
    Write-Ok ("kept {0}  (to {1:yyyy-MM-dd}, thumb {2})" -f $cert.Subject, $cert.NotAfter, $cert.Thumbprint.Substring(0, 8))
}

# ------------------------------------------------------------------ write file
$dir = Split-Path -Parent $BundlePath
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Write-Ok "created $dir"
}

# Write atomically: a half-written trust bundle would break every HTTPS request.
$tmp = "$BundlePath.tmp"
try {
    Set-Content -LiteralPath $tmp -Value $pem.ToString() -Encoding Ascii
    Move-Item -LiteralPath $tmp -Destination $BundlePath -Force
} catch {
    if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    Write-Host "Failed to write $BundlePath : $_" -ForegroundColor Red
    Write-Host "If the harness is running as another user, run this script elevated." -ForegroundColor Yellow
    exit 2
}
Write-Ok "wrote $written certificate(s) -> $BundlePath"

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
            & $node.Source $script 2>&1 | ForEach-Object { Write-Host "    $_" }
            if ($LASTEXITCODE -ne 0) {
                Write-Host 'Live verification failed. If sc304 introduced a new root, re-run after sc304 is started.' -ForegroundColor Red
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
Write-Host 'Done. Restart DeepSeek Harness if the bundle changed.' -ForegroundColor Green
exit 0
