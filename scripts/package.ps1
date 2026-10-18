param(
    [string]$GoExe = $env:NETEVIDENCE_GO_EXE,
    [string]$NSISBin = $env:NETEVIDENCE_NSIS_BIN
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if (-not $GoExe) {
    $goCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($goCommand) { $GoExe = $goCommand.Source }
}
if (-not $GoExe -or -not (Test-Path -LiteralPath $GoExe -PathType Leaf)) {
    throw 'Go executable not found. Pass -GoExe or set NETEVIDENCE_GO_EXE.'
}
$GoExe = (Resolve-Path -LiteralPath $GoExe).Path

if (-not $NSISBin) {
    $nsisCommand = Get-Command makensis.exe -ErrorAction SilentlyContinue
    if ($nsisCommand) { $NSISBin = Split-Path -Parent $nsisCommand.Source }
}
if (-not $NSISBin -or -not (Test-Path -LiteralPath (Join-Path $NSISBin 'makensis.exe') -PathType Leaf)) {
    throw 'NSIS makensis.exe not found. Pass -NSISBin or set NETEVIDENCE_NSIS_BIN.'
}
$NSISBin = (Resolve-Path -LiteralPath $NSISBin).Path

& (Join-Path $PSScriptRoot 'dev.ps1') -Task build -GoExe $GoExe
if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed.' }

$wails = Join-Path $repoRoot '.tools/bin/wails.exe'
if (-not (Test-Path -LiteralPath $wails -PathType Leaf)) { throw 'Pinned Wails CLI was not installed.' }
$env:PATH = "$(Split-Path -Parent $GoExe);$NSISBin;$env:PATH"
Push-Location $repoRoot
try {
    & $wails build -nsis -installscope user
    if ($LASTEXITCODE -ne 0) { throw 'Wails installer build failed.' }
    $installer = Join-Path $repoRoot 'build/bin/NetEvidence-amd64-installer.exe'
    if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Wails did not create the installer.' }
    Get-Item -LiteralPath $installer | Select-Object FullName, Length
    Write-Output "SHA-256: $((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash)"
} finally {
    Pop-Location
}
