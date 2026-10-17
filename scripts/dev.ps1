param(
    [ValidateSet('check', 'test', 'build')]
    [string]$Task = 'check',
    [string]$GoExe = $env:NETEVIDENCE_GO_EXE,
    [string]$GoProxy = 'https://goproxy.cn,direct'
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if (-not $GoExe) {
    $goCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($goCommand) { $GoExe = $goCommand.Source }
}
if (-not $GoExe -or -not (Test-Path -LiteralPath $GoExe -PathType Leaf)) {
    throw 'Go executable not found. Pass -GoExe or set NETEVIDENCE_GO_EXE for this process.'
}

$GoExe = (Resolve-Path -LiteralPath $GoExe).Path
$env:PATH = "$(Split-Path -Parent $GoExe);$env:PATH"
$env:GOBIN = Join-Path $repoRoot '.tools/bin'
$env:GOPROXY = $GoProxy
New-Item -ItemType Directory -Path $env:GOBIN -Force | Out-Null
$env:PATH = "$env:GOBIN;$env:PATH"

Push-Location $repoRoot
try {
    & $GoExe version
    if ($LASTEXITCODE -ne 0) { throw 'Go version check failed.' }
    node --version
    if ($LASTEXITCODE -ne 0) { throw 'Node version check failed.' }
    npm --version
    if ($LASTEXITCODE -ne 0) { throw 'npm version check failed.' }
    if ($Task -eq 'check') { return }

    & $GoExe test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed.' }
    Push-Location 'frontend'
    try {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
        npm run check
        if ($LASTEXITCODE -ne 0) { throw 'Frontend check failed.' }
        if ($Task -eq 'build') {
            npm run build
            if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
        }
    } finally {
        Pop-Location
    }
    if ($Task -eq 'build') {
        & $GoExe install github.com/wailsapp/wails/v2/cmd/wails@v2.15.0
        if ($LASTEXITCODE -ne 0) { throw 'Wails CLI install failed.' }
        & (Join-Path $env:GOBIN 'wails.exe') build
        if ($LASTEXITCODE -ne 0) { throw 'Wails build failed.' }
    }
} finally {
    Pop-Location
}
