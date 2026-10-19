param(
    [string]$Installer = 'build/bin/NetEvidence-amd64-installer.exe'
)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') {
    throw 'This smoke test may install software and must run only on an ephemeral GitHub Actions runner.'
}

$installerPath = (Resolve-Path -LiteralPath $Installer -ErrorAction Stop).Path
$installDir = Join-Path $env:LOCALAPPDATA 'Programs/NetEvidence'
$appPath = Join-Path $installDir 'NetEvidence.exe'
$uninstallRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
$historyDir = Join-Path $env:LOCALAPPDATA 'NetEvidence/history'
$sentinelPath = Join-Path $historyDir "ci-installer-smoke-$([guid]::NewGuid().ToString('N')).json"

function Get-NetEvidenceUninstallEntry {
    if (-not (Test-Path -LiteralPath $uninstallRoot)) { return @() }
    @(Get-ChildItem -LiteralPath $uninstallRoot | Where-Object {
        (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).DisplayName -eq 'NetEvidence'
    })
}

if (Test-Path -LiteralPath $installDir) { throw "Install directory already exists: $installDir" }
if (@(Get-NetEvidenceUninstallEntry).Count -ne 0) { throw 'NetEvidence is already registered for this user.' }

New-Item -ItemType Directory -Path $historyDir -Force | Out-Null
[IO.File]::WriteAllText($sentinelPath, '{"ci":"preserve history on uninstall"}', [Text.UTF8Encoding]::new($false))
$sentinelHash = (Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash

try {
    $installProcess = Start-Process -FilePath $installerPath -ArgumentList '/S' -Wait -PassThru -WindowStyle Hidden
    if ($installProcess.ExitCode -ne 0) { throw "Installer exited with code $($installProcess.ExitCode)." }
    if (-not (Test-Path -LiteralPath $appPath -PathType Leaf)) { throw 'Installed application was not found.' }
    if (@(Get-NetEvidenceUninstallEntry).Count -ne 1) { throw 'Expected one current-user uninstall entry.' }

    $uninstaller = Get-ChildItem -LiteralPath $installDir -File |
        Where-Object { $_.Name -match 'uninstall.*\.exe$' } |
        Select-Object -First 1
    if (-not $uninstaller) { throw 'Uninstaller was not found.' }

    $uninstallProcess = Start-Process -FilePath $uninstaller.FullName -ArgumentList '/S' -Wait -PassThru -WindowStyle Hidden
    if ($uninstallProcess.ExitCode -ne 0) { throw "Uninstaller exited with code $($uninstallProcess.ExitCode)." }
    if (Test-Path -LiteralPath $installDir) { throw 'Install directory remained after uninstall.' }
    if (@(Get-NetEvidenceUninstallEntry).Count -ne 0) { throw 'Uninstall registry entry remained.' }
    if (-not (Test-Path -LiteralPath $sentinelPath -PathType Leaf)) { throw 'History file was removed during uninstall.' }
    if ((Get-FileHash -LiteralPath $sentinelPath -Algorithm SHA256).Hash -ne $sentinelHash) {
        throw 'History file changed during uninstall.'
    }
    Write-Output 'Installer smoke test passed: install, uninstall, registry cleanup, and history preservation.'
} finally {
    Remove-Item -LiteralPath $sentinelPath -Force -ErrorAction SilentlyContinue
}
