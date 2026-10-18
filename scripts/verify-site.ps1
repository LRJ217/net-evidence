param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [ValidateRange(5, 60)]
    [int]$TimeoutSeconds = 15
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$cli = Join-Path $repoRoot 'build/bin/net-evidence-cli.exe'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) {
    throw 'Build the CLI with scripts/dev.ps1 -Task build first.'
}
if ($Domain -notmatch '^[a-zA-Z0-9.-]+$' -or $Domain.Contains('..') -or $Domain.StartsWith('.') -or $Domain.EndsWith('.')) {
    throw 'Pass a root domain such as example.com.'
}
$base = $Domain.ToLowerInvariant()
if ($base.StartsWith('www.')) { $base = $base.Substring(4) }
$urls = @("http://$base/", "https://$base/", "http://www.$base/", "https://www.$base/")
$rows = foreach ($url in $urls) {
    $result = & $cli -timeout "$($TimeoutSeconds)s" -format json $url | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw "CLI failed for $url" }
    [pscustomobject]@{
        Target = $url
        DNS = $result.evidence.dns.status
        TCP = $result.evidence.tcp.status
        TLS = $result.evidence.tls.status
        HTTP = $result.evidence.http.status
        Code = $result.evidence.http.data.status_code
        DurationMs = $result.evidence.duration_ms
    }
}
$rows | Format-Table -AutoSize
