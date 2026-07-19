[CmdletBinding()]
param(
    [string]$RangeRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")),
    [string]$OutputDir = (Join-Path $PSScriptRoot "reports")
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
python (Join-Path $PSScriptRoot "static_inventory.py") `
    --root $RangeRoot `
    --output (Join-Path $OutputDir "static-scan.json")
if ($LASTEXITCODE -ne 0) {
    throw "deterministic AgentRange static inventory failed"
}

if (-not (Get-Command defenseclaw -ErrorAction SilentlyContinue)) {
    Write-Warning "defenseclaw is not on PATH; deterministic report completed, optional scanner enrichment skipped"
    return
}

$skills = Get-ChildItem -LiteralPath (Join-Path $RangeRoot "skills") -Directory
foreach ($skill in $skills) {
    Write-Host "[skill] $($skill.Name)"
    & defenseclaw skill scan $skill.FullName --json 2>&1 |
        Out-File -Encoding utf8 (Join-Path $OutputDir "skill-$($skill.Name).json")
}

$codeTargets = @(
    (Join-Path $RangeRoot "mcp"),
    (Join-Path $RangeRoot "opspilot-app"),
    (Join-Path $RangeRoot "langflow")
)
foreach ($target in $codeTargets) {
    $name = Split-Path $target -Leaf
    Write-Host "[code] $name"
    & defenseclaw scan code $target 2>&1 |
        Out-File -Encoding utf8 (Join-Path $OutputDir "code-$name.txt")
}

Write-Host "Reports written to $OutputDir"
