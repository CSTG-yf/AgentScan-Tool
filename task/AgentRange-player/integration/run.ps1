[CmdletBinding()]
param(
    [ValidateSet("baseline", "observe", "action")]
    [string]$Mode = "observe"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root
New-Item -ItemType Directory -Force integration/reports, bench/results | Out-Null

python integration/static_inventory.py --output integration/reports/static-scan.json
python integration/rule_contract.py --output integration/reports/rule-contract.json

if ($Mode -eq "baseline") {
    $previous = $env:DEFENSECLAW_API_BASE
    $env:DEFENSECLAW_API_BASE = ""
    docker compose up -d --build --force-recreate
    $env:DEFENSECLAW_API_BASE = $previous
} else {
    if (-not $env:DEFENSECLAW_API_BASE -and -not (Select-String -Path .env -Pattern '^DEFENSECLAW_API_BASE=.+$' -Quiet -ErrorAction SilentlyContinue)) {
        throw "set DEFENSECLAW_API_BASE in the environment or .env"
    }
    defenseclaw setup guardrail --mode $Mode --restart
    docker compose up -d --build --force-recreate
}

python bench/benchmark.py run --mode $Mode --output "bench/results/$Mode.json"
python integration/attack_chain.py --output integration/reports/attack-chains.json
python integration/report.py
Write-Host "completed AgentRange $Mode run"
