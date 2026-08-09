[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$desktopRoot = Split-Path -Parent $PSScriptRoot
$tauriRoot = Join-Path $desktopRoot "src-tauri"
$desktopExe = Join-Path $tauriRoot "target\debug\defenseclaw-desktop.exe"
$fixtureExe = Join-Path $tauriRoot "target\debug\examples\guard_fixture.exe"
$systemRoot = Join-Path $env:ProgramData "DefenseClaw"
$systemPolicy = Join-Path $systemRoot "process-guard.json"
$auditPath = Join-Path $systemRoot "audit\process-guard.jsonl"
$testPolicy = Join-Path $env:TEMP ("defenseclaw-process-guard-e2e-" + [guid]::NewGuid().ToString("N") + ".json")
$fixture = $null
$hadPolicy = Test-Path -LiteralPath $systemPolicy
$policyBackup = if ($hadPolicy) { [IO.File]::ReadAllBytes($systemPolicy) } else { $null }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this acceptance test from an elevated PowerShell session."
}

sc.exe query DefenseClawProcessGuard *> $null
if ($LASTEXITCODE -eq 0) {
    throw "DefenseClawProcessGuard already exists; refusing to modify a pre-existing service."
}
if ($LASTEXITCODE -ne 1060) {
    throw "Unexpected service preflight result: $LASTEXITCODE"
}

Push-Location $tauriRoot
try {
    cargo build --locked
    if ($LASTEXITCODE -ne 0) { throw "Desktop debug build failed: $LASTEXITCODE" }
    cargo build --locked --example guard_fixture
    if ($LASTEXITCODE -ne 0) { throw "Guard fixture build failed: $LASTEXITCODE" }

    $policy = @{
        version = 1
        enabled = $true
        mode = "enforce"
        agentNames = @("guard_fixture.exe")
        rules = @(
            @{
                id = "e2e.command.cmd"
                enabled = $true
                executable = "cmd.exe"
                action = "terminateAgentTree"
                description = "Acceptance-test command rule"
            }
        )
        termination = @{
            gracePeriodMs = 0
            verifyProcessIdentity = $true
            protectedProcessBehavior = "auditOnly"
        }
    }
    $policyJson = $policy | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($testPolicy, $policyJson, (New-Object Text.UTF8Encoding($false)))

    & $desktopExe --apply-process-guard-policy $testPolicy
    if ($LASTEXITCODE -ne 0) { throw "Applying the acceptance policy failed: $LASTEXITCODE" }
    & $desktopExe --install-process-guard
    if ($LASTEXITCODE -ne 0) { throw "Installing the process guard failed: $LASTEXITCODE" }

    $running = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $query = sc.exe query DefenseClawProcessGuard 2>&1
        if ($LASTEXITCODE -eq 0 -and ($query -join "`n") -match "RUNNING") {
            $running = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $running) { throw "Process guard did not reach RUNNING state." }

    $startedAt = [DateTimeOffset]::UtcNow
    $fixture = Start-Process -FilePath $fixtureExe -PassThru -WindowStyle Hidden
    if (-not $fixture.WaitForExit(15000)) {
        throw "The guard did not terminate the fixture Agent within 15 seconds."
    }

    $terminated = Get-Content -LiteralPath $auditPath -Encoding UTF8 |
        ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object {
            $_.eventType -eq "agent-command-rule-matched" -and
            $_.outcome -eq "terminated" -and
            $_.agentExecutable -ieq "guard_fixture.exe" -and
            [DateTimeOffset]::Parse($_.timestamp) -ge $startedAt
        } |
        Select-Object -Last 1
    if ($null -eq $terminated) {
        throw "No successful termination audit event was recorded for the fixture Agent."
    }

    [pscustomobject]@{
        Result = "PASS"
        Agent = $terminated.agentExecutable
        AgentPid = $terminated.agentPid
        Child = $terminated.childExecutable
        Rule = $terminated.ruleId
        Outcome = $terminated.outcome
        Detail = $terminated.detail
    }
}
finally {
    if ($null -ne $fixture -and -not $fixture.HasExited) {
        Stop-Process -Id $fixture.Id -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $desktopExe) {
        & $desktopExe --uninstall-process-guard
    }
    if ($hadPolicy) {
        [IO.File]::WriteAllBytes($systemPolicy, $policyBackup)
    }
    elseif (Test-Path -LiteralPath $systemPolicy) {
        Remove-Item -LiteralPath $systemPolicy -Force
    }
    Remove-Item -LiteralPath $testPolicy -Force -ErrorAction SilentlyContinue
    Pop-Location
}

for ($attempt = 0; $attempt -lt 60; $attempt++) {
    sc.exe query DefenseClawProcessGuard *> $null
    if ($LASTEXITCODE -eq 1060) { break }
    Start-Sleep -Milliseconds 250
}
if ($LASTEXITCODE -ne 1060) {
    throw "Acceptance-test cleanup failed; the service still exists after 15 seconds."
}
Write-Output "Cleanup: service absent and original policy restored."
