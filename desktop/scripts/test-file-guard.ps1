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
$tracePath = Join-Path $systemRoot "trace\agent-trace.db"
$testRoot = Join-Path $env:TEMP ("defenseclaw-file-guard-e2e-" + [guid]::NewGuid().ToString("N"))
$blacklistedFile = Join-Path $testRoot "sensitive.txt"
$testPolicy = Join-Path $testRoot "process-guard.json"
$auditBackup = Join-Path $env:TEMP ("defenseclaw-audit-policy-" + [guid]::NewGuid().ToString("N") + ".csv")
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

New-Item -ItemType Directory -Path $testRoot | Out-Null
[IO.File]::WriteAllText($blacklistedFile, "fixture secret", (New-Object Text.UTF8Encoding($false)))
& auditpol.exe /backup "/file:$auditBackup" *> $null
if ($LASTEXITCODE -ne 0) { throw "Backing up Windows audit policy failed: $LASTEXITCODE" }

Push-Location $tauriRoot
try {
    cargo build --locked
    if ($LASTEXITCODE -ne 0) { throw "Desktop debug build failed: $LASTEXITCODE" }
    cargo build --locked --example guard_fixture
    if ($LASTEXITCODE -ne 0) { throw "Guard fixture build failed: $LASTEXITCODE" }

    $policy = @{
        version = 2
        enabled = $true
        mode = "enforce"
        agentNames = @("guard_fixture.exe")
        rules = @()
        fileGuard = @{
            enabled = $true
            auditRoots = @()
            blacklist = @(
                @{
                    id = "e2e.file.sensitive"
                    enabled = $true
                    path = $blacklistedFile
                    matchKind = "exact"
                    access = @("read")
                    action = "terminateAgentTree"
                    description = "Acceptance-test sensitive file"
                }
            )
        }
        trace = @{
            enabled = $true
            captureProcesses = $true
            captureFileReads = $true
            captureFileWrites = $true
            captureFileCreates = $true
            captureFileDeletes = $true
            retentionDays = 30
            maxDatabaseMb = 256
        }
        termination = @{
            gracePeriodMs = 0
            verifyProcessIdentity = $true
            protectedProcessBehavior = "auditOnly"
        }
    }
    [IO.File]::WriteAllText($testPolicy, ($policy | ConvertTo-Json -Depth 10), (New-Object Text.UTF8Encoding($false)))

    & $desktopExe --apply-process-guard-policy $testPolicy
    if ($LASTEXITCODE -ne 0) { throw "Applying file-guard policy failed: $LASTEXITCODE" }
    & $desktopExe --install-process-guard
    if ($LASTEXITCODE -ne 0) { throw "Installing process guard failed: $LASTEXITCODE" }

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
    $fixture = Start-Process -FilePath $fixtureExe -ArgumentList @("--read-file", $blacklistedFile) -PassThru -WindowStyle Hidden
    if (-not $fixture.WaitForExit(15000)) {
        throw "File guard did not terminate the fixture Agent within 15 seconds."
    }

    $pending = Get-Content -LiteralPath $auditPath -Encoding UTF8 |
        ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object {
            $_.eventType -eq "process-guard-service" -and
            $_.outcome -eq "fileTerminationPending" -and
            $_.detail -like "*e2e.file.sensitive*" -and
            $_.detail -like "*$blacklistedFile*" -and
            [DateTimeOffset]::Parse($_.timestamp) -ge $startedAt
        } |
        Select-Object -Last 1
    if ($null -eq $pending) {
        throw "No blacklist file-access evidence was recorded for the fixture Agent."
    }
    if (-not (Test-Path -LiteralPath $tracePath)) {
        throw "SQLite Trace database was not created."
    }

    [pscustomobject]@{
        Result = "PASS"
        FixturePid = $fixture.Id
        Rule = "e2e.file.sensitive"
        File = $blacklistedFile
        TraceDatabase = $tracePath
        Evidence = $pending.detail
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
    if (Test-Path -LiteralPath $auditBackup) {
        & auditpol.exe /restore "/file:$auditBackup" *> $null
        Remove-Item -LiteralPath $auditBackup -Force
    }
    if (Test-Path -LiteralPath $blacklistedFile) { Remove-Item -LiteralPath $blacklistedFile -Force }
    if (Test-Path -LiteralPath $testPolicy) { Remove-Item -LiteralPath $testPolicy -Force }
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Force }
    Pop-Location
}

for ($attempt = 0; $attempt -lt 60; $attempt++) {
    sc.exe query DefenseClawProcessGuard *> $null
    if ($LASTEXITCODE -eq 1060) { break }
    Start-Sleep -Milliseconds 250
}
if ($LASTEXITCODE -ne 1060) {
    throw "Acceptance-test cleanup failed; service still exists after 15 seconds."
}
Write-Output "Cleanup: service absent, audit policy and original guard policy restored."
exit 0
