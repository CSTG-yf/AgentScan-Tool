[CmdletBinding()]
param(
    [string]$InstallerPath = "",
    [Alias("Destination")]
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"
$desktopRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $desktopRoot
if (-not $InstallerPath) {
    $InstallerPath = Join-Path $repoRoot "dist\TraceBastion-Desktop-Setup-x64.exe"
}
$InstallerPath = (Resolve-Path -LiteralPath $InstallerPath).Path
if (-not $InstallDir) {
    $InstallDir = Join-Path $env:ProgramFiles "TraceBastion Desktop"
}
if (-not [IO.Path]::IsPathRooted($InstallDir)) {
    throw "InstallDir must be an absolute Windows path."
}
$InstallDir = [IO.Path]::GetFullPath($InstallDir).TrimEnd([IO.Path]::DirectorySeparatorChar)
if (-not (Split-Path -Parent $InstallDir)) {
    throw "InstallDir cannot be the root of a drive."
}

$installDir = $InstallDir
$installedExe = Join-Path $installDir "defenseclaw-desktop.exe"
$gatewayExe = Join-Path $installDir "resources\defenseclaw-gateway.exe"
$uninstaller = Join-Path $installDir "uninstall.exe"
$uninstallKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\TraceBastion Desktop"
$systemRoot = Join-Path $env:ProgramData "DefenseClaw"
$policyPath = Join-Path $systemRoot "process-guard.json"
$auditPath = Join-Path $systemRoot "audit\process-guard.jsonl"
$markerPath = Join-Path $systemRoot "process-guard.installed"
$hadPolicy = Test-Path -LiteralPath $policyPath
$hadAudit = Test-Path -LiteralPath $auditPath
$policyBackup = if ($hadPolicy) { [IO.File]::ReadAllBytes($policyPath) } else { $null }
$auditBackup = if ($hadAudit) { [IO.File]::ReadAllBytes($auditPath) } else { $null }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run the installer acceptance test from an elevated PowerShell session."
}
if ((Test-Path -LiteralPath $installDir) -or (Test-Path -LiteralPath $uninstallKey)) {
    throw "A pre-existing TraceBastion Desktop installation was found; refusing to modify it."
}
sc.exe query DefenseClawProcessGuard *> $null
if ($LASTEXITCODE -eq 0) {
    throw "A pre-existing DefenseClawProcessGuard service was found; refusing to modify it."
}

function Wait-StableInstall([Diagnostics.Process]$SetupProcess) {
    for ($attempt = 0; $attempt -lt 240; $attempt++) {
        $setupRunning = (-not $SetupProcess.HasExited) -or [bool](
            Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.ProcessName -like "*TraceBastion*setup*" }
        )
        $filesReady = (Test-Path -LiteralPath $installedExe) -and
            (Test-Path -LiteralPath $gatewayExe) -and
            (Test-Path -LiteralPath $uninstaller) -and
            (Test-Path -LiteralPath $uninstallKey)
        if (-not $setupRunning -and $filesReady) {
            Start-Sleep -Seconds 2
            if ((Test-Path -LiteralPath $installedExe) -and (Test-Path -LiteralPath $uninstallKey)) {
                return
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw "Installer did not reach a stable completed state within 60 seconds."
}

function Wait-StableUninstall {
    for ($attempt = 0; $attempt -lt 240; $attempt++) {
        $uninstallRunning = Get-Process -Name "uninstall" -ErrorAction SilentlyContinue
        sc.exe query DefenseClawProcessGuard *> $null
        $removed = -not $uninstallRunning -and $LASTEXITCODE -eq 1060 -and
            -not (Test-Path -LiteralPath $installDir) -and
            -not (Test-Path -LiteralPath $uninstallKey) -and
            -not (Test-Path -LiteralPath $markerPath)
        if ($removed) {
            Start-Sleep -Seconds 2
            sc.exe query DefenseClawProcessGuard *> $null
            if ($LASTEXITCODE -eq 1060 -and -not (Test-Path -LiteralPath $installDir)) {
                return
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw "Uninstaller did not reach a stable clean state within 60 seconds."
}

try {
    # NSIS requires /D to be the final argument. It consumes the remainder of
    # the command line, so an absolute destination containing spaces is valid.
    $setup = Start-Process -FilePath $InstallerPath `
        -ArgumentList "/S", "/D=$installDir" -PassThru
    Wait-StableInstall $setup
    if ($setup.HasExited -and $setup.ExitCode -ne 0) {
        throw "Installer exited with code $($setup.ExitCode)."
    }

    $registeredLocation = (Get-ItemProperty -LiteralPath $uninstallKey -Name InstallLocation).InstallLocation.Trim('"').TrimEnd('\')
    if (-not $registeredLocation.Equals($installDir, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Installer registered '$registeredLocation' instead of requested destination '$installDir'."
    }

    $gatewayHelp = & $gatewayExe --help 2>&1
    if ($LASTEXITCODE -ne 0 -or ($gatewayHelp -join "`n") -notmatch "start") {
        throw "Bundled gateway smoke test failed."
    }

    & $installedExe --install-process-guard
    $running = $false
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        $query = sc.exe query DefenseClawProcessGuard 2>&1
        if ($LASTEXITCODE -eq 0 -and ($query -join "`n") -match "RUNNING") {
            $running = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $running) { throw "Installed process guard did not reach RUNNING state." }

    & $uninstaller /S
    Wait-StableUninstall

    [pscustomobject]@{
        Result = "PASS"
        InstallerSha256 = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
        InstallDirectory = $installDir
        RegisteredLocation = $registeredLocation
        Gateway = "PASS"
        ServiceRan = $running
        StableUninstall = $true
    }
}
finally {
    if (Test-Path -LiteralPath $installedExe) {
        & $installedExe --uninstall-process-guard
    }
    if (Test-Path -LiteralPath $uninstaller) {
        & $uninstaller /S
        try { Wait-StableUninstall } catch { Write-Warning $_ }
    }
    if ($hadPolicy) {
        [IO.File]::WriteAllBytes($policyPath, $policyBackup)
    }
    elseif (Test-Path -LiteralPath $policyPath) {
        Remove-Item -LiteralPath $policyPath -Force
    }
    if ($hadAudit) {
        [IO.File]::WriteAllBytes($auditPath, $auditBackup)
    }
    elseif (Test-Path -LiteralPath $auditPath) {
        Remove-Item -LiteralPath $auditPath -Force
    }
}
