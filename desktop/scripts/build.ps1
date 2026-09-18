[CmdletBinding()]
param(
    [switch]$SkipInstall,
    [switch]$WebOnly,
    [switch]$AllowMissingGateway,
    [switch]$SkipGatewayBuild
)

$ErrorActionPreference = "Stop"
$desktopRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $desktopRoot

function Require-Command([string]$Name, [string]$Hint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required. $Hint"
    }
}

Require-Command "pnpm" "Install Node.js 20+ and enable pnpm with Corepack."

Push-Location $desktopRoot
try {
    if (-not $SkipInstall) {
        pnpm install --frozen-lockfile
        if ($LASTEXITCODE -ne 0) { throw "pnpm install failed with exit code $LASTEXITCODE" }
    }

    if ($WebOnly) {
        pnpm build
        if ($LASTEXITCODE -ne 0) { throw "web build failed with exit code $LASTEXITCODE" }
        Write-Host "Web build complete: $desktopRoot\dist"
        return
    }

    Require-Command "cargo" "Install Rust stable with the MSVC toolchain."

    $iconFile = Join-Path $desktopRoot "src-tauri\icons\icon.ico"
    if (-not (Test-Path $iconFile)) {
        pnpm tauri icon "src-tauri\icons\app-icon.svg"
    }

    $existingGateway = Join-Path $desktopRoot "src-tauri\resources\defenseclaw-gateway.exe"
    $goCommand = Get-Command "go" -ErrorAction SilentlyContinue
    if ($SkipGatewayBuild) {
        if (-not (Test-Path $existingGateway)) {
            throw "Cannot skip gateway build because $existingGateway does not exist."
        }
        Write-Warning "Skipping gateway build; reusing the existing gateway resource."
    } elseif ($goCommand) {
        $resourceDir = Join-Path $desktopRoot "src-tauri\resources"
        New-Item -ItemType Directory -Force -Path $resourceDir | Out-Null
        & go build -trimpath -ldflags "-s -w" -o (Join-Path $resourceDir "defenseclaw-gateway.exe") "$repoRoot\cmd\defenseclaw"
        if ($LASTEXITCODE -ne 0) { throw "gateway build failed with exit code $LASTEXITCODE" }
    } else {
        if (-not $AllowMissingGateway -or -not (Test-Path $existingGateway)) {
            throw "Go is required to build the bundled gateway. Install the version declared by go.mod, or use -AllowMissingGateway only for a local shell build with an existing gateway resource."
        }
        Write-Warning "Go is not installed; reusing the existing development gateway resource."
    }

    pnpm tauri build --bundles nsis
    if ($LASTEXITCODE -ne 0) { throw "Tauri build failed with exit code $LASTEXITCODE" }

    # The desktop installer must let an operator choose its destination. Tauri's
    # standard NSIS template provides that page, but assert it here so a future
    # template/configuration change cannot silently turn the installer into a
    # fixed-path package.
    $generatedNsis = Get-ChildItem -LiteralPath (Join-Path $desktopRoot "src-tauri\target\release\nsis") `
        -Filter "installer.nsi" -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $generatedNsis) {
        throw "Tauri completed but the generated NSIS script could not be found."
    }
    if ((Get-Content -LiteralPath $generatedNsis.FullName -Raw) -notmatch '!insertmacro\s+MUI_PAGE_DIRECTORY') {
        throw "The generated NSIS installer does not contain a destination-folder selection page."
    }

    $bundleDir = Join-Path $desktopRoot "src-tauri\target\release\bundle\nsis"
    # A product rename can leave an older installer beside the new bundle.
    # Select the current product explicitly instead of copying an arbitrary EXE.
    $installer = Get-ChildItem -LiteralPath $bundleDir -Filter "TraceBastion Desktop_*-setup.exe" -File |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $installer) {
        throw "Tauri completed but no NSIS installer was found under $bundleDir"
    }
    $artifactDir = Join-Path $repoRoot "dist\windows"
    New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
    $releaseInstaller = Join-Path $artifactDir "TraceBastion-Desktop-Setup-Windows-x64.exe"
    Copy-Item -LiteralPath $installer.FullName -Destination $releaseInstaller -Force
    Write-Host "Installer: $releaseInstaller"
} finally {
    Pop-Location
}
