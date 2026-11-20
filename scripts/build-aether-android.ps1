param(
    [string[]]$Targets = @("arm64-v8a", "x86_64"),
    [int]$ApiLevel = 26
)

Clear-Host
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$ExpectedBranch = "feature/cloudflare-one-masque"
$CurrentBranch = (git branch --show-current).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read the current Git branch."
}
if ($CurrentBranch -ne $ExpectedBranch) {
    throw "Refusing to build Aether outside '$ExpectedBranch'. Current branch: '$CurrentBranch'."
}

$AetherPath = Join-Path $RepoRoot "third_party/Aether"
$Manifest = Join-Path $AetherPath "aether/Cargo.toml"
$OutputDir = Join-Path $RepoRoot "app/src/main/jniLibs"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git is required."
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Rust Cargo is required."
}
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
    throw "rustup is required to verify Android Rust targets."
}
if (-not (Get-Command cargo-ndk -ErrorAction SilentlyContinue)) {
    throw "cargo-ndk is required. Install it with: cargo install cargo-ndk"
}

git submodule update --init --recursive -- third_party/Aether
if ($LASTEXITCODE -ne 0) {
    throw "Unable to initialize the Aether submodule."
}
if (-not (Test-Path $Manifest)) {
    throw "Aether Cargo manifest not found: $Manifest"
}

$TargetMap = @{
    "arm64-v8a" = "aarch64-linux-android"
    "x86_64" = "x86_64-linux-android"
    "armeabi-v7a" = "armv7-linux-androideabi"
}
foreach ($Abi in $Targets) {
    if (-not $TargetMap.ContainsKey($Abi)) {
        throw "Unsupported Android ABI '$Abi'. Supported: $($TargetMap.Keys -join ', ')"
    }
}

$InstalledTargets = @(rustup target list --installed)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to query installed Rust targets."
}
foreach ($Abi in $Targets) {
    $RustTarget = $TargetMap[$Abi]
    if ($InstalledTargets -notcontains $RustTarget) {
        throw "Rust target '$RustTarget' is missing. Install it with: rustup target add $RustTarget"
    }
}

if (-not $env:ANDROID_NDK_HOME -and -not $env:ANDROID_NDK_ROOT -and -not $env:NDK_HOME -and -not $env:ANDROID_HOME) {
    throw "Set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT / NDK_HOME / ANDROID_HOME) to an installed Android NDK."
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$CargoNdkArgs = @()
foreach ($Abi in $Targets) {
    $CargoNdkArgs += @("-t", $Abi)
}
$CargoNdkArgs += @(
    "-p", "$ApiLevel",
    "-o", $OutputDir,
    "build",
    "--manifest-path", $Manifest,
    "--release"
)

Write-Host "Building Aether for Android: $($Targets -join ', ')" -ForegroundColor Cyan
Write-Host "Pinned source: $((git -C $AetherPath rev-parse HEAD).Trim())"
Write-Host "Output: $OutputDir"

& cargo ndk @CargoNdkArgs
if ($LASTEXITCODE -ne 0) {
    throw "Aether Android build failed."
}

foreach ($Abi in $Targets) {
    $Library = Join-Path (Join-Path $OutputDir $Abi) "libaether.so"
    if (-not (Test-Path $Library)) {
        throw "Build completed but expected library was not produced: $Library"
    }
}

Write-Host "Aether Android libraries built successfully." -ForegroundColor Green
