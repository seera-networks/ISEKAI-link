<#
.SYNOPSIS
Package binaries with the DLLs they need to run somewhere else.

.DESCRIPTION
The Windows half of scripts/bundle-apps.sh, and much shorter for one reason:
Windows resolves a DLL from the directory the executable is in before anywhere
else, so beside the binaries is all this needs — no launcher, no rpath, no
load-command rewriting.

What it must not forget is `msquic.dll`, which seera-msquic's build script
produces and never installs. It lives under cargo's output with a build hash in
the path, so it is searched for rather than named — and a bundle without it
fails at startup on the first machine that is not the one that built it.

Anything else an app needs on top of this — the camera apps' OpenCV, for
instance — is that workflow's business to copy in afterwards.

.EXAMPLE
scripts/bundle-apps.ps1 rust/target/release dist portal-apps-windows portal-server portal-client
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ReleaseDir,
    [Parameter(Mandatory = $true)][string] $OutDir,
    [Parameter(Mandatory = $true)][string] $Name,
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]] $Apps
)

$ErrorActionPreference = 'Stop'

$stage = Join-Path $OutDir $Name
New-Item -ItemType Directory -Force -Path $stage | Out-Null

foreach ($app in $Apps) {
    $exe = Join-Path $ReleaseDir "$app.exe"
    if (-not (Test-Path $exe)) { throw "$exe not found; was it built?" }
    Copy-Item $exe $stage
}

# Searched rather than named: the directory carries a build hash, and CMake puts
# the DLL under `bin` or `lib` depending on the generator.
$msquic = Get-ChildItem -Path (Join-Path $ReleaseDir 'build') -Recurse -Filter msquic.dll `
    -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $msquic) { throw "msquic.dll not found under $ReleaseDir/build" }
Copy-Item $msquic.FullName $stage

# The bundle is meant to run somewhere else, and the machine that built it
# cannot answer whether it will — every DLL is installed here. So this asks the
# question that does not depend on the machine: is msquic.dll actually in the
# directory the loader will look in first?
if (-not (Test-Path (Join-Path $stage 'msquic.dll'))) {
    throw "the bundle has no msquic.dll; it would fail to start elsewhere"
}

Write-Host "bundled into ${stage}:"
Get-ChildItem $stage | Format-Table Name, Length
