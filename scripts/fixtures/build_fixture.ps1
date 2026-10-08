# Builds the benign Go runtime fixture (tests/fixtures/go/fixture.go) for
# both of GoMemForensics' current Phase 1/2 targets: Windows x86-64 and
# Linux x86-64. Requires a local Go toolchain (any version; Go's toolchain
# cross-compiles regardless of host GOARCH).
#
# This fixture contains no malware behavior - see tests/fixtures/go/fixture.go
# for its full source and intent.
#
# Usage:
#   pwsh scripts/fixtures/build_fixture.ps1
#
# Output (gitignored - build artifacts are not committed):
#   tests/fixtures/go/bin/gomemforensics_fixture_windows_amd64.exe
#   tests/fixtures/go/bin/gomemforensics_fixture_linux_amd64

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$fixtureDir = Join-Path $repoRoot "tests\fixtures\go"
$outDir = Join-Path $fixtureDir "bin"

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

Write-Host "[+] Go toolchain:" (go version)

Push-Location $fixtureDir
try {
    Write-Host "[+] Building windows/amd64 fixture..."
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    go build -o (Join-Path $outDir "gomemforensics_fixture_windows_amd64.exe") fixture.go

    Write-Host "[+] Building linux/amd64 fixture..."
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    go build -o (Join-Path $outDir "gomemforensics_fixture_linux_amd64") fixture.go
}
finally {
    Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}

Write-Host "[+] Fixture binaries written to $outDir"
Write-Host "[!] These binaries are build artifacts, not evidence or malware - do not treat them as a captured memory image."
