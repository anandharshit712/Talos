<#
.SYNOPSIS
    Run the repository rule checkers on Windows, where `make` is usually absent.

.DESCRIPTION
    Thin wrapper over tools/checks/run_all_checks.py so local runs, pre-commit, and CI all
    execute identical logic. Use -Strict for the phase gate (adds the R3.5 test-mirror check)
    and -Full to also run ruff, mypy, and pytest.

.EXAMPLE
    .\scripts\run_checks.ps1
    .\scripts\run_checks.ps1 -Strict -Full
#>
[CmdletBinding()]
param(
    [switch]$Strict,
    [switch]$Full
)

$ErrorActionPreference = 'Continue'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

try {
    $failed = @()

    $checkArgs = @('tools/checks/run_all_checks.py')
    if ($Strict) { $checkArgs += '--strict' }
    & python @checkArgs
    if ($LASTEXITCODE -ne 0) { $failed += 'rule checks' }

    if ($Full) {
        & python -m ruff check .
        if ($LASTEXITCODE -ne 0) { $failed += 'ruff' }

        & python -m mypy
        if ($LASTEXITCODE -ne 0) { $failed += 'mypy' }

        & python -m pytest
        if ($LASTEXITCODE -ne 0) { $failed += 'pytest' }
    }

    if ($failed.Count -gt 0) {
        Write-Host ''
        Write-Host ("FAILED: " + ($failed -join ', ')) -ForegroundColor Red
        exit 1
    }

    Write-Host ''
    Write-Host 'All checks passed.' -ForegroundColor Green
    exit 0
}
finally {
    Pop-Location
}
