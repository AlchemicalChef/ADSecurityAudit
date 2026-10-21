#Requires -Modules Pester
<#
    Unit tests for Resolve-ADSecurityAuditPath (Common.ps1).

    Covers the reported -ExportPath ".\foldername" bug: a relative path
    resolved fine for Join-Path/Test-Path (PowerShell-provider-aware, honor
    $PWD), but a later raw .NET file write resolved it against
    [Environment]::CurrentDirectory instead - which many hosts leave
    pointing at the user's profile folder rather than keeping in sync with
    $PWD - so a perfectly valid, writable relative -ExportPath threw
    "Export path is not writable". These tests deliberately desync
    [Environment]::CurrentDirectory from $PWD (the exact condition that
    caused the bug) and confirm resolution still follows $PWD correctly.

    Run from the repo root:  Invoke-Pester ./tests/ResolveADSecurityAuditPath.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $root 'src/Common.ps1')
}

Describe 'Resolve-ADSecurityAuditPath' {
    It 'resolves a relative path against $PWD, not [Environment]::CurrentDirectory' {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "adsecaudit_test_$(Get-Random)"
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
        $originalCwd = [Environment]::CurrentDirectory
        try {
            # Deliberately desync [Environment]::CurrentDirectory from
            # $PWD - the exact real-world condition (IDE terminal, scheduled
            # task, some launch shortcuts) that produced the original bug.
            [Environment]::CurrentDirectory = [System.IO.Path]::GetTempPath()
            Push-Location $tempRoot
            try {
                $resolved = Resolve-ADSecurityAuditPath -Path ".\subfolder"
                $resolved | Should -Be (Join-Path $tempRoot "subfolder")
            }
            finally {
                Pop-Location
            }
        }
        finally {
            [Environment]::CurrentDirectory = $originalCwd
            Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'leaves an already-absolute path unchanged' {
        $absolute = Join-Path ([System.IO.Path]::GetTempPath()) "adsecaudit_absolute_test"
        $resolved = Resolve-ADSecurityAuditPath -Path $absolute
        $resolved | Should -Be $absolute
    }

    It 'does not require the path to already exist (string computation only)' {
        Push-Location ([System.IO.Path]::GetTempPath())
        try {
            { Resolve-ADSecurityAuditPath -Path ".\does-not-exist-yet-$(Get-Random)" } | Should -Not -Throw
        }
        finally {
            Pop-Location
        }
    }

    It 'resolves "." to the current $PWD' {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "adsecaudit_test_$(Get-Random)"
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null
        try {
            Push-Location $tempRoot
            try {
                Resolve-ADSecurityAuditPath -Path "." | Should -Be $tempRoot
            }
            finally {
                Pop-Location
            }
        }
        finally {
            Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
