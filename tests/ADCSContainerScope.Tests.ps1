#Requires -Modules Pester
<#
    Regression coverage for the AD CS "container object leaks in as a
    fake template/CA" bug.

    Get-ADObject -SearchBase "CN=Certificate Templates,..." (or
    "CN=Enrollment Services,...") with the DEFAULT SearchScope (Subtree)
    returns the CONTAINER OBJECT ITSELF in addition to its real children -
    pKICertificateTemplate/pKIEnrollmentService objects are never nested
    further than one level under these containers, so nothing downstream
    ever needs Subtree's extra reach, but nothing filtered the container
    out either. The container's own Name is literally "Certificate
    Templates"/"Enrollment Services", it has no dNSHostName/cACertificate/
    template attributes, and was silently iterated by every check as if it
    were a real template or CA (e.g. "CA 'Enrollment Services' has no
    dNSHostName; skipping ESC8 probe" - about the container, not any real,
    misconfigured CA).

    This is a static source-inspection test rather than a functional mock
    test: Test-ADCertificateServices/Test-ADCSExtended are large functions
    with substantial unrelated setup (module imports, Get-Acl, live
    registry/network calls) that would need extensive mocking to execute
    safely here. Asserting the fix's actual shape (-SearchScope OneLevel on
    every affected call) is a reliable, low-risk guard against this
    specific regression reappearing, without depending on being able to
    fully execute those functions.

    Run from the repo root:  Invoke-Pester ./tests/ADCSContainerScope.Tests.ps1
#>

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    $script:AffectedFiles = @(
        (Join-Path $root 'src/CertificateServicesAudits.ps1')
        (Join-Path $root 'src/CertificateServicesExtendedAudits.ps1')
    )
}

Describe 'AD CS container-object exclusion (Certificate Templates / Enrollment Services)' {
    It 'every Get-ADObject call against the Certificate Templates container specifies -SearchScope OneLevel' {
        foreach ($file in $script:AffectedFiles) {
            $content = Get-Content -Path $file -Raw
            $lines = [regex]::Matches($content, 'Get-ADObject[^\r\n]*"CN=Certificate Templates[^\r\n]*')
            $lines.Count | Should -BeGreaterThan 0 -Because "expected at least one Certificate Templates query in $file"
            foreach ($line in $lines) {
                $line.Value | Should -Match '-SearchScope\s+OneLevel' -Because "a Subtree (default) search over the Certificate Templates container also returns the container object itself in $file : $($line.Value)"
            }
        }
    }

    It 'every Get-ADObject call against the Enrollment Services container specifies -SearchScope OneLevel' {
        foreach ($file in $script:AffectedFiles) {
            $content = Get-Content -Path $file -Raw
            $lines = [regex]::Matches($content, 'Get-ADObject[^\r\n]*"CN=Enrollment Services[^\r\n]*')
            $lines.Count | Should -BeGreaterThan 0 -Because "expected at least one Enrollment Services query in $file"
            foreach ($line in $lines) {
                $line.Value | Should -Match '-SearchScope\s+OneLevel' -Because "a Subtree (default) search over the Enrollment Services container also returns the container object itself in $file : $($line.Value)"
            }
        }
    }
}
