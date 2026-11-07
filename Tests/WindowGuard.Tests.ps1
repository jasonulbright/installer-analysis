#Requires -Modules Pester
# Tests the window-test guard itself (Test-WindowTestsAllowed in WindowHarness.ps1) with injected
# parameters, and checks that every test file that opens a window uses the guard.
# This file opens no window and starts no runspace.

BeforeDiscovery {
    $script:WindowPattern = 'Invoke-WpfSta|New-WpfWindow|ShowDialog|\.Show\(\)|WindowHarness'
    $script:WindowTestCases = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.Tests.ps1' -File |
            Where-Object { $_.Name -ne 'WindowGuard.Tests.ps1' -and (Get-Content -LiteralPath $_.FullName -Raw) -match $script:WindowPattern } |
            ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

BeforeAll {
    . "$PSScriptRoot\WindowHarness.ps1"
    # Calls the guard with injected values (the computer name is test data, not a target).
    function Get-Guard($Computer, $OptIn) { Test-WindowTestsAllowed -ComputerName $Computer -OptIn $OptIn }
}

Describe 'Test-WindowTestsAllowed' {
    It 'refuses on the dev PC even with the opt-in' {
        (Get-Guard 'AYW' '1').Allowed | Should -BeFalse
    }

    It 'refuses on the dev PC when the name is lower case' {
        (Get-Guard 'ayw' '1').Allowed | Should -BeFalse
    }

    It 'allows another computer with the opt-in' {
        (Get-Guard 'CM01' '1').Allowed | Should -BeTrue
    }

    It 'refuses another computer when the opt-in is <Label>' -ForEach @(
        @{ Label = 'empty'; OptIn = '' }
        @{ Label = '0'; OptIn = '0' }
        @{ Label = 'missing'; OptIn = $null }
    ) {
        $r = Get-Guard 'CM01' $OptIn
        $r.Allowed | Should -BeFalse
        $r.Reason | Should -Match 'SUITE_ALLOW_WINDOW_TESTS'
    }

    It 'gives a reason when it refuses' -ForEach @(
        @{ ComputerName = 'AYW'; OptIn = '1' }
        @{ ComputerName = 'CM01'; OptIn = '0' }
    ) {
        (Get-Guard $ComputerName $OptIn).Reason | Should -Not -BeNullOrEmpty
    }

    It 'names the dev PC as the reason on the dev PC' {
        (Get-Guard 'AYW' '0').Reason | Should -Match 'dev PC'
    }
}

Describe 'Window test files' {
    It 'finds the window test files' {
        # Discovery variables do not exist in the run phase, so the file list is read again here.
        $files = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.Tests.ps1' -File | Where-Object { $_.Name -ne 'WindowGuard.Tests.ps1' -and (Get-Content -LiteralPath $_.FullName -Raw) -match 'Invoke-WpfSta|WindowHarness' })
        $files.Count | Should -BeGreaterOrEqual 1
    }

    It '<Name> uses the guard' -ForEach $script:WindowTestCases {
        Get-Content -LiteralPath $Path -Raw | Should -Match 'Test-WindowTestsAllowed'
    }
}