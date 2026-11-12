#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }
# Static checks of the capture scripts in tools\guide-capture. The test opens no window and
# runs no capture. It parses the scripts and checks that they carry no password, secret or
# credential file path: the caller gives the credential script and the lab values as parameters.

BeforeDiscovery {
    $script:CaptureDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\guide-capture'
    $script:ScriptCases = @(Get-ChildItem -LiteralPath $script:CaptureDir -Filter '*.ps1' -File | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } })
}

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:CaptureDir = Join-Path $script:Root 'tools\guide-capture'
    $script:InvokePath = Join-Path $script:CaptureDir 'Invoke-GuideCapture.ps1'
    $script:InvokeText = [System.IO.File]::ReadAllText($script:InvokePath)
    $script:InvokeAst = [System.Management.Automation.Language.Parser]::ParseFile($script:InvokePath, [ref]$null, [ref]$null)
}

Describe 'Capture scripts' {
    It 'has the four capture scripts' {
        foreach ($n in 'Invoke-GuideCapture.ps1', 'guilib.ps1', 'main.ps1', 'steps-guide.ps1') {
            Test-Path -LiteralPath (Join-Path $script:CaptureDir $n) | Should -BeTrue -Because $n
        }
    }

    It 'parses <Name> without error' -ForEach $script:ScriptCases {
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
        @($errors) | Should -BeNullOrEmpty
    }

    It 'has no password, secret or credential file literal in <Name>' -ForEach $script:ScriptCases {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $strings = @($ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                    $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst]
                }, $true) | ForEach-Object { $_.Value })
        $bad = foreach ($s in $strings) {
            if ($s -match '(?i)\b(password|passwd|pwd|secret|apikey|api_key|token)\s*[:=]\s*\S') { "secret: $s"; continue }
            if ($s -match '(?i)credentials?[^\\/]*\.local\.ps1') { "credential file: $s"; continue }
        }
        @($bad) | Should -BeNullOrEmpty
        $plain = @($ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.CommandAst] -and
                    $n.GetCommandName() -eq 'ConvertTo-SecureString' -and
                    @($n.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $_.StringConstantType -ne 'BareWord' }).Count -gt 0
                }, $true))
        $plain | Should -BeNullOrEmpty
    }

    It 'takes the lab computer, the logon account and the credential only from mandatory parameters without a default' {
        $params = @{}
        foreach ($p in $script:InvokeAst.ParamBlock.Parameters) { $params[$p.Name.VariablePath.UserPath] = $p }
        foreach ($n in 'CredentialScript', 'Target', 'LogonUser') {
            $params.ContainsKey($n) | Should -BeTrue -Because $n
            $params[$n].DefaultValue | Should -BeNullOrEmpty -Because $n
            ($params[$n].Attributes | Where-Object { $_.Extent.Text -match 'Mandatory' }) | Should -Not -BeNullOrEmpty -Because $n
        }
    }

    It 'connects and schedules the task with the values of the caller' {
        $calls = @($script:InvokeAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in 'New-PSSession', 'New-ScheduledTaskPrincipal' }, $true))
        $calls.Count | Should -Be 2
        foreach ($c in $calls) {
            $text = $c.Extent.Text
            if ($c.GetCommandName() -eq 'New-PSSession') {
                $text | Should -Match '-ComputerName \$Target\b'
                $text | Should -Match '-Credential \$LabCredential\b'
            }
            else { $text | Should -Match '-UserId \$user\b' }
        }
        $script:InvokeText | Should -Match '-ArgumentList \$root, \$LogonUser, \$captureJson, \$taskName'
    }

    It 'takes the capture lock with New-Item and an IOException catch, and treats a lock older than 60 minutes as stale' {
        $newItem = @($script:InvokeAst.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-Item' -and
                    $n.Extent.Text -match '-ItemType File' -and $n.Extent.Text -match '-ErrorAction Stop'
                }, $true))
        $newItem.Count | Should -Be 1
        $catch = @($script:InvokeAst.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.CatchClauseAst] -and
                    @($n.CatchTypes | Where-Object { $_.TypeName.FullName -eq 'System.IO.IOException' }).Count -gt 0
                }, $true))
        $catch.Count | Should -Be 1
        $script:InvokeText | Should -Match "\`$lockPath = 'C:\\guide\\capture\.lock'"
        $script:InvokeText | Should -Match '-ArgumentList \$lockPath, \$lockToken, 60, \$LockWaitMinutes'
        $script:InvokeText | Should -Match 'TotalMinutes -gt \$staleMinutes'
    }

    It 'works in its own folder and its own task, removes only its own files and the lock, and never removes C:\guide' {
        $script:InvokeText | Should -Match '\$root = "C:\\guide\\\$app"'
        $script:InvokeText | Should -Match '\$taskName = "GuideShots-\$app"'
        $script:InvokeText | Should -Not -Match 'TaskName GuideShots\b'
        $removals = @($script:InvokeAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Remove-Item' }, $true))
        foreach ($c in $removals) { $c.Extent.Text | Should -Not -Match "C:\\guide\b(?!\\)" -Because $c.Extent.Text }
    }

    It 'stops a running capture in the finally block before it removes the task, the folder and the lock' {
        $iFinally = $script:InvokeText.LastIndexOf('finally {')
        $iFinally | Should -BeGreaterThan 0
        $tail = $script:InvokeText.Substring($iFinally)
        $iStop = $tail.IndexOf('Stop-ScheduledTask')
        $iKill = $tail.IndexOf('Stop-Process')
        $iUnregister = $tail.IndexOf('Unregister-ScheduledTask')
        $iFolder = $tail.IndexOf('Remove-Item $r -Recurse')
        $iLock = $tail.IndexOf('Remove-Item -LiteralPath $path -Force')
        $iStop | Should -BeGreaterThan -1
        $iKill | Should -BeGreaterThan $iStop
        $iUnregister | Should -BeGreaterThan $iKill
        $iFolder | Should -BeGreaterThan $iUnregister
        $iLock | Should -BeGreaterThan $iFolder
    }

    It 'does not spin on a stale lock, re-reads the age before the delete and touches the lock while it runs' {
        $script:InvokeText | Should -Match '\$again = Get-Item -LiteralPath \$path'
        $script:InvokeText | Should -Match 'if \(-not \(Test-Path -LiteralPath \$path\)\) \{ continue \}'
        $script:InvokeText | Should -Not -Match '(?s)Remove-Item -LiteralPath \$path -Force -ErrorAction SilentlyContinue\s*\r?\n\s*continue'
        $script:InvokeText | Should -Match '\.LastWriteTime = Get-Date'
    }

    It 'stops before it replaces an image when a step failed' {
        $iThrow = $script:InvokeText.IndexOf('if ($failed.Count) { throw')
        $iCopy = $script:InvokeText.IndexOf('$staging = ')
        $iThrow | Should -BeGreaterThan 0
        $iCopy | Should -BeGreaterThan $iThrow
        [System.IO.File]::ReadAllText((Join-Path $script:CaptureDir 'main.ps1')) | Should -Match "'failed: '"
    }

    It 'produces in its steps every image of the guide' {
        $steps = Join-Path $script:CaptureDir 'steps-guide.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($steps, [ref]$null, [ref]$null)
        $strings = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { [string]$_.Value })
        $images = @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'docs\images') -Filter '*.png' | ForEach-Object { $_.BaseName })
        $images.Count | Should -BeGreaterThan 10
        @($images | Where-Object { $strings -notcontains $_ }) | Should -BeNullOrEmpty
    }

    It 'documents the one command that retakes the captures' {
        [System.IO.File]::ReadAllText((Join-Path $script:Root 'docs\reference\capture-images.md')) | Should -Match 'tools\\guide-capture\\Invoke-GuideCapture\.ps1'
    }
}
