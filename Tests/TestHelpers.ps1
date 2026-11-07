# Shared helpers for the Installer Analysis tests. Dot-source from BeforeAll.

$script:AppRoot = Split-Path -Parent $PSScriptRoot

function Import-AppModule {
    Import-Module (Join-Path $script:AppRoot 'Module\InstallerAnalysisCommon.psd1') -Force -DisableNameChecking
}

# Builds a small but real Windows Installer database with the COM API, so the MSI reading
# functions run against a file that Windows Installer itself accepts. All parts are optional:
#   -Property   ordered or plain hashtable of Property table rows
#   -Summary    hashtable with Subject, Author, Comments, Template, Revision
#   -Component  rows of @{ Name; Attributes }
#   -Registry   rows of @{ Id; Root; Key; Name; Value; Component }  (Name and Value may be $null)
#   -RemoveRegistry rows of @{ Id; Root; Key; Name; Component }
# The function releases every COM object before it returns, because an open handle locks the
# file and makes the next read fail with a sharing violation.
function New-TestMsi {
    param(
        [Parameter(Mandatory)][string]$Path,
        [System.Collections.IDictionary]$Property,
        [hashtable]$Summary,
        [object[]]$Component,
        [object[]]$Registry,
        [object[]]$RemoveRegistry
    )
    $release = { param($o) if ($null -ne $o -and [System.Runtime.InteropServices.Marshal]::IsComObject($o)) { [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($o) } }
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.OpenDatabase($Path, 3)
    try {
        $run = {
            param($Sql, $Values)
            $view = $db.OpenView($Sql)
            try {
                if ($Values) {
                    $rec = $installer.CreateRecord($Values.Count)
                    for ($i = 0; $i -lt $Values.Count; $i++) {
                        $v = $Values[$i]
                        if ($null -eq $v) { continue }
                        if ($v -is [int]) { $rec.IntegerData($i + 1) = $v } else { $rec.StringData($i + 1) = [string]$v }
                    }
                    $view.Execute($rec)
                    & $release $rec
                }
                else { $view.Execute() }
                $view.Close()
            }
            finally { & $release $view }
        }
        if ($Property) {
            & $run 'CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL PRIMARY KEY `Property`)' $null
            foreach ($k in $Property.Keys) { & $run 'INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)' @([string]$k, [string]$Property[$k]) }
        }
        if ($Component) {
            & $run 'CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)' $null
            foreach ($c in $Component) { & $run 'INSERT INTO `Component` (`Component`, `Directory_`, `Attributes`) VALUES (?, ?, ?)' @([string]$c.Name, 'TARGETDIR', [int]$c.Attributes) }
        }
        if ($Registry) {
            & $run 'CREATE TABLE `Registry` (`Registry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL LOCALIZABLE, `Name` CHAR(255) LOCALIZABLE, `Value` CHAR(0) LOCALIZABLE, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Registry`)' $null
            foreach ($r in $Registry) { & $run 'INSERT INTO `Registry` (`Registry`, `Root`, `Key`, `Name`, `Value`, `Component_`) VALUES (?, ?, ?, ?, ?, ?)' @([string]$r.Id, [int]$r.Root, [string]$r.Key, $r.Name, $r.Value, [string]$r.Component) }
        }
        if ($RemoveRegistry) {
            & $run 'CREATE TABLE `RemoveRegistry` (`RemoveRegistry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL LOCALIZABLE, `Name` CHAR(255) LOCALIZABLE, `Component_` CHAR(72) NOT NULL PRIMARY KEY `RemoveRegistry`)' $null
            foreach ($r in $RemoveRegistry) { & $run 'INSERT INTO `RemoveRegistry` (`RemoveRegistry`, `Root`, `Key`, `Name`, `Component_`) VALUES (?, ?, ?, ?, ?)' @([string]$r.Id, [int]$r.Root, [string]$r.Key, $r.Name, [string]$r.Component) }
        }
        $si = $db.SummaryInformation(20)
        try {
            if ($Summary) {
                if ($Summary.Subject) { $si.Property(3) = [string]$Summary.Subject }
                if ($Summary.Author) { $si.Property(4) = [string]$Summary.Author }
                if ($Summary.Comments) { $si.Property(6) = [string]$Summary.Comments }
                if ($Summary.Template) { $si.Property(7) = [string]$Summary.Template }
                if ($Summary.Revision) { $si.Property(9) = [string]$Summary.Revision }
            }
            $si.Persist()
        }
        finally { & $release $si }
        $db.Commit()
    }
    finally {
        & $release $db
        & $release $installer
        $db = $null; $installer = $null
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
}

# A stand-in for 7z.exe: a .cmd file that the code under test starts with Start-Process.
# What it does comes from environment variables that the test sets before the call:
#   FAKE7Z_EXIT    exit code (default 0)
#   FAKE7Z_LOG     file that receives the raw command line
#   FAKE7Z_WRITE   space separated file names to create in the -o folder
#   FAKE7Z_LISTCOPY file that receives a copy of the -i@ list file
#   FAKE7Z_STDOUT  file whose content the fake prints (for "7z l" listings)
function New-FakeSevenZip {
    param([Parameter(Mandatory)][string]$Directory)
    if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }
    $path = Join-Path $Directory 'fake7z.cmd'
    $lines = @(
        '@echo off'
        'if defined FAKE7Z_LOG >>"%FAKE7Z_LOG%" echo %*'
        'setlocal EnableDelayedExpansion'
        'set "outdir="'
        'set "listfile="'
        'for %%a in (%*) do ('
        '  set "a=%%~a"'
        '  if "!a:~0,2!"=="-o" set "outdir=!a:~2!"'
        '  if "!a:~0,3!"=="-i@" set "listfile=!a:~3!"'
        ')'
        'if defined outdir set "outdir=!outdir:"=!"'
        'if defined listfile if defined FAKE7Z_LISTCOPY copy /y "!listfile!" "%FAKE7Z_LISTCOPY%" >nul'
        'if defined FAKE7Z_WRITE if defined outdir ('
        '  if not exist "!outdir!" mkdir "!outdir!"'
        '  for %%f in (%FAKE7Z_WRITE%) do >"!outdir!\%%f" echo extracted'
        ')'
        'if defined FAKE7Z_STDOUT type "%FAKE7Z_STDOUT%"'
        'if not defined FAKE7Z_EXIT set "FAKE7Z_EXIT=0"'
        'exit /b %FAKE7Z_EXIT%'
    )
    [System.IO.File]::WriteAllText($path, ($lines -join "`r`n") + "`r`n", (New-Object System.Text.ASCIIEncoding))
    return $path
}

# Sets or clears the FAKE7Z_* environment variables. Call with no argument to clear them all.
function Set-FakeSevenZipBehavior {
    param([hashtable]$Setting = @{})
    foreach ($n in 'FAKE7Z_EXIT', 'FAKE7Z_LOG', 'FAKE7Z_WRITE', 'FAKE7Z_LISTCOPY', 'FAKE7Z_STDOUT') {
        [Environment]::SetEnvironmentVariable($n, $(if ($Setting.ContainsKey($n)) { [string]$Setting[$n] } else { $null }), 'Process')
    }
}

# The parameter names of one command call: the ones written as -Name, and the keys of a splatted
# hashtable (@params) that the same function or script block builds with a literal or with
# $params['Key'] / $params.Key assignments.
function Get-CommandParameterName {
    param([Parameter(Mandatory)][System.Management.Automation.Language.CommandAst]$Command)
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($e in $Command.CommandElements) {
        if ($e -is [System.Management.Automation.Language.CommandParameterAst]) { $names.Add($e.ParameterName) }
        elseif ($e -is [System.Management.Automation.Language.VariableExpressionAst] -and $e.Splatted) {
            $var = $e.VariablePath.UserPath
            $scope = $Command.Parent
            while ($scope -and $scope -isnot [System.Management.Automation.Language.FunctionDefinitionAst] -and $scope -isnot [System.Management.Automation.Language.ScriptBlockAst]) { $scope = $scope.Parent }
            if (-not $scope) { continue }
            $assigns = $scope.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
            foreach ($a in $assigns) {
                $left = $a.Left
                if ($left -is [System.Management.Automation.Language.VariableExpressionAst] -and $left.VariablePath.UserPath -eq $var -and $a.Right.Expression -is [System.Management.Automation.Language.HashtableAst]) {
                    foreach ($kv in $a.Right.Expression.KeyValuePairs) { if ($kv.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $names.Add($kv.Item1.Value) } }
                }
                elseif ($left -is [System.Management.Automation.Language.IndexExpressionAst] -and $left.Target -is [System.Management.Automation.Language.VariableExpressionAst] -and $left.Target.VariablePath.UserPath -eq $var -and $left.Index -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    $names.Add($left.Index.Value)
                }
                elseif ($left -is [System.Management.Automation.Language.MemberExpressionAst] -and $left.Expression -is [System.Management.Automation.Language.VariableExpressionAst] -and $left.Expression.VariablePath.UserPath -eq $var -and $left.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    $names.Add($left.Member.Value)
                }
            }
        }
    }
    return @($names | Select-Object -Unique)
}
