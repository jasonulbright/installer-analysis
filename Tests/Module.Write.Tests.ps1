#Requires -Modules Pester
# The functions that write: payload extraction with 7-Zip, and the CSV and HTML exports.
# 7z.exe is replaced by a small .cmd file (New-FakeSevenZip in TestHelpers.ps1) that
# writes files, a log of its command line, and an exit code that the test chooses.

BeforeAll {
    . "$PSScriptRoot\TestHelpers.ps1"
    Import-AppModule
    $script:Work = Join-Path ([System.IO.Path]::GetTempPath()) ('ia-write-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Work -Force | Out-Null
    $script:Fake = New-FakeSevenZip -Directory (Join-Path $script:Work 'tool')
    $script:Archive = Join-Path $script:Work 'setup file.exe'
    [System.IO.File]::WriteAllText($script:Archive, 'not a real archive')
}

AfterAll {
    Set-FakeSevenZipBehavior
    Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Expand-InstallerPayload' {
    BeforeEach {
        Set-FakeSevenZipBehavior
        $script:Log = Join-Path $script:Work ('log-' + [guid]::NewGuid().ToString('N') + '.txt')
        $script:Out = Join-Path $script:Work ('out ' + [guid]::NewGuid().ToString('N'))
    }
    AfterEach { Set-FakeSevenZipBehavior }

    It 'extracts into a new folder and returns that folder when 7-Zip exits with 0' {
        Set-FakeSevenZipBehavior @{ FAKE7Z_EXIT = 0; FAKE7Z_LOG = $script:Log; FAKE7Z_WRITE = 'a.txt' }
        $result = Expand-InstallerPayload -Path $script:Archive -OutputPath $script:Out -SevenZipPath $script:Fake
        $result | Should -Be $script:Out
        Test-Path -LiteralPath (Join-Path $script:Out 'a.txt') | Should -BeTrue
    }

    It 'passes the archive path and the output folder as one quoted argument each, also with spaces' {
        Set-FakeSevenZipBehavior @{ FAKE7Z_LOG = $script:Log }
        $null = Expand-InstallerPayload -Path $script:Archive -OutputPath $script:Out -SevenZipPath $script:Fake
        $line = Get-Content -LiteralPath $script:Log -Raw
        $line | Should -BeLike ('x "{0}" -o"{1}" -y*' -f $script:Archive, $script:Out)
    }

    It 'returns nothing when 7-Zip exits with a fatal error (exit code <Code>)' -ForEach @(
        @{ Code = 2 }, @{ Code = 7 }, @{ Code = 8 }, @{ Code = 255 }
    ) {
        Set-FakeSevenZipBehavior @{ FAKE7Z_EXIT = $Code; FAKE7Z_LOG = $script:Log }
        Expand-InstallerPayload -Path $script:Archive -OutputPath $script:Out -SevenZipPath $script:Fake | Should -BeNullOrEmpty
    }

    It 'returns the folder when 7-Zip exits with the warning code 1' {
        Set-FakeSevenZipBehavior @{ FAKE7Z_EXIT = 1; FAKE7Z_WRITE = 'a.txt' }
        Expand-InstallerPayload -Path $script:Archive -OutputPath $script:Out -SevenZipPath $script:Fake | Should -Be $script:Out
    }

    It 'logs a warning that names the exit code' {
        Mock -ModuleName InstallerAnalysisCommon Write-Log {}
        Set-FakeSevenZipBehavior @{ FAKE7Z_EXIT = 2 }
        $null = Expand-InstallerPayload -Path $script:Archive -OutputPath $script:Out -SevenZipPath $script:Fake
        Should -Invoke Write-Log -ModuleName InstallerAnalysisCommon -Times 1 -Exactly -ParameterFilter { $Level -eq 'WARN' -and $Message -like '*code 2*' }
    }

    It 'returns nothing and logs an error when 7-Zip cannot be found' {
        Mock -ModuleName InstallerAnalysisCommon Find-7ZipPath { $null }
        Mock -ModuleName InstallerAnalysisCommon Write-Log {}
        Expand-InstallerPayload -Path $script:Archive -OutputPath $script:Out | Should -BeNullOrEmpty
        Should -Invoke Write-Log -ModuleName InstallerAnalysisCommon -Times 1 -Exactly -ParameterFilter { $Level -eq 'ERROR' }
        Test-Path -LiteralPath $script:Out | Should -BeFalse
    }

    It 'looks up 7-Zip itself when no path is given' {
        Mock -ModuleName InstallerAnalysisCommon Find-7ZipPath { $global:FakePath }
        $global:FakePath = $script:Fake
        try {
            Set-FakeSevenZipBehavior @{ FAKE7Z_WRITE = 'a.txt' }
            Expand-InstallerPayload -Path $script:Archive -OutputPath $script:Out | Should -Be $script:Out
            Should -Invoke Find-7ZipPath -ModuleName InstallerAnalysisCommon -Times 1 -Exactly
        }
        finally { Remove-Variable -Name FakePath -Scope Global -ErrorAction SilentlyContinue }
    }

    It 'builds a default folder under the temp folder from the installer name' {
        Set-FakeSevenZipBehavior @{ FAKE7Z_WRITE = 'a.txt' }
        $result = Expand-InstallerPayload -Path $script:Archive -SevenZipPath $script:Fake
        try {
            $result | Should -BeLike (Join-Path $env:TEMP 'InstallerAnalysis\setup file_*')
            Test-Path -LiteralPath $result | Should -BeTrue
        }
        finally { if ($result) { Remove-Item -LiteralPath (Split-Path -Parent $result) -Recurse -Force -ErrorAction SilentlyContinue } }
    }

    It 'reuses an output folder that exists and keeps its files' {
        New-Item -ItemType Directory -Path $script:Out -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:Out 'keep.txt') -Value 'keep'
        Set-FakeSevenZipBehavior @{ FAKE7Z_WRITE = 'a.txt' }
        $null = Expand-InstallerPayload -Path $script:Archive -OutputPath $script:Out -SevenZipPath $script:Fake
        Test-Path -LiteralPath (Join-Path $script:Out 'keep.txt') | Should -BeTrue
    }
}

Describe 'Expand-PayloadEntry' {
    BeforeEach {
        Set-FakeSevenZipBehavior
        $script:Out = Join-Path $script:Work ('entry ' + [guid]::NewGuid().ToString('N'))
    }
    AfterEach { Set-FakeSevenZipBehavior }

    It 'returns nothing when 7-Zip is missing' {
        Expand-PayloadEntry -SevenZipPath (Join-Path $script:Work 'missing.exe') -ArchivePath $script:Archive -EntryName 'a.msi' -OutputDir $script:Out | Should -BeNullOrEmpty
        Test-Path -LiteralPath $script:Out | Should -BeFalse
    }

    It 'returns nothing when the archive is missing' {
        Expand-PayloadEntry -SevenZipPath $script:Fake -ArchivePath (Join-Path $script:Work 'missing.exe') -EntryName 'a.msi' -OutputDir $script:Out | Should -BeNullOrEmpty
        Test-Path -LiteralPath $script:Out | Should -BeFalse
    }

    It 'creates the output folder and returns the path of the extracted file' {
        Set-FakeSevenZipBehavior @{ FAKE7Z_WRITE = 'inner.msi' }
        $r = Expand-PayloadEntry -SevenZipPath $script:Fake -ArchivePath $script:Archive -EntryName 'inner.msi' -OutputDir $script:Out
        $r | Should -Be (Join-Path $script:Out 'inner.msi')
    }

    It 'quotes the include filter so that a name with spaces stays one argument' {
        $log = Join-Path $script:Work 'entry-log.txt'
        Set-FakeSevenZipBehavior @{ FAKE7Z_LOG = $log; FAKE7Z_WRITE = 'my inner.msi' }
        $null = Expand-PayloadEntry -SevenZipPath $script:Fake -ArchivePath $script:Archive -EntryName 'dir\my inner.msi' -OutputDir $script:Out
        (Get-Content -LiteralPath $log -Raw) | Should -BeLike '*"-i!dir\my inner.msi"*'
    }

    It 'strips the angle brackets of a synthetic name and the folder part when it looks for the file' {
        Set-FakeSevenZipBehavior @{ FAKE7Z_WRITE = 'inner.msi' }
        Expand-PayloadEntry -SevenZipPath $script:Fake -ArchivePath $script:Archive -EntryName '<sub\inner.msi>' -OutputDir $script:Out | Should -Be (Join-Path $script:Out 'inner.msi')
    }

    It 'returns nothing for exit code <Code>' -ForEach @(@{ Code = 1 }, @{ Code = 2 }, @{ Code = 255 }) {
        Set-FakeSevenZipBehavior @{ FAKE7Z_EXIT = $Code; FAKE7Z_WRITE = 'inner.msi' }
        Expand-PayloadEntry -SevenZipPath $script:Fake -ArchivePath $script:Archive -EntryName 'inner.msi' -OutputDir $script:Out | Should -BeNullOrEmpty
    }

    It 'returns the file that 7-Zip wrote when it changed the name of the entry' {
        Set-FakeSevenZipBehavior @{ FAKE7Z_WRITE = 'renamed.msi' }
        Expand-PayloadEntry -SevenZipPath $script:Fake -ArchivePath $script:Archive -EntryName 'inner.msi' -OutputDir $script:Out | Should -Be (Join-Path $script:Out 'renamed.msi')
    }

    It 'does not return a file from an earlier extraction when 7-Zip found nothing to extract' {
        # 7-Zip exits with 0 and extracts nothing when the include filter matches no entry.
        New-Item -ItemType Directory -Path $script:Out -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:Out 'stale-from-before.msi') -Value 'old'
        Set-FakeSevenZipBehavior @{ FAKE7Z_EXIT = 0 }
        Expand-PayloadEntry -SevenZipPath $script:Fake -ArchivePath $script:Archive -EntryName 'missing.msi' -OutputDir $script:Out | Should -BeNullOrEmpty
    }

    It 'returns the new file when old files are in the folder too' {
        New-Item -ItemType Directory -Path $script:Out -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:Out 'stale-from-before.msi') -Value 'old'
        (Get-Item -LiteralPath (Join-Path $script:Out 'stale-from-before.msi')).LastWriteTime = (Get-Date).AddDays(1)
        Set-FakeSevenZipBehavior @{ FAKE7Z_WRITE = 'renamed.msi' }
        Expand-PayloadEntry -SevenZipPath $script:Fake -ArchivePath $script:Archive -EntryName 'inner.msi' -OutputDir $script:Out | Should -Be (Join-Path $script:Out 'renamed.msi')
    }
}

Describe 'Expand-InstallerEntries' {
    BeforeEach {
        Set-FakeSevenZipBehavior
        $script:Out = Join-Path $script:Work ('entries ' + [guid]::NewGuid().ToString('N'))
        $script:ListCopy = Join-Path $script:Work ('list-' + [guid]::NewGuid().ToString('N') + '.txt')
    }
    AfterEach { Set-FakeSevenZipBehavior }

    It 'throws when 7-Zip cannot be found' {
        { Expand-InstallerEntries -Path $script:Archive -EntryName 'a.txt' -OutputPath $script:Out -SevenZipPath (Join-Path $script:Work 'missing.exe') } | Should -Throw '*7-Zip*'
    }

    It 'throws when the installer does not exist' {
        { Expand-InstallerEntries -Path (Join-Path $script:Work 'missing.exe') -EntryName 'a.txt' -OutputPath $script:Out -SevenZipPath $script:Fake } | Should -Throw '*Installer not found*'
        Test-Path -LiteralPath $script:Out | Should -BeFalse
    }

    It 'returns the 7-Zip exit code <Code>' -ForEach @(@{ Code = 0 }, @{ Code = 1 }, @{ Code = 2 }) {
        Set-FakeSevenZipBehavior @{ FAKE7Z_EXIT = $Code }
        Expand-InstallerEntries -Path $script:Archive -EntryName 'a.txt' -OutputPath $script:Out -SevenZipPath $script:Fake | Should -Be $Code
    }

    It 'creates the output folder' {
        Expand-InstallerEntries -Path $script:Archive -EntryName 'a.txt' -OutputPath $script:Out -SevenZipPath $script:Fake | Out-Null
        Test-Path -LiteralPath $script:Out -PathType Container | Should -BeTrue
    }

    It 'writes the names to a UTF-8 list file without a byte order mark, one per line, without duplicates and without angle brackets' {
        Set-FakeSevenZipBehavior @{ FAKE7Z_LISTCOPY = $script:ListCopy }
        $null = Expand-InstallerEntries -Path $script:Archive -EntryName @('dir\a b.txt', '<inner.msi>', 'dir\a b.txt', "caf$([char]0xE9).txt") -OutputPath $script:Out -SevenZipPath $script:Fake
        $bytes = [System.IO.File]::ReadAllBytes($script:ListCopy)
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB) | Should -BeFalse
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        @($text -split "\r?\n" | Where-Object { $_ }) | Should -Be @('dir\a b.txt', 'inner.msi', "caf$([char]0xE9).txt")
    }

    It 'removes its list file after the run, also when 7-Zip fails' {
        $before = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Filter 'ia-entries-*.txt' -ErrorAction SilentlyContinue).Count
        Set-FakeSevenZipBehavior @{ FAKE7Z_EXIT = 7 }
        Expand-InstallerEntries -Path $script:Archive -EntryName 'a.txt' -OutputPath $script:Out -SevenZipPath $script:Fake | Should -Be 7
        @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Filter 'ia-entries-*.txt' -ErrorAction SilentlyContinue).Count | Should -Be $before
    }

    It 'rejects an empty list of entry names' {
        { Expand-InstallerEntries -Path $script:Archive -EntryName @() -OutputPath $script:Out -SevenZipPath $script:Fake } | Should -Throw
    }
}

Describe 'Get-PayloadContents' {
    BeforeEach { Set-FakeSevenZipBehavior }
    AfterEach { Set-FakeSevenZipBehavior }

    It 'returns nothing and warns when 7-Zip cannot be found' {
        Mock -ModuleName InstallerAnalysisCommon Find-7ZipPath { $null }
        Get-PayloadContents -Path $script:Archive | Should -BeNullOrEmpty
    }

    It 'parses the listing table into names, sizes and folder flags' {
        $listing = Join-Path $script:Work 'listing.txt'
        Set-Content -LiteralPath $listing -Value @(
            '7-Zip 24.08 (x64) : Copyright (c) 1999-2024 Igor Pavlov'
            ''
            '   Date      Time    Attr         Size   Compressed  Name'
            '------------------- ----- ------------ ------------  ------------------------'
            '2026-01-02 03:04:05 ....A      2097152      1048576  bin\big file.dll'
            '2026-01-02 03:04:05 ....A         2048         1024  readme.txt'
            '2026-01-02 03:04:05 D....            0            0  bin'
            '                    .....          100               [0]~'
            '------------------- ----- ------------ ------------  ------------------------'
            '2026-01-02 03:04:05              2099300      1049600  4 files'
        )
        Set-FakeSevenZipBehavior @{ FAKE7Z_STDOUT = $listing }
        $rows = @(Get-PayloadContents -Path $script:Archive -SevenZipPath $script:Fake)
        $rows.Count | Should -Be 4
        $rows[0].Name | Should -Be 'bin\big file.dll'
        $rows[0].Size | Should -Be 2097152
        $rows[0].SizeFormatted | Should -Be '2.0 MB'
        $rows[1].SizeFormatted | Should -Be '2 KB'
        $rows[2].IsDirectory | Should -BeTrue
        $rows[1].IsDirectory | Should -BeFalse
        $rows[3].Name | Should -Be '[0]~'
        $rows[3].SizeFormatted | Should -Be '100 B'
    }

    It 'returns an empty list for output without a file table' {
        $listing = Join-Path $script:Work 'listing-none.txt'
        Set-Content -LiteralPath $listing -Value @('ERROR: Cannot open file as archive')
        Set-FakeSevenZipBehavior @{ FAKE7Z_STDOUT = $listing; FAKE7Z_EXIT = 2 }
        @(Get-PayloadContents -Path $script:Archive -SevenZipPath $script:Fake).Count | Should -Be 0
    }

    It 'removes its two temp files' {
        $before = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Filter 'tmp*.tmp' -ErrorAction SilentlyContinue).Count
        $null = Get-PayloadContents -Path $script:Archive -SevenZipPath $script:Fake
        @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Filter 'tmp*.tmp' -ErrorAction SilentlyContinue).Count | Should -BeLessOrEqual $before
    }
}

Describe 'Export-AnalysisReport' {
    BeforeAll {
        $script:Table = New-Object System.Data.DataTable
        [void]$script:Table.Columns.Add('Section'); [void]$script:Table.Columns.Add('Property'); [void]$script:Table.Columns.Add('Value')
        [void]$script:Table.Rows.Add('Source', 'FileName', 'setup.exe')
        [void]$script:Table.Rows.Add('Source', 'Note', 'comma, "quote" and a new' + "`r`n" + 'line')
        [void]$script:Table.Rows.Add('Source', 'Unicode', "caf$([char]0xE9) $([char]0x4E2D)$([char]0x6587)")
    }

    It 'writes the rows so that Import-Csv reads the same values back' {
        $out = Join-Path $script:Work 'report.csv'
        Export-AnalysisReport -DataTable $script:Table -OutputPath $out
        $rows = @(Import-Csv -LiteralPath $out -Encoding UTF8)
        $rows.Count | Should -Be 3
        $rows[0].Property | Should -Be 'FileName'
        $rows[0].Value | Should -Be 'setup.exe'
        $rows[1].Value | Should -Be ('comma, "quote" and a new' + "`r`n" + 'line')
        $rows[2].Value | Should -Be "caf$([char]0xE9) $([char]0x4E2D)$([char]0x6587)"
    }

    It 'creates a missing parent folder' {
        $out = Join-Path $script:Work 'new folder\deeper\report.csv'
        Export-AnalysisReport -DataTable $script:Table -OutputPath $out
        Test-Path -LiteralPath $out | Should -BeTrue
    }

    It 'overwrites an existing file' {
        $out = Join-Path $script:Work 'overwrite.csv'
        Set-Content -LiteralPath $out -Value ('old content that is much longer than the new content ' * 30)
        Export-AnalysisReport -DataTable $script:Table -OutputPath $out
        (Get-Content -LiteralPath $out -Raw) | Should -Not -BeLike '*old content*'
    }

    It 'writes no data row for an empty table' {
        $empty = New-Object System.Data.DataTable
        [void]$empty.Columns.Add('Section')
        $out = Join-Path $script:Work 'empty.csv'
        Export-AnalysisReport -DataTable $empty -OutputPath $out
        if (Test-Path -LiteralPath $out) { @(Import-Csv -LiteralPath $out).Count | Should -Be 0 }
    }

    It 'throws when the file cannot be written' {
        $blocker = Join-Path $script:Work 'blocker.txt'
        Set-Content -LiteralPath $blocker -Value 'x'
        { Export-AnalysisReport -DataTable $script:Table -OutputPath (Join-Path $blocker 'report.csv') } | Should -Throw
    }

    It 'does not let a cell that starts with "<Lead>" run as a formula in a spreadsheet' -ForEach @(
        @{ Lead = '=' ; Cell = '=HYPERLINK("http://example.test","x")' }
        @{ Lead = '+' ; Cell = '+1+1' }
        @{ Lead = '-' ; Cell = '-2+3' }
        @{ Lead = '@' ; Cell = '@SUM(A1:A2)' }
    ) {
        $hostile = New-Object System.Data.DataTable
        [void]$hostile.Columns.Add('Section'); [void]$hostile.Columns.Add('Property'); [void]$hostile.Columns.Add('Value')
        [void]$hostile.Rows.Add('Application', 'DisplayName', $Cell)
        $out = Join-Path $script:Work ('hostile-' + [guid]::NewGuid().ToString('N') + '.csv')
        Export-AnalysisReport -DataTable $hostile -OutputPath $out
        $value = (Import-Csv -LiteralPath $out -Encoding UTF8)[0].Value
        $value.StartsWith($Lead) | Should -BeFalse
        $value | Should -BeLike ("*" + $Cell)
    }

    It 'leaves ordinary text and numbers as they are' {
        $plain = New-Object System.Data.DataTable
        [void]$plain.Columns.Add('Section'); [void]$plain.Columns.Add('Property'); [void]$plain.Columns.Add('Value')
        [void]$plain.Rows.Add('Source', 'FileSize', '1048576')
        [void]$plain.Rows.Add('Source', 'ProductName', 'Acme Tool 1.2')
        $out = Join-Path $script:Work 'plain.csv'
        Export-AnalysisReport -DataTable $plain -OutputPath $out
        $rows = @(Import-Csv -LiteralPath $out -Encoding UTF8)
        $rows[0].Value | Should -Be '1048576'
        $rows[1].Value | Should -Be 'Acme Tool 1.2'
    }
}

Describe 'Export-AnalysisHtml' {
    BeforeAll {
        $script:HtmlTable = New-Object System.Data.DataTable
        [void]$script:HtmlTable.Columns.Add('Section'); [void]$script:HtmlTable.Columns.Add('Value')
        [void]$script:HtmlTable.Rows.Add('Source', '<script>alert(1)</script> & "quoted"')
        [void]$script:HtmlTable.Rows.Add('Application', 'plain')
    }

    It 'encodes the title, the headers and the cells' {
        $out = Join-Path $script:Work 'report.html'
        Export-AnalysisHtml -DataTable $script:HtmlTable -OutputPath $out -ReportTitle '<b>Title</b> & more'
        $html = Get-Content -LiteralPath $out -Raw
        $html | Should -Not -Match '<script>alert'
        $html | Should -Not -Match '<b>Title</b>'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt; &amp; (&quot;|")quoted'
        $html | Should -Match '<title>\s*&lt;b&gt;Title&lt;/b&gt; &amp; more\s*</title>'
        $html | Should -Match 'Rows: 2'
    }

    It 'marks only the first column as the property column' {
        $out = Join-Path $script:Work 'cls.html'
        Export-AnalysisHtml -DataTable $script:HtmlTable -OutputPath $out
        ([regex]::Matches((Get-Content -LiteralPath $out -Raw), '<td class="prop">')).Count | Should -Be 2
    }

    It 'uses the default title' {
        $out = Join-Path $script:Work 'default-title.html'
        Export-AnalysisHtml -DataTable $script:HtmlTable -OutputPath $out
        (Get-Content -LiteralPath $out -Raw) | Should -Match '<h1>Installer Analysis Report</h1>'
    }

    It 'creates a missing parent folder' {
        $out = Join-Path $script:Work 'html folder\sub\report.html'
        Export-AnalysisHtml -DataTable $script:HtmlTable -OutputPath $out
        Test-Path -LiteralPath $out | Should -BeTrue
    }

    It 'writes a table without rows' {
        $empty = New-Object System.Data.DataTable
        [void]$empty.Columns.Add('Section')
        $out = Join-Path $script:Work 'empty.html'
        Export-AnalysisHtml -DataTable $empty -OutputPath $out
        (Get-Content -LiteralPath $out -Raw) | Should -Match 'Rows: 0'
    }

    It 'throws when the file cannot be written' {
        $blocker = Join-Path $script:Work 'blocker2.txt'
        Set-Content -LiteralPath $blocker -Value 'x'
        { Export-AnalysisHtml -DataTable $script:HtmlTable -OutputPath (Join-Path $blocker 'report.html') } | Should -Throw
    }
}
