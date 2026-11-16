#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.1.0' }
# Headless test (XAML only, no window is opened) for the compact 1080p density of the main window (D-20).
# The shared style values are asserted in one place. Density.Window.Tests.ps1 measures them on screen.

BeforeAll {
    $script:Xaml = [xml](Get-Content -LiteralPath (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'MainWindow.xaml') -Raw)
    $script:Ns = New-Object System.Xml.XmlNamespaceManager($script:Xaml.NameTable)
    $script:Ns.AddNamespace('w', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
    $script:Ns.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
    function Get-StyleValue {
        param([string]$Key, [string]$Property)
        $style = $script:Xaml.SelectSingleNode("//w:Style[@x:Key='$Key']", $script:Ns)
        $style | Should -Not -BeNullOrEmpty -Because $Key
        $setter = $style.SelectSingleNode("w:Setter[@Property='$Property']", $script:Ns)
        if ($setter) { $setter.GetAttribute('Value') } else { $null }
    }
}

Describe 'Compact density at 1080p' {
    It 'opens at the design size of a maximized 1080p work area and keeps the 1024x640 minimum' {
        $w = $script:Xaml.DocumentElement
        [int]$w.GetAttribute('Width') | Should -Be 1920
        [int]$w.GetAttribute('Height') | Should -Be 1032
        [int]$w.GetAttribute('MinWidth') | Should -BeLessOrEqual 1024
        [int]$w.GetAttribute('MinHeight') | Should -BeLessOrEqual 640
    }

    It 'sizes the sidebar view buttons between 34 and 36 px' {
        [double](Get-StyleValue 'ViewButtonStyle' 'Height') | Should -BeIn 34, 35, 36
    }

    It 'sizes the inline buttons between 26 and 28 px' {
        [double](Get-StyleValue 'SquareInlineButtonStyle' 'Height') | Should -BeGreaterOrEqual 26
        [double](Get-StyleValue 'SquareInlineButtonStyle' 'Height') | Should -BeLessOrEqual 28
    }

    It 'sizes every single-line text box with a height between 26 and 28 px' {
        $boxes = @($script:Xaml.SelectNodes('//w:TextBox[@Height]', $script:Ns))
        $boxes.Count | Should -BeGreaterThan 3
        foreach ($tb in $boxes) { [double]$tb.GetAttribute('Height') | Should -BeIn 26, 27, 28 -Because $tb.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml') }
    }

    It 'gives every grid rows of 24 to 26 px and a 26 px column header from the one shared style' {
        [double](Get-StyleValue 'ViewDataGrid' 'RowHeight') | Should -BeGreaterOrEqual 24
        [double](Get-StyleValue 'ViewDataGrid' 'RowHeight') | Should -BeLessOrEqual 26
        [double](Get-StyleValue 'ViewDataGrid' 'ColumnHeaderHeight') | Should -Be 26
        foreach ($g in @($script:Xaml.SelectNodes('//w:DataGrid', $script:Ns))) {
            $g.GetAttribute('RowHeight') | Should -BeNullOrEmpty -Because 'the row height has one place: ViewDataGrid'
            $g.GetAttribute('Style') | Should -Match 'ViewDataGrid' -Because $g.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml')
        }
    }

    It 'gives no pane that holds a grid, a list or a text box a fixed Height or Width of its own (the view takes the free space)' {
        $bad = @()
        foreach ($node in @($script:Xaml.SelectNodes('//w:DataGrid[@Height or @Width] | //w:ListBox[@Height or @Width] | //w:TreeView[@Height or @Width]', $script:Ns))) { $bad += $node.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml') }
        $bad | Should -BeNullOrEmpty -Because ('fixed size on: ' + ($bad -join ', '))
    }
}