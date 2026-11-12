# Settings

This page lists what Installer Analysis saves and where.

## What it does

The tool saves its settings in `InstallerAnalysis.prefs.json` in the folder of the script. The Options dialog writes the file when you select **OK**. The window state is in `InstallerAnalysis.windowstate.json`.

## When to use it

Use it to copy the settings to another computer or to reset them.

## Requirements

None.

## Settings

| Key | Option | Default |
|---|---|---|
| `SevenZipPath` | **7-Zip Executable** | Empty. The tool looks in Program Files. |
| `ReportsFolder` | **Reports Folder** | Empty. The tool uses `Reports` beside the script. |
| `LastBrowseDir` | The last folder of the file dialog. | Empty. |
| `DarkMode` | **Dark Theme** switch | `true`. |

## Steps

### Reset the settings

1. Close the tool.
2. Delete `InstallerAnalysis.prefs.json` and `InstallerAnalysis.windowstate.json`.
3. Start the tool.

## Limits

- The files are in the folder of the script. Extract the tool to a folder that you can write to.

## Troubleshooting

| Message or symptom | Cause | Fix |
|---|---|---|
| The settings do not stick. | The folder is not writable. | Move the tool to a writable folder. |

## Links

- [Options dialog](../core/options.md)
- [Files and logs](files-and-logs.md)
