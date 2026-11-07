# Files and logs

This page lists every folder and file that Installer Analysis writes.

## What it does

The tool writes in the folder of the script, in a temporary folder for extractions, and in the folder that you choose for an export or an extraction. It writes nothing in the registry. It never changes the installer that you open.

## When to use it

Use it to find a log, a report or an extraction, or to clean up.

## Requirements

None.

## Files

| Path | Content | Written when |
|---|---|---|
| `InstallerAnalysis.prefs.json` | The settings. | You select **OK** in Options, or change the theme. |
| `InstallerAnalysis.windowstate.json` | The size and the place of the window. | You close the window. |
| `Logs\InstallerAnalysis-<yyyyMMdd-HHmmss>.log` | The log of one session. | During the session. |
| `Logs\InstallerAnalysis-startup-<yyyyMMdd-HHmmss>.txt` | The PowerShell transcript of the start. | At the start. |
| The reports folder (default `Reports`) | CSV and HTML exports. | **Export CSV** or **Export HTML**. |
| `%LOCALAPPDATA%\InstallerAnalysis\Temp` | The entries that you extract to analyze an inner installer. | **Analyze Selected**, **Extract to temp folder**. The tool tries to remove it when you close the window. Removal is best effort. Delete the folder by hand if files stay. |
| The folder that you choose | An extraction. | **Extract All** and the other extract actions. |

## Steps

### Clean up

1. Close the tool.
2. Delete the logs and the reports that you do not need.

## Limits

- The tool never deletes a log or a report.

## Troubleshooting

| Message or symptom | Cause | Fix |
|---|---|---|
| A start leaves no log. | The folder is not writable. | Move the tool to a writable folder. |

## Links

- [Settings](settings.md)
- [Export and copy](../core/export.md)
