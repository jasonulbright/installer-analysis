# Troubleshooting

This page lists the most common problems of Installer Analysis with cause and fix. See [Error messages](reference/error-messages.md) for every message.

## What it does

It gives a short fix for each common problem.

## When to use it

Use it when an analysis, an export or an extraction does not work.

## Requirements

None.

## Problems

| Message or symptom | Cause | Fix |
|---|---|---|
| The type is `Unknown`. | The file is not one of the detected types, or it is an uninstaller. | Open the setup file of the product. See [Installer types](reference/installer-types.md). |
| The Payload view is empty. | The file has no payload, or 7-Zip is missing. | Install 7-Zip or set its path in Options. |
| The Files and Embedded buttons are missing. | The file has no payload that 7-Zip lists. | None. |
| The silent install command says `Unable to determine`. | The type has no known silent switch. | Try `/?` and `--help` on the file. |
| A long key or value is cut in a grid. | The column is narrow. | Use **Copy All** or the exports. |
| An export fails. | The reports folder is not writable. | Set another folder in **Options > Reports**. |

## Steps

1. Read the log pane. It names the cause of most problems.
2. Read the session log in `Logs`.
3. Do the fix of the table.

## Limits

None.

## Links

- [Error messages](reference/error-messages.md)
- [Files and logs](reference/files-and-logs.md)
