# Error messages

This page lists the messages of Installer Analysis with cause and fix. The messages show in the log pane and in the status bar.

## What it does

It maps a message to its cause and to a fix.

## When to use it

Use it when an analysis, an export or an extraction does not work.

## Requirements

None.

## Messages

| Message | Where | Cause | Fix |
|---|---|---|---|
| `7-Zip not found. Configure the path in Options > 7-Zip.` | Log | The payload views need `7z.exe` and the tool cannot find it. | Install 7-Zip or set the path in Options. |
| `Copy Summary: no analysis result yet.` and the same for Copy JSON, Export CSV, Export HTML | Log | No file is analyzed. | Open a file first. |
| `Export CSV failed: <reason>` and `Export HTML failed: <reason>` | Log | The tool cannot write the file. | Read the reason. Choose a writable folder. |
| `Analyze Selected: no row selected.` | Log | No inner installer is selected. | Select a row. |
| `Analyze Selected: entry not analyzable (<reason>)` | Log | The entry is not an installer. | Select an installer entry. |
| `Analyze Selected: extraction failed for <name>` | Log | 7-Zip could not extract the entry. | Read the log. Extract the entry by hand. |
| `Max drill-down depth (5) reached. Extract manually to continue deeper.` | Log | The nesting is deeper than 5. | Extract the entry and open it. |
| `Extract Payload: no payload listed for the current file.` | Log | The file has no payload list. | None. |
| `Extract Payload: canceled (target not empty).` | Log | The target folder has files. | Select an empty folder. |
| `Extract <name>: 7z.exe not found.` | Log | 7-Zip is missing. | Install 7-Zip. |
| `Hash: no rows selected.` and `Extract to temp: no rows selected.` | Log | No row is selected. | Select rows. |
| `Open enclosing folder: path is empty or does not exist.` | Log | The path box is empty or the file is gone. | Open a file. |

## Steps

1. Find the message in the table.
2. Do the fix.
3. Run the action again.

## Limits

- The messages are in English.

## Troubleshooting

See [Troubleshooting](../troubleshooting.md).

## Links

- [Troubleshooting](../troubleshooting.md)
- [Options dialog](../core/options.md)
