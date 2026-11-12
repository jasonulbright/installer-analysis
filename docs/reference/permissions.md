# Permissions

This page lists the rights that Installer Analysis needs.

## What it does

The tool reads the installer file and writes its own files. It needs no administrator rights.

## When to use it

Use it to set up an account, or to find out why a read or a write is refused.

## Requirements

| Action | Right |
|---|---|
| Start the tool | Read and write in the folder of the script. |
| Analyze a file | Read access to the file. |
| Export | Write access to the reports folder. |
| Extract | Write access to the target folder and the temporary folder. |

## Steps

Start the tool as a standard user.

## Limits

- The tool does not connect to a Configuration Manager site and needs no console and no role.

## Troubleshooting

| Message or symptom | Cause | Fix |
|---|---|---|
| `Export CSV failed.` | The reports folder is not writable. | Set another folder in **Options > Reports**. |

## Links

- [Network](network.md)
- [Files and logs](files-and-logs.md)
