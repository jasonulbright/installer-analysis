# MSI Properties

The MSI Properties view shows the property table of an MSI.

## What it does

The view lists every property of the MSI with its value, for example `ProductCode`, `UpgradeCode`, `ProductVersion` and `Manufacturer`. The grid fills only when the analyzed file is an MSI. An MSP or an EXE wrapper does not fill it. To read the properties of an MSI inside a wrapper, extract the MSI with 7-Zip and analyze it on its own.

## When to use it

Use it to find a property that you need for a transform, a detection method or a command line.

## Requirements

An analyzed MSI.

## Steps

1. Open an MSI. See [Getting started](../getting-started.md).
2. Select **MSI Properties** in the sidebar.

![The MSI Properties view](../images/view-msi.png)

3. Use **Copy JSON**, **Export CSV** or **Export HTML** to take the whole table. **Copy Summary** has only four named MSI properties.

## Options and settings of this page

| Control | Effect |
|---|---|
| **Copy Summary**, **Copy JSON**, **Export CSV**, **Export HTML** | See [Export and copy](export.md). |

## Limits

- The tool reads the properties with the vendored `MSI` module, and with the `WindowsInstaller` COM object when the module cannot load.
- The tool reads the file. It does not apply transforms.

## Troubleshooting

| Message or symptom | Cause | Fix |
|---|---|---|
| The grid is empty. | The file is not an MSI. An MSP and an EXE wrapper do not fill it. | Open an MSI, or extract the MSI of a wrapper and open it. |

## Links

- [Overview](overview.md)
- [Registry Settings and Strings](registry-and-strings.md)
