# Glossary

This page defines the terms of Installer Analysis.

## What it does

It explains the terms that the tool and this guide use.

## When to use it

Use it when a term is not clear.

## Requirements

None.

## Terms

| Term | Meaning |
|---|---|
| Installer | A file that installs a product. |
| MSI | A Windows Installer package. |
| MSP | A Windows Installer patch. |
| Product code | The GUID of an MSI product. It names the uninstall registry key. |
| Upgrade code | The GUID that groups the versions of a product. |
| ARP | Add/Remove Programs. The registry key under `Uninstall` that lists the product. |
| Silent switch | A command line option that installs without a window, for example `/qn` or `/S`. |
| Payload | The files that an EXE wrapper holds. |
| Inner installer | An installer file inside the payload of another installer. |
| NSIS, Inno Setup, WiX Burn | Installer builders whose setup files the tool recognizes. |
| Authenticode | The signature of a Windows file. |
| SHA-256 | The hash of the file. |
| 7-Zip | A free archive tool. The tool uses it to list and extract a payload. |

## Steps

None.

## Limits

None.

## Troubleshooting

None.

## Links

- [Installer types](installer-types.md)
