# Installer Analysis documentation

Installer Analysis reads a Windows installer file and shows the data that you need to package it: the type, the signature, the install and uninstall commands, the product code and the registry keys. It reads the file only. It needs no administrator rights and no Configuration Manager console. This page links every page of the documentation.

## Start

- [Getting started](getting-started.md): install, open a file and read the Overview.

## Core

- [Overview](core/overview.md): the type, the source facts, the deployment fields and the package metadata.
- [MSI Properties](core/msi-properties.md): the property table of an MSI.
- [Payload and inner installers](core/payload.md): the files inside an EXE wrapper, which need 7-Zip.
- [Registry Settings and Strings](core/registry-and-strings.md): the registry keys that the installer writes and the strings of the file.
- [Export and copy](core/export.md): Copy Summary, Copy JSON, Export CSV and Export HTML.
- [Options dialog](core/options.md): the 7-Zip path, logging, reports and About.

## Reference

- [Installer types](reference/installer-types.md): the formats that the tool detects.
- [Settings](reference/settings.md): what the tool saves and where.
- [Files and logs](reference/files-and-logs.md): every folder and file that the tool writes.
- [Permissions](reference/permissions.md): the rights that the tool needs.
- [Network](reference/network.md): every outbound call.
- [Keyboard](reference/keyboard.md): the Tab order and the keys.
- [Error messages](reference/error-messages.md): message, cause and fix.
- [Glossary](reference/glossary.md): the terms of the tool.
- [Capture the images again](reference/capture-images.md): the one command that regenerates the images of this guide.

## External references

- [External references](external-references.md): pages of Microsoft and of the installer projects.

## Troubleshooting

- [Troubleshooting](troubleshooting.md): the most common messages with cause and fix.
