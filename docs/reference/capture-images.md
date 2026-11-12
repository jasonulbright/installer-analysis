# Capture the images again

One command regenerates every image of this guide.

## What it does

`tools\guide-capture\Invoke-GuideCapture.ps1` copies the tool to a lab computer, starts it in an interactive session of a lab account, walks every view, dialog and setting with Windows UI Automation, takes the screenshots at 1440 by 900 pixels, copies the PNG files back to `docs\images` and removes its files from the lab computer. It replaces only the images that exist already.

One capture runs at a time on a lab computer. The command takes the lock file `C:\guide\capture.lock` and waits while another capture holds it. A lock older than 60 minutes is stale. The command works in its own folder `C:\guide\installer-analysis`, removes its own files and the lock at the end, and never removes `C:\guide`.

## When to use it

Use it after a change that alters the window, and before a release.

## Requirements

- A lab computer with PowerShell remoting for an account. The tool needs no Configuration Manager console.
- A script, outside the repository, that sets `$LabCredential` to the credential of that account.
- A domain account that has an interactive session on the lab computer. The capture runs as a scheduled task with an interactive logon.
- Lab data only. The capture copies sample files from the lab computer (an MSI of the Windows Installer cache, `ccmsetup.exe` and an uninstaller) and analyzes the copies. It writes in the capture folder only.

## Steps

1. Run this command from the repository folder:

   ```powershell
   .\tools\guide-capture\Invoke-GuideCapture.ps1 -CredentialScript C:\lab\credentials.local.ps1 -Target CLIENT01 -LogonUser contoso\labadmin
   ```

2. Wait for the command to end. It prints a warning for each step that failed.
3. Open every changed image and check it. Look for clipped text, empty grids and stale version strings.
4. Run the documentation test: `Invoke-Pester .\Tests\Documentation.Tests.ps1`.


## Limits

- The capture needs an interactive session on the lab computer. A locked session breaks it.
- The images show data from the lab computer.

## Troubleshooting

| Message or symptom | Cause | Fix |
|---|---|---|
| `The capture did not finish` | The session is locked or a window did not show. | Unlock the session and run again. |
| A step shows `control not found`. | The window changed. | Update the step in `steps-guide.ps1`. |

## Links

- [Index](../index.md)
