# Third-Party Notices

Installer Analysis bundles or depends on the following third-party
components. Their respective copyrights and licenses are retained by
their authors; this notice exists to surface attribution.

---

## MahApps.Metro

- File: `Lib\MahApps.Metro.dll` (+ `Lib\MahApps.Metro.xml`)
- Project: <https://github.com/MahApps/MahApps.Metro>
- License: MIT

Copyright (c) .NET Foundation and Contributors. All rights reserved.

---

## ControlzEx

- File: `Lib\ControlzEx.dll`
- Project: <https://github.com/ControlzEx/ControlzEx>
- License: MIT

Copyright (c) Jan Karger, Bastian Schmidt, James Willock.

---

## Microsoft.Xaml.Behaviors.Wpf

- File: `Lib\Microsoft.Xaml.Behaviors.dll`
- Project: <https://github.com/microsoft/XamlBehaviorsWpf>
- License: MIT

Copyright (c) Microsoft Corporation.

---

## Windows Installer PowerShell Module (MSI)

- Path: `Lib\MSI\3.3.4\` (full module)
- Project: <https://github.com/heaths/psmsi>
- Author: Heath Stewart (Microsoft Corporation)
- License: MIT (see `Lib\MSI\3.3.4\LICENSE.txt`)

Provides `Microsoft.Deployment.WindowsInstaller.*` managed wrappers
over the Windows Installer API (also known as the WiX Deployment
Tools Foundation / DTF libraries). Used here for read-only MSI /
MSP property and summary-information extraction.

Vendored components included with this module:

- `Microsoft.Deployment.WindowsInstaller.dll`
- `Microsoft.Deployment.WindowsInstaller.Package.dll`
- `Microsoft.Deployment.Compression.dll`
- `Microsoft.Deployment.Compression.Cab.dll`
- `Microsoft.Tools.WindowsInstaller.PowerShell.dll`

Each is governed by the MIT license shipped at
`Lib\MSI\3.3.4\LICENSE.txt`. Per-component license texts are also
preserved at `Lib\MSI\3.3.4\Licenses\`.

---

## LZMA SDK (reference decoder)

- File: `Module\InstallerAnalysisCommon.psm1` (the C# `NsisLzmaDecoder`
  type compiled at module load)
- Project: <https://7-zip.org/sdk.html>
- Author: Igor Pavlov
- License: public domain

The LZMA1 range decoder and the BCJ x86 branch-conversion filter used to
read NSIS header streams are a C# port of the SDK's `LzmaSpec.cpp`
reference decoder and `Bra86.c`. No SDK binaries ship with this tool.

---

## License Texts

Full MIT license text applies to all components above. The canonical
copy for the MSI module ships at `Lib\MSI\3.3.4\LICENSE.txt`; the MIT
text is reproduced here for the binary-only assemblies:

```
Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
