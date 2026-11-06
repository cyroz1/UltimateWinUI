# UltimateWinUI

A native **WinUI 3** front end for the [FR33THY Ultimate](https://github.com/FR33THYFR33THY/Ultimate)
Windows optimization script library, styled after the Windows Settings app
(the same idea as the AtlasOS toolbox, but for this script library).

![status](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)

## What it does

- **All 104 scripts** from the library, organized in the library's own 8
  categories: Check, Refresh, Setup, Installers, Graphics, Windows, Hardware,
  Advanced.
- **The right control for every tweak**, generated from the script itself:
  - 2+ options -> a **dropdown** + Apply, preselected to the detected or
    last-applied state
  - a script that only opens something -> a **button / link** (settings pages,
    control panel applets, websites, other apps)
  - multi-action scripts -> one button per action
  - scripts with a *Check* option -> a **Check** button that runs it and shows
    the output in Logs
- **State detection.** The catalog generator extracts the registry writes each
  option performs. On launch the app reads those values back from the live
  registry and shows which state every tweak is actually in. For tweaks that
  are not registry backed, the app remembers what it last applied. Both are
  saved in `%LocalAppData%\UltimateWinUI` and **survive restarts**.
- **No consoles.** The app runs elevated, so scripts never relaunch themselves
  into a visible PowerShell window. Script output is piped into the in-app
  **Logs** page (and a log file). Consoles only exist if you open the log file
  yourself.
- **Safety settings:** a confirmation dialog before running anything from the
  Advanced category (on by default), plus an optional restore point before
  each apply (off by default). Both settings can be changed in Settings.
  Independently of those settings, every Advanced option also carries its
  own confirmation prompt in the catalog, so an Advanced change is never
  applied with no dialog at all.

## How it works

The app never reimplements tweak logic in C#. `tools/catalog_gen.py` parses
the upstream scripts once and produces `Assets/tweaks.json`:

- folder -> category, file name -> tweak, `Write-Host` menu -> options,
  switch-case bodies -> the exact script text to run per option
- each option's registry writes become its detection **signature**

At runtime, choosing an option writes its body to a temp .ps1 and runs it
hidden with Windows PowerShell, elevated, with stdout/stderr streamed to the
log. The original scripts are also bundled under `Assets/Scripts` untouched.

To refresh the catalog from a newer upstream release:

```powershell
git clone https://github.com/FR33THYFR33THY/Ultimate ..\Ultimate
git -C ..\Ultimate checkout <commit-or-tag-you-are-shipping>
python tools\catalog_gen.py ..\Ultimate src\UltimateWinUI\Assets\Scripts src\UltimateWinUI\Assets\tweaks.json
```

The generator records the upstream commit and a SHA256 digest of the
input script tree in `tweaks.json` (`upstream` field), and CI fails the
release build if the committed catalog does not match a regeneration
from the bundled `Assets/Scripts`, so the shipped catalog always
corresponds to a known upstream state. The generator also applies the
security transforms in `tools/hardening.py` to the emitted bodies
(private staging directories, verified vendor downloads, confirmation
prompts for every Advanced option); the bundled scripts stay pristine.

## Build

Requires Windows + the .NET 8 SDK. WinUI 3 cannot be built on Linux/macOS.

```powershell
dotnet publish src\UltimateWinUI\UltimateWinUI.csproj -c Release -r win-x64 --self-contained true -p:Version=1.0.4 -o artifacts\publish\win-x64
```

Installer (Inno Setup 6), for x64:

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DAppVersion=1.0.4 /DPublishDir=..\artifacts\publish\win-x64 /DOutName=UltimateWinUI-x64-Setup-1.0.4 /DArchAllowed=x64compatible /DIn64Bit=x64compatible /Oartifacts installer\UltimateWinUI.iss
```

## CI

`.github/workflows/build.yml` runs when a `v*` tag is pushed. It builds only
the self-contained x64 and ARM64 Inno Setup installers, then creates and
publishes a GitHub release with a commit-based changelog and both installers
attached. The workflow can also be dispatched manually for a tag. The first
release uses the `v1.0.0` tag.

Release hardening: every action is pinned to a full commit SHA and the
Inno Setup install is pinned to a fixed version. Each build job records
a SHA256 digest of its installer; the publish job verifies the bytes
against those digests, attaches `SHA256SUMS.txt` to the release and
prints the checksums in the release notes, refuses to overwrite assets
on an existing release, and requires approval in the `release` GitHub
environment before publishing. A `catalog-check` job regenerates the
catalog from `Assets/Scripts` and blocks the release if the committed
`tweaks.json` differs. The installers are not code-signed (no
certificate is configured for this repo), so the published digests are
the integrity check users have.

## Layout

```
src/UltimateWinUI/
  App.xaml(.cs)            services bootstrap + shared apply pipeline
  MainWindow.xaml(.cs)     NavigationView shell, search, theme, info bar
  Models/Catalog.cs        catalog types (tweaks.json shape)
  Services/
    CatalogService.cs      catalog load, settings, data dir
    Detector.cs            registry signature matching -> live state
    Runner.cs              hidden elevated PowerShell runner + launcher
    LogService.cs          in-app log + log file
  Views/                   Home, Category (data-driven cards), Logs, Settings
  Assets/tweaks.json       generated catalog (do not hand edit)
  Assets/Scripts/          pristine upstream scripts
tools/catalog_gen.py       upstream scripts -> tweaks.json
tools/screenshot.ps1       drives the installed app and captures pages
installer/UltimateWinUI.iss
```

## ARM64

The app ships native **win-arm64** builds and a dedicated ARM64 installer,
same as the x64 ones. Nothing is disabled on ARM64. Where an x86/x64 step
in a script literally cannot work there, the app runs a replacement body
instead (`tools/arch.py`, shipped as `arm64Body` in the catalog):

- **GPU driver tooling** (driver installs, DDU, vendor settings): ARM64
  Windows has no discrete NVIDIA/AMD/Intel driver packages. GPU drivers
  arrive through Windows Update and the device maker, so the replacement
  opens Windows Update (or Device Manager, for driver removal) and logs
  why.
- **Kernel-driver tweaks** (controller overclock's hidusbf, MSI
  Afterburner's RTCore64, the WHQL bypass, ReBAR, ULPS, discrete-GPU
  registry tweaks): no ARM64 equivalent exists, so the replacement logs a
  plain explanation and changes nothing, instead of pretending to work.
- **Native payloads where they exist:** the Visual C++ script downloads
  Microsoft's official ARM64 redistributable for the 2015-2022 pack
  (2005-2013 packs were never made for ARM64 and install under emulation),
  and scripts that fetch 7-Zip get the official ARM64 installer.
- Everything else (registry, policy, bcdedit, services, user-mode
  downloads under emulation) is architecture neutral and runs as-is.

## Credits and license

All tweak logic is from [FR33THYFR33THY/Ultimate](https://github.com/FR33THYFR33THY/Ultimate),
MIT licensed, (c) FR33THY (see `Assets/UPSTREAM-LICENSE.txt`). This wrapper is
an unofficial front end and is not affiliated with FR33THY.
