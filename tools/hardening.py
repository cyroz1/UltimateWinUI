"""
Security hardening transforms for generated catalog bodies.

tools/catalog_gen.py applies these to every script body it emits, in the
same spirit as tools/arch.py (whose ARM64 swaps also make shipped bodies
differ from the pristine upstream scripts):

  1. Verified downloads. Downloads whose publisher identity is stable
     (NVIDIA and AMD driver packages fetched from the vendors' own
     endpoints) are rewritten to Invoke-VerifiedDownload, which refuses
     to place the payload unless its Authenticode signature is valid
     and issued to the expected publisher. The helper fails closed: it
     demands either a SHA256 pin or a signer, and deletes the download
     on any mismatch.

  2. Private staging. Download / extract / execute chains that used
     predictable shared locations (C:\\Windows\\Temp, C:\\inteldriver)
     are redirected to a per-run randomized directory under
     C:\\ProgramData\\UltimateWinUI\\Staging whose ACL is reset to
     SYSTEM + Administrators only, so neither another local user nor a
     medium-integrity process of the same user can pre-plant or swap
     the payload an elevated script is about to execute.

Downloads that come from the FR33THY "Files" GitHub release mirror have
no groundable publisher expectation in the scripts themselves (the
mirror, not the vendor, is the source), so they are NOT routed through
signature verification; they only get the private-staging treatment.
They remain a known remainder: see the audit notes in README.md.

ARM64 variant bodies (tools/arch.py) are computed from the unhardened
bodies and are not passed through these transforms yet.
"""

# Bump whenever the emitted catalog format or these transforms change in
# a way a reviewer should be able to spot from tweaks.json alone.
GENERATOR_VERSION = 2

# PowerShell helpers prepended to any body that ends up referencing
# $UltimateStaging or Invoke-VerifiedDownload after the transforms.
# Windows PowerShell 5.1 compatible (the app runs bodies with
# powershell.exe): no ternary/null-coalescing operators, no ForEach-Object
# -Parallel, splatting via hashtable only.
PRELUDE = r"""# --- UltimateWinUI hardening helpers (injected by tools/catalog_gen.py) ---
function Get-UltimateStagingDir {
    if ($script:UltimateStagingDir) { return $script:UltimateStagingDir }
    $root = Join-Path $env:ProgramData 'UltimateWinUI\Staging'
    $dir = Join-Path $root ([Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # The scripts run elevated; keep staging writable by SYSTEM and
    # Administrators only so payloads cannot be pre-planted or swapped by
    # another user or by a medium-integrity process of the same user.
    icacls.exe $dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' /grant:r 'Administrators:(OI)(CI)F' | Out-Null
    $script:UltimateStagingDir = $dir
    return $dir
}
$UltimateStaging = Get-UltimateStagingDir

function Invoke-VerifiedDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [string]$Sha256,
        [string]$Signer,
        [hashtable]$Headers
    )
    if (-not $Sha256 -and -not $Signer) {
        throw "Invoke-VerifiedDownload requires -Sha256 or -Signer; refusing unverified download of $Url"
    }
    $tmp = Join-Path (Get-UltimateStagingDir) ([Guid]::NewGuid().ToString('N') + '.download')
    $request = @{ Uri = $Url; OutFile = $tmp; UseBasicParsing = $true }
    if ($Headers) { $request['Headers'] = $Headers }
    Invoke-WebRequest @request
    if ($Sha256) {
        $actual = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash
        if ($actual -ne $Sha256) {
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            throw "SHA256 mismatch for $Url (expected $Sha256, got $actual); download discarded."
        }
    }
    if ($Signer) {
        $sig = Get-AuthenticodeSignature -FilePath $tmp
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike "*$Signer*") {
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            throw "Authenticode check failed for $Url (status $($sig.Status), signer '$($sig.SignerCertificate.Subject)'; expected a signer containing '$Signer'); download discarded."
        }
    }
    $parent = Split-Path $OutFile -Parent
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    Move-Item -Path $tmp -Destination $OutFile -Force
}
# --- end of injected helpers ---
"""

# Staging prefix swaps, applied first: (script path, old, new). Scoped to
# the payload names that are downloaded, extracted, or executed, so
# unrelated Temp uses (self-authored .reg/.xml hand-offs, log files) keep
# their original paths.
STAGING_SWAPS = [
    # Graphics driver trio: driver packages and their extraction trees.
    ("5 Graphics/2 Driver Updated Install.ps1",
     r"$env:SystemRoot\Temp\nvidiadriver", r"$UltimateStaging\nvidiadriver"),
    ("5 Graphics/2 Driver Updated Install.ps1",
     r"$env:SystemRoot\Temp\amddriver", r"$UltimateStaging\amddriver"),
    ("5 Graphics/3 Driver Updated Install & Settings.ps1",
     r"$env:SystemRoot\Temp\nvidiadriver", r"$UltimateStaging\nvidiadriver"),
    ("5 Graphics/3 Driver Updated Install & Settings.ps1",
     r"$env:SystemRoot\Temp\amddriver", r"$UltimateStaging\amddriver"),
    ("5 Graphics/3 Driver Updated Install & Settings.ps1",
     r"$env:SystemRoot\Temp\nvp.appx", r"$UltimateStaging\nvp.appx"),
    ("5 Graphics/3 Driver Updated Install & Settings.ps1",
     r"$env:SystemRoot\Temp\7zip.exe", r"$UltimateStaging\7zip.exe"),
    ("5 Graphics/4 Driver Debloat Install & Settings.ps1",
     r"$env:SystemRoot\Temp\nvidiadriver", r"$UltimateStaging\nvidiadriver"),
    ("5 Graphics/4 Driver Debloat Install & Settings.ps1",
     r"$env:SystemRoot\Temp\amddriver", r"$UltimateStaging\amddriver"),
    ("5 Graphics/4 Driver Debloat Install & Settings.ps1",
     r"$env:SystemDrive\inteldriver", r"$UltimateStaging\inteldriver"),
    ("5 Graphics/4 Driver Debloat Install & Settings.ps1",
     r"$env:SystemRoot\Temp\nvp.appx", r"$UltimateStaging\nvp.appx"),
    ("5 Graphics/4 Driver Debloat Install & Settings.ps1",
     r"$env:SystemRoot\Temp\7zip.exe", r"$UltimateStaging\7zip.exe"),
    # Installers: every payload this script stages in the shared Temp
    # folder, plus the two cases that stage in the user temp folder via a
    # $tempDir variable (rebound to the staging dir).
    ("4 Installers/1 Installers.ps1",
     "$env:SystemRoot\\Temp\\", "$UltimateStaging\\"),
    ("4 Installers/1 Installers.ps1",
     "$Global:tempDir = (([System.IO.Path]::GetTempPath())).trimend('\\')",
     "$Global:tempDir = $UltimateStaging"),
    # Check / Refresh / Setup one-shot download-then-run helpers.
    ("1 Check/3 Ram Check.ps1",
     r"$env:SystemRoot\Temp\cpuz.exe", r"$UltimateStaging\cpuz.exe"),
    ("1 Check/4 Gpu Check.ps1",
     r"$env:SystemRoot\Temp\gpuz.exe", r"$UltimateStaging\gpuz.exe"),
    ("1 Check/5 Storage Ram Cpu Test & Bench.ps1",
     r"$env:SystemRoot\Temp\occt.exe", r"$UltimateStaging\occt.exe"),
    ("1 Check/6 Gpu Test & Bench.ps1",
     r"$env:SystemRoot\Temp\furmark", r"$UltimateStaging\furmark"),
    ("2 Refresh/3 Reinstall.ps1",
     r"$env:SystemRoot\Temp\mediacreationtool", r"$UltimateStaging\mediacreationtool"),
    ("3 Setup/10 Edge Settings.ps1",
     r"$env:SystemRoot\Temp\edge.exe", r"$UltimateStaging\edge.exe"),
    # Same one-shot pattern in the remaining download-then-run tweaks
    # (payloads come from the FR33THY Files mirror: staging only, no
    # groundable publisher expectation). Self-authored .reg hand-offs in
    # the same scripts deliberately keep their original paths.
    ("4 Installers/2 MSI Afterburner.ps1",
     r"$env:SystemRoot\Temp\msiafterburner.exe", r"$UltimateStaging\msiafterburner.exe"),
    ("5 Graphics/1 Driver Clean.ps1",
     r"$env:SystemRoot\Temp\7zip.exe", r"$UltimateStaging\7zip.exe"),
    ("5 Graphics/1 Driver Clean.ps1",
     r"$env:SystemRoot\Temp\ddu", r"$UltimateStaging\ddu"),
    ("5 Graphics/11 DirectX.ps1",
     r"$env:SystemRoot\Temp\7zip.exe", r"$UltimateStaging\7zip.exe"),
    ("5 Graphics/11 DirectX.ps1",
     r"$env:SystemRoot\Temp\directx", r"$UltimateStaging\directx"),
    ("5 Graphics/12 C++.ps1",
     r"$env:SystemRoot\Temp\vcredist", r"$UltimateStaging\vcredist"),
    ("6 Windows/13 Bloatware.ps1",
     r"$env:SystemRoot\Temp\remotedesktopconnection.exe", r"$UltimateStaging\remotedesktopconnection.exe"),
    ("6 Windows/13 Bloatware.ps1",
     r"$env:SystemRoot\Temp\snippingtool.exe", r"$UltimateStaging\snippingtool.exe"),
    ("6 Windows/19 Gamebar.ps1",
     r"$env:SystemRoot\Temp\edgewebview.exe", r"$UltimateStaging\edgewebview.exe"),
    ("6 Windows/19 Gamebar.ps1",
     r"$env:SystemRoot\Temp\gamingrepairtool.exe", r"$UltimateStaging\gamingrepairtool.exe"),
    ("6 Windows/20 Edge & WebView.ps1",
     r"$env:SystemRoot\Temp\edge.exe", r"$UltimateStaging\edge.exe"),
    ("6 Windows/20 Edge & WebView.ps1",
     r"$env:SystemRoot\Temp\edgewebview.exe", r"$UltimateStaging\edgewebview.exe"),
    ("7 Hardware/4 Controller Overclock.ps1",
     r"$env:SystemRoot\Temp\hidusbf.zip", r"$UltimateStaging\hidusbf.zip"),
]

# Verified-download swaps, applied after staging swaps (so their old
# strings are written against the staged paths). Only direct-from-vendor
# downloads with a stable signing identity are listed; the signer string
# is matched against the Authenticode signer certificate subject.
VERIFIED_SWAPS = [
    # NVIDIA: the URL itself is derived from NVIDIA's driver service, the
    # payload comes from international.download.nvidia.com and NVIDIA
    # signs its driver packages as "NVIDIA Corporation".
    ("5 Graphics/2 Driver Updated Install.ps1",
     r'IWR $url -OutFile "$UltimateStaging\nvidiadriver.exe"',
     r'Invoke-VerifiedDownload -Url $url -OutFile "$UltimateStaging\nvidiadriver.exe" -Signer "NVIDIA Corporation"'),
    ("5 Graphics/3 Driver Updated Install & Settings.ps1",
     r'IWR $url -OutFile "$UltimateStaging\nvidiadriver.exe"',
     r'Invoke-VerifiedDownload -Url $url -OutFile "$UltimateStaging\nvidiadriver.exe" -Signer "NVIDIA Corporation"'),
    # AMD: the installer href is scraped from amd.com and points at
    # drivers.amd.com; AMD signs as "Advanced Micro Devices, Inc.".
    ("5 Graphics/2 Driver Updated Install.ps1",
     r'IWR $DownloadAmd.href -UseBasicParsing -Headers $spoofwebbrowser -OutFile "$UltimateStaging\amddriver.exe" -ErrorAction SilentlyContinue | Out-Null',
     r'Invoke-VerifiedDownload -Url $DownloadAmd.href -OutFile "$UltimateStaging\amddriver.exe" -Signer "Advanced Micro Devices, Inc." -Headers $spoofwebbrowser'),
    ("5 Graphics/3 Driver Updated Install & Settings.ps1",
     r'IWR $DownloadAmd.href -UseBasicParsing -Headers $spoofwebbrowser -OutFile "$UltimateStaging\amddriver.exe" -ErrorAction SilentlyContinue | Out-Null',
     r'Invoke-VerifiedDownload -Url $DownloadAmd.href -OutFile "$UltimateStaging\amddriver.exe" -Signer "Advanced Micro Devices, Inc." -Headers $spoofwebbrowser'),
]

# Per-tweak confirmation text for Advanced options whose risk deserves
# specific wording, keyed by (script path, option label). Any Advanced
# "apply" option that still has no confirmation after this gets the
# generic ADVANCED_CONFIRMATION below, so no Advanced apply can run with
# zero dialogs even if the settings-file confirmation gate is tampered
# with.
CONFIRMATION_OVERRIDES = {
    ("8 Advanced/2 Firewall.ps1", "Firewall: Disable"):
        "Choosing \"Firewall: Disable\" turns off the Windows Firewall for all "
        "profiles, leaving this PC reachable on networks you do not control. "
        "Only continue if you understand the exposure, and re-enable the "
        "firewall from this same card when you are done.",
}

ADVANCED_CONFIRMATION = (
    "This is an Advanced tweak: \"{label}\" changes security-relevant or "
    "low-level system state. It normally gets the extra Advanced review "
    "dialog as well; this prompt is shown so the change is never applied "
    "without an explicit confirmation."
)


def apply_hardening(script_path: str, body: str, stats: dict) -> str:
    """Apply staging + verified-download transforms to one option body.

    stats is a mutable counter dict the generator prints at the end so a
    reviewer can see how many replacements actually landed.
    """
    out = body
    for path, old, new in STAGING_SWAPS:
        if path == script_path and old in out:
            stats["staging"] = stats.get("staging", 0) + out.count(old)
            out = out.replace(old, new)
    for path, old, new in VERIFIED_SWAPS:
        if path == script_path and old in out:
            stats["verified"] = stats.get("verified", 0) + out.count(old)
            out = out.replace(old, new)
    if "$UltimateStaging" in out or "Invoke-VerifiedDownload" in out:
        out = PRELUDE + "\n" + out
        stats["preludes"] = stats.get("preludes", 0) + 1
    return out
