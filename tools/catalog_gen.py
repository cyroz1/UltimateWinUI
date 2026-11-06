#!/usr/bin/env python3
"""
Catalog generator for UltimateWinUI.

Parses every PowerShell script in the FR33THY Ultimate library and emits
Assets/tweaks.json, which the WinUI app renders data-driven:

  - folder            -> category
  - file name         -> tweak name (leading "N " number stripped, kept as sort order)
  - Write-Host menu   -> options ("1. Power Plan: On (Recommended)" ...)
  - switch-case body  -> the exact script text the app runs for that option
  - "Check" option    -> a check action (output goes to the app log view)
  - no menu at all    -> a single action (button / link style)

For state detection the generator extracts the registry writes each option
performs (reg add / Set-ItemProperty / New-ItemProperty) as a "signature".
At runtime the app reads those values back from the live registry and matches
them against each option's signature to work out which state the tweak is in.

Usage:
    python3 catalog_gen.py <ultimate-repo-dir> <scripts-out-dir> <json-out>
"""
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from descriptions import DESCRIPTIONS
from arch import ARM64_BODIES, ARM64_BODY_SWAPS
from hardening import (
    ADVANCED_CONFIRMATION,
    CONFIRMATION_OVERRIDES,
    GENERATOR_VERSION,
    apply_hardening,
)


def arm64_variant(script_path: str, body: str):
    if script_path in ARM64_BODIES:
        return ARM64_BODIES[script_path]
    swaps = ARM64_BODY_SWAPS.get(script_path)
    if not swaps:
        return None
    out = body
    for old, new in swaps:
        if old not in out:
            return None
        out = out.replace(old, new)
    return out if out != body else None

CATEGORY_META = {
    "1 Check":     ("Check",     "Diagnostics and benchmarks for BIOS, storage, RAM, GPU and CPU."),
    "2 Refresh":   ("Refresh",   "Reset, reinstall and Windows refresh helpers."),
    "3 Setup":     ("Setup",     "First-time setup: activation, region, startup and background apps."),
    "4 Installers": ("Installers", "App installers and MSI Afterburner."),
    "5 Graphics":  ("Graphics",  "GPU drivers, vendor settings, DirectX, runtimes and display."),
    "6 Windows":   ("Windows",   "Windows UI, gaming, power, privacy-adjacent and cleanup tweaks."),
    "7 Hardware":  ("Hardware",  "Mouse, controller, monitor and network hardware tuning and tests."),
    "8 Advanced":  ("Advanced",  "High-risk tweaks. Security features, mitigations and driver signing live here."),
}

ADMIN_BLOCK = re.compile(
    r"# SCRIPT RUN AS ADMIN.*?Exit\}\s*", re.DOTALL | re.IGNORECASE)
MENU_LINE = re.compile(r'Write-Host\s+"\s*(\d+)\.\s*([^"]+)"')
READHOST_LOOP = re.compile(r"while\s*\(\$true\)\s*\{", re.IGNORECASE)
REG_ADD = re.compile(
    r'reg\s+add\s+"([^"]+)"\s+/v\s+"([^"]+)"\s+/t\s+(REG_\w+)\s+/d\s+"?([^\s"]+)',
    re.IGNORECASE)
REG_ADD_LOOSE = re.compile(
    r'reg\s+add\s+(\S+)\s+/v\s+(\S+)\s+/t\s+(REG_\w+)\s+/d\s+"?([^\s"]+)',
    re.IGNORECASE)
REG_DELETE = re.compile(
    r'reg\s+delete\s+"([^"]+)"\s+/v\s+"([^"]+)"', re.IGNORECASE)
SET_ITEMPROP = re.compile(
    r'(?:Set|New)-ItemProperty\s+(?:-Path\s+)?\\?"?([^"\s]+)\\?"?\s+-Name\s+\\?"([^"\\]+)\\?"\s+-Value\s+\$?\(?([0-9]+)',
    re.IGNORECASE)
START_PROCESS = re.compile(r'Start-Process\s+(?:-FilePath\s+)?\\?"([^"\\]+)\\?"', re.IGNORECASE)
WRITE_CONSOLE_LINE = re.compile(
    r'^\s*(?:Write-(?:Host|Output|Information|Warning|Error)|echo)\s+'
    r'(?:"((?:`.|[^"])*)"|\'((?:`.|[^\'])*)\'|[^\r\n]+)',
    re.IGNORECASE | re.MULTILINE)
CONSOLE_COMMAND = re.compile(
    r'^\s*(?:Write-(?:Host|Output|Information|Warning|Error)|echo)\b',
    re.IGNORECASE | re.MULTILINE)


def strip_scaffolding(text: str) -> str:
    """Remove the run-as-admin relaunch block and console cosmetics."""
    text = ADMIN_BLOCK.sub("", text)
    text = re.sub(r"\$Host\.UI\.RawUI\.[^\n]*\n", "", text)
    text = re.sub(r"\$Host\.PrivateData\.[^\n]*\n", "", text)
    text = re.sub(r"^\s*Clear-Host\s*$", "", text, flags=re.MULTILINE)
    return text


def clean_label(label: str) -> str:
    label = label.replace("`n", " ").replace("`t", " ")
    return re.sub(r"\s+", " ", label).strip()


def find_switch_cases(text: str):
    """Return {choice_number: body} for the menu switch in a script."""
    cases = {}
    # locate 'switch ($choice) {' then walk its cases with brace matching
    m = re.search(r"switch\s*\(\s*\$choice\s*\)\s*\{", text, re.IGNORECASE)
    if not m:
        return cases
    i = m.end()
    n = len(text)
    while i < n:
        cm = re.compile(r"\s*(\d+)\s*\{").match(text, i)
        if not cm:
            break
        num = int(cm.group(1))
        depth = 1
        j = cm.end()
        start = j
        while j < n and depth:
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
            j += 1
        cases[num] = text[start:j - 1]
        i = j
        # skip whitespace; stop when the switch block closes
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i < n and text[i] == "}":
            break
    return cases


def extract_menu(text: str):
    """Ordered [(num, label)] using the nearest preceding group header to
    disambiguate duplicate labels (e.g. 'DRIVER UPDATES: 1. Block' and
    'UPDATES: 4. Block' in the same script)."""
    items = []
    seen = set()
    header = ""
    for line in text.splitlines():
        hm = re.search(r'Write-Host\s+"([^"]{2,40})"\s*$', line)
        if hm and not MENU_LINE.search(line):
            cand = hm.group(1).strip()
            if cand.endswith(":") and not cand.lower().startswith(("http", "settings")):
                header = cand.rstrip(":").title()
            continue
        mm = MENU_LINE.search(line)
        if mm:
            num = int(mm.group(1))
            if num in seen:
                continue
            seen.add(num)
            label = clean_label(mm.group(2))
            if header and not label.lower().startswith(header.lower()):
                label = f"{header}: {label}"
            items.append((num, label))
    return items


def clean_body(body: str) -> str:
    body = re.sub(r"^\s*Clear-Host\s*$", "", body, flags=re.MULTILINE)
    body = re.sub(r"^\s*Pause\s*$", "", body, flags=re.MULTILINE)
    body = re.sub(r"^\s*exit\s*$", "", body, flags=re.MULTILINE)
    return body.strip("\n").rstrip() + "\n"


def normalize(body: str) -> str:
    """FR33THY escapes quotes with backticks and doubles backslashes in cmd strings."""
    body = body.replace('`"', '"').replace("`n", " ").replace("`t", " ")
    return body.replace("\\\\", "\\").replace('\\"', '"')


def signature(body: str):
    body = normalize(body)
    sig = []
    seen = set()
    found = REG_ADD.findall(body) or REG_ADD_LOOSE.findall(body)
    for key, name, reg_type, val in found:
        if key.startswith("$") or name.startswith("$"):
            continue
        if not key.upper().startswith(("HKLM", "HKCU", "HKEY")):
            continue
        ident = (key.lower(), name.lower())
        if ident in seen:
            continue
        seen.add(ident)
        kind = reg_type.upper()
        if kind == "REG_BINARY":
            binary = re.sub(r"[\s,]", "", val)
            binary = re.sub(r"^0x", "", binary, flags=re.IGNORECASE)
            if not binary or not re.fullmatch(r"[0-9a-fA-F]+", binary):
                continue
            sig.append({"key": key, "name": name, "value": binary.upper(), "kind": "binary"})
        elif kind in ("REG_DWORD", "REG_QWORD"):
            try:
                number = int(val, 0)
            except ValueError:
                try:
                    number = int(val, 10)
                except ValueError:
                    continue
            sig.append({"key": key, "name": name, "value": number,
                        "kind": "qword" if kind == "REG_QWORD" else "dword"})
        else:
            sig.append({"key": key, "name": name, "value": val, "kind": "string"})
    for path, name, val in SET_ITEMPROP.findall(body):
        key = path.replace("HKLM:", "HKEY_LOCAL_MACHINE").replace("HKCU:", "HKEY_CURRENT_USER")
        ident = (key.lower(), name.lower())
        if ident in seen:
            continue
        seen.add(ident)
        sig.append({"key": key, "name": name, "value": int(val), "kind": "dword"})
    deletes = [{"key": k, "name": n, "kind": "deleted"} for k, n in REG_DELETE.findall(body)]
    return sig[:12], deletes[:6]


READHOST_PROMPT = re.compile(r'Read-Host\s+(?:-Prompt\s+)?"([^"]*)"', re.IGNORECASE)


def extract_inputs(body: str):
    """Real user inputs a script asks for (excludes the bare menu Read-Host)."""
    prompts = []
    for p in READHOST_PROMPT.findall(body):
        p = p.strip()
        if p:
            prompts.append(p)
    return prompts


def confirmation_message(body: str) -> str | None:
    """Summarize console text and interactions the app cannot render itself."""
    messages = []
    has_unrendered_output = False
    for match in WRITE_CONSOLE_LINE.finditer(body):
        message = (match.group(1) if match.group(1) is not None else match.group(2))
        if message is None:
            has_unrendered_output = True
            continue
        message = (message.replace('`"', '"').replace('``', '`')
                   .replace('`n', '\n').replace('`t', ' ')).strip()
        # Variable interpolation would be misleading when shown before execution.
        if message and '$' not in message:
            if message not in messages:
                messages.append(message)
        elif message:
            has_unrendered_output = True

    notes = []
    if CONSOLE_COMMAND.search(body):
        if messages:
            text = '\n'.join(messages)
            if len(text) > 2400:
                text = text[:2397].rstrip() + '...'
            notes.append('Console messages that may appear:\n' + text)
            if has_unrendered_output:
                notes.append('Some console output depends on live values and appears only while the script runs.')
        else:
            notes.append('This option prints additional console messages while it runs.')

    if re.search(r'^\s*Pause\s*$', body, re.IGNORECASE | re.MULTILINE):
        notes.append('The original script pauses for console input; this Run/Cancel prompt replaces that pause.')
    if re.search(r'\b(?:ShowDialog|PromptForChoice|ReadKey)\b', body, re.IGNORECASE):
        notes.append('The script opens another prompt or dialog while it runs.')
    if len(re.findall(r'\bRead-Host\b', body, re.IGNORECASE)) > len(extract_inputs(body)):
        notes.append('The script requests console input beyond values collected in the app.')
    if re.search(r'\bshutdown(?:\.exe)?\b[^\r\n]*(?:/r|/fw)|\bRestart-Computer\b', body, re.IGNORECASE):
        notes.append('This option restarts the PC or opens BIOS/UEFI setup.')
    if re.search(r'RadeonSoftware\.exe', body, re.IGNORECASE):
        notes.append('This option opens AMD Software briefly while applying AMD settings.')

    return '\n\n'.join(notes) if notes else None


def classify_option(label: str, body: str) -> str:
    low = label.lower()
    if "check" in low:
        return "check"
    targets = START_PROCESS.findall(body)
    meaningful = [t for t in targets if not t.lower().startswith(("powershell", "cmd"))]
    if meaningful and len(body.strip().splitlines()) <= 6:
        return "launch"
    return "apply"


def control_for(options) -> str:
    applies = [o for o in options if o["kind"] == "apply"]
    if not applies:
        return "actions"          # only check / launch buttons
    if len(applies) == 1 and len(options) == 1:
        return "button"
    return "dropdown"


def main() -> int:
    src = Path(sys.argv[1])
    scripts_out = Path(sys.argv[2])
    json_out = Path(sys.argv[3])
    scripts_out.mkdir(parents=True, exist_ok=True)

    categories = []
    total = 0
    stats = {"dropdown": 0, "button": 0, "actions": 0}
    hardening_stats: dict = {}

    for folder in sorted(p for p in src.iterdir() if p.is_dir() and p.name in CATEGORY_META):
        cat_name, cat_desc = CATEGORY_META[folder.name]
        tweaks = []
        for ps1 in sorted(folder.glob("*.ps1")):
            raw = ps1.read_text(encoding="utf-8", errors="replace")
            text = strip_scaffolding(raw)
            stem = ps1.stem
            m = re.match(r"(\d+)\s+(.*)", stem)
            order, name = (int(m.group(1)), m.group(2)) if m else (99, stem)

            menu_items = extract_menu(text)
            cases = find_switch_cases(text)
            options = []
            if menu_items and cases:
                for num, label in menu_items:
                    raw_body = cases.get(num, "")
                    body = clean_body(raw_body)
                    kind = classify_option(label, body)
                    if kind in ("apply", "check") and not body.strip():
                        continue  # e.g. a menu "Exit" entry with no real body
                    sig, dels = signature(body)
                    opt = {"label": label, "kind": kind}
                    if kind in ("apply", "check"):
                        opt["bodyFile"] = f"{folder.name}/{ps1.name}#opt{num}"
                        opt["body"] = body
                    else:
                        targets = START_PROCESS.findall(body)
                        opt["target"] = targets[0] if targets else ""
                        opt["body"] = body
                    if sig:
                        opt["signature"] = sig
                    if dels:
                        opt["deletes"] = dels
                    inputs = extract_inputs(body)
                    if inputs:
                        opt["inputs"] = inputs
                    confirmation = confirmation_message(raw_body)
                    if confirmation:
                        opt["confirmation"] = confirmation
                    options.append(opt)
            else:
                # no menu: whole script is one action
                targets = START_PROCESS.findall(text)
                body = clean_body(text)
                if targets and len(body.strip().splitlines()) <= 4:
                    options.append({"label": "Open", "kind": "launch",
                                    "target": targets[0], "body": body})
                else:
                    sig, dels = signature(body)
                    opt = {"label": "Run", "kind": "apply", "body": body,
                           "bodyFile": f"{folder.name}/{ps1.name}#full"}
                    if sig:
                        opt["signature"] = sig
                    if dels:
                        opt["deletes"] = dels
                    inputs = extract_inputs(body)
                    if inputs:
                        opt["inputs"] = inputs
                    confirmation = confirmation_message(text)
                    if confirmation:
                        opt["confirmation"] = confirmation
                    options.append(opt)

            control = control_for(options)
            stats[control] += 1
            script_path = f"{folder.name}/{ps1.name}"
            for opt in options:
                if opt.get("body"):
                    variant = arm64_variant(script_path, opt["body"])
                    if variant:
                        opt["arm64Body"] = variant
            # Security hardening (tools/hardening.py): private staging for
            # download/extract/execute chains and verified downloads for
            # direct-from-vendor payloads. Applied after the ARM64 variant
            # is derived so the arch swaps keep matching the original text;
            # ARM64 variant bodies are not hardened yet.
            for opt in options:
                if opt.get("body"):
                    opt["body"] = apply_hardening(script_path, opt["body"], hardening_stats)
            # No Advanced apply may ship without a confirmation: if the
            # settings-file gate is ever disabled (or tampered with), these
            # options still prompt. Options that already carry a console
            # derived confirmation keep it.
            if cat_name == "Advanced":
                for opt in options:
                    if opt["kind"] == "apply" and not opt.get("confirmation"):
                        opt["confirmation"] = CONFIRMATION_OVERRIDES.get(
                            (script_path, opt["label"]),
                            ADVANCED_CONFIRMATION.format(label=opt["label"]))
            recommended = next((o["label"] for o in options
                                if "recommended" in o["label"].lower()), None)
            tweak = {
                "id": f"{cat_name.lower()}-{order}-{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')}",
                "name": name,
                "description": DESCRIPTIONS.get(f"{folder.name}/{ps1.name}", ""),
                "order": order,
                "script": f"{folder.name}/{ps1.name}",
                "control": control,
                "options": options,
            }
            if recommended:
                tweak["recommended"] = recommended
            if cat_name == "Advanced":
                tweak["risk"] = "high"
            tweaks.append(tweak)
            total += 1

            # copy the pristine upstream script next to the app assets
            dst = scripts_out / folder.name
            dst.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ps1, dst / ps1.name)

        categories.append({"name": cat_name, "folder": folder.name,
                             "description": cat_desc, "tweaks": tweaks})

    # Provenance: bind the emitted catalog to the exact upstream input it
    # was generated from, so a reviewer (and the CI regen check) can tell
    # whether the committed catalog corresponds to a known upstream state.
    # The tree digest covers every consumed script, so it works for any
    # input directory; the commit is recorded when the input is a git
    # checkout (the documented refresh flow clones upstream).
    digest = hashlib.sha256()
    for ps1 in sorted(src.rglob("*.ps1")):
        digest.update(ps1.relative_to(src).as_posix().encode())
        digest.update(b"\0")
        digest.update(ps1.read_bytes())
        digest.update(b"\0")
    upstream_commit = None
    try:
        upstream_commit = subprocess.run(
            ["git", "-C", str(src), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10).stdout.strip() or None
    except Exception:
        upstream_commit = None

    doc = {
        "library": "FR33THY Ultimate",
        "source": "https://github.com/FR33THYFR33THY/Ultimate",
        "license": "MIT (c) FR33THY",
        "generator": {"tool": "tools/catalog_gen.py", "version": GENERATOR_VERSION},
        "upstream": {"commit": upstream_commit, "treeSha256": digest.hexdigest()},
        "categories": categories,
    }
    missing = [f"{c['folder']}/{t['script'].split('/')[-1]}"
               for c in categories for t in c["tweaks"] if not t["description"]]
    if missing:
        print(f"WARNING: {len(missing)} tweaks have no description: {missing[:5]}")
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(doc, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"tweaks: {total}  controls: {stats}")
    print(f"hardening: {hardening_stats}")
    print(f"upstream: commit={upstream_commit} treeSha256={digest.hexdigest()}")
    print(f"json: {json_out} ({json_out.stat().st_size/1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
