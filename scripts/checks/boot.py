"""Boot chain and disk encryption (category: Boot & Disk).

Checks: secure_boot (10), disk_encryption (15), boot_chain (5). All fast lane.
Never calls sudo. LUKS header parameters are reported as unknown with a
manual cryptsetup command. EFI-only checks are N/A when /sys/firmware/efi
is missing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import FAST_CHECKS, make_result, read_text, register_check, run_cmd

CATEGORY = "Boot & Disk"
EFI_DIR = Path("/sys/firmware/efi")
EFI_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
SECURE_BOOT_VAR = f"SecureBoot-{EFI_GUID}"
SETUP_MODE_VAR = f"SetupMode-{EFI_GUID}"
SWAPS_PATH = Path("/proc/swaps")
CMDLINE_PATH = Path("/proc/cmdline")
TPM_DIR = Path("/sys/class/tpm/tpm0")
SYS_BLOCK = Path("/sys/block")
PRESET_DIR = Path("/etc/mkinitcpio.d")
LOCKDOWN_PATH = Path("/sys/kernel/security/lockdown")

REF_SECURE_BOOT = "https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot"
REF_SBCTL = "https://github.com/Foxboron/sbctl"
REF_DM_CRYPT = "https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system"
REF_UKI = "https://wiki.archlinux.org/title/Unified_kernel_image"
REF_LOCKDOWN = "https://docs.kernel.org/security/lockdown.html"

SB_REFS = [REF_SECURE_BOOT, REF_SBCTL]
DISK_REFS = [REF_DM_CRYPT]
BOOT_REFS = [REF_UKI, REF_LOCKDOWN, REF_SECURE_BOOT]

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_ESP_RESTRICT = re.compile(r"(?:fmask|umask)=0*077\b")
_UKI_PRESET = re.compile(r"^default_uki\s*=", re.MULTILINE)
_HEADER_DUMP = (
    "sudo cryptsetup luksDump {device} | grep -E 'Version|PBKDF|Cipher|tpm2|fido2'"
)


def _worst_severity(severities):
    worst = "info"
    for item in severities:
        if _SEV_RANK.get(item, 0) > _SEV_RANK.get(worst, 0):
            worst = item
    return worst


def _na(check_id, title, max_score, description, details, refs):
    return make_result(
        id=check_id,
        category=CATEGORY,
        title=title,
        passed=False,
        applicable=False,
        score=0,
        max_score=max_score,
        description=description,
        details=details,
        refs=refs,
        lane="fast",
    )


def _devpath(name):
    if not name:
        return None
    if str(name).startswith("/"):
        return str(name)
    return "/dev/" + str(name)


def _mountpoints(dev):
    mps = dev.get("mountpoints")
    if mps is None:
        mp = dev.get("mountpoint")
        mps = [mp] if mp else []
    elif isinstance(mps, str):
        mps = [mps]
    return [mp for mp in mps if mp]


def _iter_blockdevices(devices, parent=None):
    for dev in devices or []:
        node = {
            "name": dev.get("name") or "",
            "type": (dev.get("type") or "") or "",
            "fstype": dev.get("fstype"),
            "fsver": dev.get("fsver"),
            "mountpoints": _mountpoints(dev),
            "size": dev.get("size"),
            "parent": parent,
        }
        yield node
        yield from _iter_blockdevices(dev.get("children") or [], parent=node)


def _ancestors(node):
    current = node
    while current is not None:
        yield current
        current = current.get("parent")


def _efivar_on(path):
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    if len(data) < 5:
        return None
    return data[4] != 0


def _parse_bootctl_status(text):
    secure = None
    setup = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        lower = line.lower()
        if lower.startswith("secure boot:"):
            rest = line.split(":", 1)[1].strip().lower()
            if rest.startswith("enabled") or rest.startswith("on"):
                secure = True
            elif rest.startswith("disabled") or rest.startswith("off"):
                secure = False
            if "(setup)" in rest:
                setup = True
        elif lower.startswith("setup mode:"):
            rest = line.split(":", 1)[1].strip().lower()
            if rest.startswith("enabled") or rest.startswith("on"):
                setup = True
            elif rest.startswith("disabled") or rest.startswith("off"):
                setup = False
    return secure, setup


def _secure_boot_state(efi_dir, run):
    efi_dir = Path(efi_dir)
    secure = _efivar_on(efi_dir / "efivars" / SECURE_BOOT_VAR)
    setup = _efivar_on(efi_dir / "efivars" / SETUP_MODE_VAR)
    used_bootctl = False
    if secure is None or setup is None:
        res = run(["bootctl", "status", "--no-pager"], timeout=0.4)
        if res.returncode not in (127, 124):
            parsed_secure, parsed_setup = _parse_bootctl_status(res.stdout or "")
            used_bootctl = True
            if secure is None:
                secure = parsed_secure
            if setup is None:
                setup = parsed_setup
    return secure, setup, used_bootctl


def _sbctl_details(run, timeout=0.1):
    res = run(["sbctl", "status"], timeout=timeout)
    if res.returncode != 0:
        return []
    lines = []
    for raw in (res.stdout or "").splitlines():
        text = raw.strip()
        if not text:
            continue
        lines.append(text[:120])
        if len(lines) >= 12:
            break
    return lines


def _virt_type(run):
    res = run(["systemd-detect-virt"], timeout=0.4)
    if res.returncode == 127:
        return None
    text = (res.stdout or "").strip().lower()
    if res.returncode == 0 and text and text != "none":
        return text
    return None


def _parse_lsblk(stdout):
    try:
        data = json.loads(stdout or "")
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return list(_iter_blockdevices(data.get("blockdevices") or []))


def _find_root(nodes):
    for node in nodes:
        if "/" in node["mountpoints"]:
            return node
    return None


def _node_by_name(nodes, name):
    for node in nodes:
        if node.get("name") == name:
            return node
    return None


def _node_for_path(nodes, path):
    best = None
    best_len = -1
    for node in nodes:
        for mp in node["mountpoints"]:
            if mp == "[SWAP]":
                continue
            if path == mp or path.startswith(mp.rstrip("/") + "/") or (
                mp == "/" and path.startswith("/")
            ):
                if len(mp) > best_len:
                    best = node
                    best_len = len(mp)
    return best


def _dm_uuids(sys_block):
    mapping = {}
    block = Path(sys_block)
    if not block.is_dir():
        return mapping
    try:
        entries = list(block.iterdir())
    except OSError:
        return mapping
    for entry in entries:
        if not entry.name.startswith("dm-"):
            continue
        uuid = (read_text(entry / "dm" / "uuid") or "").strip()
        name = (read_text(entry / "dm" / "name") or "").strip()
        if not uuid:
            continue
        mapping[entry.name] = uuid
        if name:
            mapping[name] = uuid
    return mapping


def _luks_version_from_uuid(uuid):
    if not uuid:
        return None
    if uuid.startswith("CRYPT-LUKS1"):
        return 1
    if uuid.startswith("CRYPT-LUKS2"):
        return 2
    return None


def _encryption_info(root, dm_uuids):
    """Return (encrypted, luks_version or None, luks_device or None)."""
    version = None
    device = None
    encrypted = False
    for anc in _ancestors(root):
        fstype = (anc.get("fstype") or "").lower()
        ntype = (anc.get("type") or "").lower()
        uuid = dm_uuids.get(anc.get("name") or "", "")
        if fstype == "crypto_luks":
            encrypted = True
            device = _devpath(anc.get("name"))
            fsver = str(anc.get("fsver") or "").strip()
            if fsver.startswith("1"):
                version = 1
            elif fsver.startswith("2"):
                version = 2
            elif version is None:
                version = _luks_version_from_uuid(uuid)
        elif ntype == "crypt" or _luks_version_from_uuid(uuid):
            encrypted = True
            if device is None:
                device = _devpath(anc.get("name"))
            if version is None:
                version = _luks_version_from_uuid(uuid)
    if not encrypted:
        uuid = dm_uuids.get(root.get("name") or "", "")
        version = _luks_version_from_uuid(uuid)
        if version:
            encrypted = True
            device = _devpath(root.get("name"))
    return encrypted, version, device


def _under_crypt(node, dm_uuids):
    encrypted, _, _ = _encryption_info(node, dm_uuids)
    return encrypted


def _unencrypted_swaps(swaps_text, nodes, dm_uuids):
    findings = []
    if not swaps_text:
        return findings
    for raw in swaps_text.splitlines()[1:]:
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        filename, kind = parts[0], parts[1]
        lower_name = filename.lower()
        if "zram" in lower_name:
            continue
        if kind == "file":
            node = _node_for_path(nodes, filename)
        else:
            node = _node_by_name(nodes, Path(filename).name)
        if node is not None and _under_crypt(node, dm_uuids):
            continue
        findings.append(filename)
    return findings


def _esp_options(run):
    for mount in ("/boot", "/efi"):
        res = run(["findmnt", "-n", "-o", "TARGET,OPTIONS", mount], timeout=0.4)
        if res.returncode != 0:
            continue
        line = (res.stdout or "").strip()
        if not line:
            continue
        parts = line.split(None, 1)
        target = parts[0]
        options = parts[1] if len(parts) > 1 else ""
        if target in ("/boot", "/efi"):
            return target, options
    return None, None


def _preset_uses_uki(preset_dir):
    directory = Path(preset_dir)
    if not directory.is_dir():
        return False
    try:
        presets = sorted(directory.glob("*.preset"))
    except OSError:
        return False
    for preset in presets:
        text = read_text(preset) or ""
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if _UKI_PRESET.match(line):
                return True
    return False


def _bootctl_list_uses_uki(text):
    lower = (text or "").lower()
    if "linux boot manager" in lower:
        return True
    collapsed = lower.replace(" ", "")
    if "type#2" in collapsed or "type2" in collapsed:
        return True
    return False


def _lockdown_current(text):
    match = re.search(r"\[([^\]]+)\]", text or "")
    if match:
        return match.group(1).strip()
    return (text or "").strip() or None


@register_check(
    FAST_CHECKS,
    check_id="secure_boot",
    category=CATEGORY,
    title="UEFI Secure Boot",
    max_score=10,
)
def check_secure_boot(*, efi_dir=None, run=None, sbctl_timeout=0.1):
    efi_dir = Path(efi_dir) if efi_dir else EFI_DIR
    run = run or run_cmd
    if not efi_dir.exists():
        return _na(
            "secure_boot",
            "UEFI Secure Boot",
            10,
            "No EFI firmware; Secure Boot is not applicable.",
            [f"{efi_dir} is not present."],
            SB_REFS,
        )

    details = []
    secure, setup, used_bootctl = _secure_boot_state(efi_dir, run)
    if used_bootctl:
        details.append("Secure Boot state read from bootctl status (efivar unreadable).")
    details.extend(_sbctl_details(run, timeout=sbctl_timeout))

    if secure is None:
        details.append(
            "Secure Boot state unknown. Run: bootctl status --no-pager"
        )
        return make_result(
            id="secure_boot",
            category=CATEGORY,
            title="UEFI Secure Boot",
            passed=True,
            score=10,
            max_score=10,
            description="Secure Boot state could not be determined from efivars or bootctl.",
            details=details,
            refs=SB_REFS,
            lane="fast",
        )

    score = 10
    issues = []
    severities = []
    if not secure:
        issues.append("Secure Boot is disabled")
        score -= 7
        severities.append("high")
        details.append("Secure Boot: disabled")
    else:
        details.append("Secure Boot: enabled")
    if setup is True:
        issues.append("firmware setup mode is on")
        score -= 3
        severities.append("high")
        details.append("Setup Mode: on")
    elif setup is False:
        details.append("Setup Mode: off")
    else:
        details.append("Setup Mode: unknown")

    score = max(0, score)
    passed = not issues
    if passed:
        desc = "Secure Boot is enabled and setup mode is off."
        rec = None
    else:
        desc = "; ".join(issues) + "."
        rec = (
            "Enable Secure Boot in firmware and enroll keys with sbctl; see the "
            "Arch wiki UEFI/Secure Boot page. There is no automated fix_cmd "
            "because enrolling keys incorrectly can brick firmware."
        )
    return make_result(
        id="secure_boot",
        category=CATEGORY,
        title="UEFI Secure Boot",
        passed=passed,
        score=score,
        max_score=10,
        severity=_worst_severity(severities),
        description=desc,
        details=details,
        recommendation=rec,
        fix_cmd=None,
        refs=SB_REFS,
        lane="fast",
    )


@register_check(
    FAST_CHECKS,
    check_id="disk_encryption",
    category=CATEGORY,
    title="Disk Encryption",
    max_score=15,
)
def check_disk_encryption(
    *,
    run=None,
    swaps_path=None,
    cmdline_path=None,
    tpm_dir=None,
    sys_block=None,
):
    run = run or run_cmd
    swaps_path = Path(swaps_path) if swaps_path else SWAPS_PATH
    cmdline_path = Path(cmdline_path) if cmdline_path else CMDLINE_PATH
    tpm_dir = Path(tpm_dir) if tpm_dir else TPM_DIR
    sys_block = Path(sys_block) if sys_block else SYS_BLOCK

    lsblk = run(
        ["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,FSVER,MOUNTPOINTS,SIZE"],
        timeout=0.5,
    )
    if lsblk.returncode == 127:
        return _na(
            "disk_encryption",
            "Disk Encryption",
            15,
            "lsblk is not installed; disk encryption cannot be assessed.",
            ["Install util-linux (lsblk) to inspect the block device tree."],
            DISK_REFS,
        )
    if lsblk.returncode != 0:
        return _na(
            "disk_encryption",
            "Disk Encryption",
            15,
            "lsblk failed; disk encryption cannot be assessed.",
            ["lsblk returned a non-zero exit status."],
            DISK_REFS,
        )

    nodes = _parse_lsblk(lsblk.stdout or "")
    if nodes is None:
        return _na(
            "disk_encryption",
            "Disk Encryption",
            15,
            "lsblk JSON could not be parsed; disk encryption cannot be assessed.",
            ["lsblk -J did not return valid JSON."],
            DISK_REFS,
        )

    root = _find_root(nodes)
    if root is None:
        return _na(
            "disk_encryption",
            "Disk Encryption",
            15,
            "Could not identify the block device mounted at /.",
            ["lsblk reported no device with mountpoint /."],
            DISK_REFS,
        )

    dm_uuids = _dm_uuids(sys_block)
    encrypted, luks_version, luks_dev = _encryption_info(root, dm_uuids)
    virt = _virt_type(run)
    swaps_text = read_text(swaps_path, "")
    bad_swaps = _unencrypted_swaps(swaps_text, nodes, dm_uuids)
    cmdline = read_text(cmdline_path, "") or ""

    details = [
        f"Root device: {_devpath(root.get('name'))} "
        f"type={root.get('type') or 'unknown'} "
        f"fstype={root.get('fstype') or 'unknown'} "
        f"size={root.get('size') or 'unknown'}"
    ]
    if encrypted:
        ver_label = f"LUKS{luks_version}" if luks_version else "LUKS"
        details.append(f"Root is encrypted ({ver_label}" + (f" on {luks_dev}" if luks_dev else "") + ").")
        dump_dev = luks_dev or _devpath(root.get("name"))
        details.append(
            "LUKS header not inspected (needs root). Run: "
            + _HEADER_DUMP.format(device=dump_dev)
        )
    else:
        details.append("No crypto_LUKS ancestor and no CRYPT-LUKS dm uuid on the root stack.")

    if "rd.luks.options" in cmdline and (
        "tpm2-device" in cmdline or "fido2-device" in cmdline
    ):
        details.append("unlock token configured on kernel cmdline")

    if tpm_dir.exists():
        version = (read_text(tpm_dir / "tpm_version_major") or "").strip()
        if version:
            details.append(f"TPM present (version {version})")
        else:
            details.append("TPM present (version unknown)")
    else:
        details.append("TPM not present")

    if virt:
        details.append(f"systemd-detect-virt reports {virt}")

    score = 15
    issues = []
    severities = []
    recs = []

    if not encrypted:
        if virt:
            issues.append(
                f"Root filesystem is not encrypted ({virt} guest; "
                "full-disk encryption is less critical on VMs and containers)"
            )
            score -= 5
            severities.append("low")
            recs.append(
                "Consider LUKS2 if this guest stores sensitive data; hypervisor "
                "or host encryption may already cover the disk."
            )
        else:
            issues.append("Root filesystem is not encrypted")
            score -= 15
            severities.append("high")
            recs.append(
                "Encrypt the system with LUKS2; see Arch wiki dm-crypt/Encrypting an entire system."
            )
    elif luks_version == 1:
        issues.append("Root is encrypted with LUKS1")
        score -= 5
        severities.append("medium")
        recs.append("Convert the volume to LUKS2 with cryptsetup convert --type luks2.")
        details.append("LUKS1 detected; LUKS2 is recommended.")

    for swap_name in bad_swaps:
        issues.append(f"Unencrypted swap: {swap_name}")
        score -= 3
        severities.append("medium")
        details.append(f"Unencrypted swap: {swap_name}")
        recs.append("Encrypt swap or use zram so hibernation and swap pages are not stored in the clear.")

    score = max(0, score)
    passed = not issues
    if passed:
        desc = (
            "Root filesystem is encrypted with LUKS2."
            if luks_version == 2 or (encrypted and luks_version != 1)
            else "Root filesystem encryption looks sound."
        )
        rec = None
    else:
        desc = "; ".join(issues) + "."
        rec = " ".join(dict.fromkeys(recs))
    return make_result(
        id="disk_encryption",
        category=CATEGORY,
        title="Disk Encryption",
        passed=passed,
        score=score,
        max_score=15,
        severity=_worst_severity(severities),
        description=desc,
        details=details,
        recommendation=rec,
        fix_cmd=None,
        refs=DISK_REFS,
        lane="fast",
    )


@register_check(
    FAST_CHECKS,
    check_id="boot_chain",
    category=CATEGORY,
    title="Boot Chain Integrity",
    max_score=5,
)
def check_boot_chain(
    *,
    efi_dir=None,
    run=None,
    preset_dir=None,
    lockdown_path=None,
):
    efi_dir = Path(efi_dir) if efi_dir else EFI_DIR
    run = run or run_cmd
    preset_dir = Path(preset_dir) if preset_dir else PRESET_DIR
    lockdown_path = Path(lockdown_path) if lockdown_path else LOCKDOWN_PATH
    if not efi_dir.exists():
        return _na(
            "boot_chain",
            "Boot Chain Integrity",
            5,
            "No EFI firmware; boot chain checks are not applicable.",
            [f"{efi_dir} is not present."],
            BOOT_REFS,
        )

    details = []
    score = 5
    issues = []
    severities = []
    recs = []

    uki = _preset_uses_uki(preset_dir)
    bootctl_list = run(["bootctl", "list", "--no-pager"], timeout=0.4)
    if not uki and bootctl_list.returncode not in (127, 124):
        uki = _bootctl_list_uses_uki(bootctl_list.stdout or "")
    if uki:
        details.append("Unified kernel image in use (mkinitcpio default_uki or bootctl Type #2).")
    else:
        issues.append("Not booting a unified kernel image")
        score -= 2
        severities.append("low")
        details.append("No default_uki preset and no Type #2 / Linux Boot Manager bootctl entry.")
        recs.append("Build and boot a UKI; see Arch wiki Unified kernel image.")

    mount, options = _esp_options(run)
    if mount is None:
        details.append("ESP permissions skipped (/boot and /efi are not separate mounts).")
    else:
        details.append(f"{mount} mount options: {options}")
        if not _ESP_RESTRICT.search(options.replace(" ", "")):
            issues.append(f"{mount} is mounted without root-only fmask/umask")
            score -= 2
            severities.append("medium")
            recs.append(f"Remount {mount} with fmask=0077,dmask=0077 so only root can read ESP files.")
        else:
            details.append(f"{mount} restricts file access with fmask/umask 0077.")

    lockdown_text = read_text(lockdown_path)
    secure, _, _ = _secure_boot_state(efi_dir, run)
    if lockdown_text is None:
        details.append("Kernel lockdown sysfs not present.")
    else:
        mode = _lockdown_current(lockdown_text)
        details.append(f"Kernel lockdown: {mode}")
        if mode == "none" and secure is True:
            issues.append("Kernel lockdown is none while Secure Boot is enabled")
            score -= 1
            severities.append("low")
            recs.append("Enable kernel lockdown (integrity) when using Secure Boot.")

    pacman = run(["pacman", "-Q", "limine"], timeout=0.4)
    if pacman.returncode == 0:
        pkg = (pacman.stdout or "").strip() or "limine"
        details.append(f"Bootloader package: {pkg}")
    elif pacman.returncode == 127:
        details.append("Bootloader package: pacman not available to query limine.")
    else:
        details.append("Bootloader package: limine is not installed.")

    score = max(0, score)
    passed = not issues
    if passed:
        desc = "UKI boot chain, ESP permissions, and kernel lockdown look sound."
        rec = None
    else:
        desc = "; ".join(issues) + "."
        rec = " ".join(dict.fromkeys(recs))
    return make_result(
        id="boot_chain",
        category=CATEGORY,
        title="Boot Chain Integrity",
        passed=passed,
        score=score,
        max_score=5,
        severity=_worst_severity(severities),
        description=desc,
        details=details,
        recommendation=rec,
        fix_cmd=None,
        refs=BOOT_REFS,
        lane="fast",
    )
