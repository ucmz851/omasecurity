"""Unit tests for Boot & Disk checks (fake files + patched subprocess)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from checks.boot import (  # noqa: E402
    SECURE_BOOT_VAR,
    SETUP_MODE_VAR,
    check_boot_chain,
    check_disk_encryption,
    check_secure_boot,
)

EFI_ATTR = bytes([0x07, 0x00, 0x00, 0x00])

LSBLK_LUKS2_ZRAM = {
    "blockdevices": [
        {
            "name": "nvme0n1",
            "type": "disk",
            "fstype": None,
            "fsver": None,
            "mountpoints": [None],
            "size": "476.9G",
            "children": [
                {
                    "name": "nvme0n1p1",
                    "type": "part",
                    "fstype": "vfat",
                    "fsver": "FAT32",
                    "mountpoints": ["/boot"],
                    "size": "2G",
                },
                {
                    "name": "nvme0n1p2",
                    "type": "part",
                    "fstype": "crypto_LUKS",
                    "fsver": "2",
                    "mountpoints": [None],
                    "size": "474G",
                    "children": [
                        {
                            "name": "root",
                            "type": "crypt",
                            "fstype": "btrfs",
                            "fsver": None,
                            "mountpoints": ["/"],
                            "size": "474G",
                        }
                    ],
                },
            ],
        },
        {
            "name": "zram0",
            "type": "disk",
            "fstype": None,
            "fsver": None,
            "mountpoints": ["[SWAP]"],
            "size": "8G",
        },
    ]
}

LSBLK_LUKS1_SWAP = {
    "blockdevices": [
        {
            "name": "sda",
            "type": "disk",
            "fstype": None,
            "fsver": None,
            "mountpoints": [None],
            "size": "100G",
            "children": [
                {
                    "name": "sda1",
                    "type": "part",
                    "fstype": "crypto_LUKS",
                    "fsver": "1",
                    "mountpoints": [None],
                    "size": "96G",
                    "children": [
                        {
                            "name": "root",
                            "type": "crypt",
                            "fstype": "ext4",
                            "mountpoints": ["/"],
                            "size": "96G",
                        }
                    ],
                },
                {
                    "name": "sda2",
                    "type": "part",
                    "fstype": "swap",
                    "fsver": None,
                    "mountpoints": ["[SWAP]"],
                    "size": "4G",
                },
            ],
        }
    ]
}

LSBLK_EXT4 = {
    "blockdevices": [
        {
            "name": "vda",
            "type": "disk",
            "fstype": None,
            "fsver": None,
            "mountpoints": [None],
            "size": "20G",
            "children": [
                {
                    "name": "vda1",
                    "type": "part",
                    "fstype": "ext4",
                    "fsver": "1.0",
                    "mountpoints": ["/"],
                    "size": "20G",
                }
            ],
        }
    ]
}

SWAPS_ZRAM = (
    "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
    "/dev/zram0                              partition\t8388604\t0\t100\n"
)

SWAPS_PARTITION = (
    "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
    "/dev/sda2                               partition\t4194304\t0\t-2\n"
)

SWAPS_NONE = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"

BOOTCTL_STATUS_ENABLED = """\
System:
      Firmware: UEFI 2.80
   Secure Boot: enabled (user)
    Setup Mode: disabled
"""

BOOTCTL_STATUS_DISABLED = """\
System:
      Firmware: UEFI 2.80
   Secure Boot: disabled (setup)
    Setup Mode: enabled
"""

BOOTCTL_LIST_UKI = """\
Boot Loader Entries:
         type: Boot Loader Specification Type #2 (.efi)
        title: Linux Boot Manager
     filename: /EFI/Linux/omarchy.efi
"""

BOOTCTL_LIST_TYPE1 = """\
Boot Loader Entries:
         type: Boot Loader Specification Type #1 (.conf)
        title: Arch Linux
     filename: arch.conf
"""


def _proc(argv, rc, stdout=""):
    return subprocess.CompletedProcess(list(argv), rc, stdout=stdout, stderr="")


def fake_run(mapping, default_rc=127):
    calls = []

    def run(argv, timeout=1.0):
        argv = list(argv)
        calls.append(argv)
        if any(os.path.basename(str(part)) == "sudo" for part in argv):
            raise AssertionError("sudo invoked: %r" % argv)
        for prefix, payload in mapping.items():
            if tuple(argv[: len(prefix)]) == tuple(prefix):
                if isinstance(payload, tuple):
                    rc, out = payload
                else:
                    rc, out = 0, payload
                return _proc(argv, rc, out)
        return _proc(argv, default_rc, "")

    run.calls = calls
    return run


def _write_efivar(efi_dir, name, value):
    efivars = Path(efi_dir) / "efivars"
    efivars.mkdir(parents=True, exist_ok=True)
    (efivars / name).write_bytes(EFI_ATTR + bytes([value]))


def _lsblk_run(tree, virt="none", virt_rc=1, extra=None):
    mapping = {
        ("lsblk",): json.dumps(tree),
        ("systemd-detect-virt",): (virt_rc, virt + "\n"),
    }
    if extra:
        mapping.update(extra)
    return fake_run(mapping)


class SecureBootTests(unittest.TestCase):
    def test_not_applicable_without_efi(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "no-efi"
            result = check_secure_boot(efi_dir=missing, run=fake_run({}))
        self.assertFalse(result["applicable"])
        self.assertEqual(result["id"], "secure_boot")
        self.assertEqual(result["severity"], "info")
        self.assertEqual(result["max_score"], 10)
        self.assertIn("No EFI firmware", result["description"])

    def test_enabled_efivar(self):
        with tempfile.TemporaryDirectory() as tmp:
            efi = Path(tmp) / "efi"
            _write_efivar(efi, SECURE_BOOT_VAR, 1)
            _write_efivar(efi, SETUP_MODE_VAR, 0)
            result = check_secure_boot(efi_dir=efi, run=fake_run({}))
        self.assertTrue(result["applicable"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], 10)
        self.assertEqual(result["severity"], "info")
        self.assertIsNone(result["fix_cmd"])

    def test_disabled_efivar_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            efi = Path(tmp) / "efi"
            efi.mkdir()
            _write_efivar(efi, SECURE_BOOT_VAR, 0)
            _write_efivar(efi, SETUP_MODE_VAR, 0)
            result = check_secure_boot(efi_dir=efi, run=fake_run({}))
        self.assertTrue(result["applicable"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 3)
        self.assertEqual(result["severity"], "high")
        self.assertIsNone(result["fix_cmd"])
        self.assertTrue(any("wiki.archlinux.org" in url for url in result["refs"]))

    def test_setup_mode_on_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            efi = Path(tmp) / "efi"
            _write_efivar(efi, SECURE_BOOT_VAR, 1)
            _write_efivar(efi, SETUP_MODE_VAR, 1)
            result = check_secure_boot(efi_dir=efi, run=fake_run({}))
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 7)
        self.assertEqual(result["severity"], "high")
        self.assertIn("setup mode", result["description"].lower())

    def test_disabled_and_setup_mode_zero_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            efi = Path(tmp) / "efi"
            _write_efivar(efi, SECURE_BOOT_VAR, 0)
            _write_efivar(efi, SETUP_MODE_VAR, 1)
            result = check_secure_boot(efi_dir=efi, run=fake_run({}))
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["severity"], "high")

    def test_bootctl_fallback_and_sbctl_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            efi = Path(tmp) / "efi"
            efi.mkdir()
            (efi / "efivars").mkdir()
            run = fake_run(
                {
                    ("bootctl", "status"): BOOTCTL_STATUS_ENABLED,
                    ("sbctl", "status"): "Installed:\tsbctl is installed\nSecure Boot:\tEnabled\n",
                }
            )
            result = check_secure_boot(efi_dir=efi, run=run)
        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], 10)
        self.assertTrue(any("bootctl" in line.lower() for line in result["details"]))
        self.assertTrue(any("sbctl" in line.lower() for line in result["details"]))


class DiskEncryptionTests(unittest.TestCase):
    def _paths(self, tmp, swaps=SWAPS_NONE, cmdline="", tpm=False, tpm_ver="2"):
        root = Path(tmp)
        swaps_path = root / "swaps"
        cmdline_path = root / "cmdline"
        tpm_dir = root / "tpm0"
        sys_block = root / "block"
        swaps_path.write_text(swaps)
        cmdline_path.write_text(cmdline)
        sys_block.mkdir()
        if tpm:
            tpm_dir.mkdir()
            (tpm_dir / "tpm_version_major").write_text(tpm_ver + "\n")
        return {
            "swaps_path": swaps_path,
            "cmdline_path": cmdline_path,
            "tpm_dir": tpm_dir,
            "sys_block": sys_block,
        }

    def test_luks2_root_with_zram_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp, swaps=SWAPS_ZRAM, cmdline="rd.luks.options=tpm2-device=auto")
            result = check_disk_encryption(run=_lsblk_run(LSBLK_LUKS2_ZRAM), **paths)
        self.assertTrue(result["applicable"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], 15)
        self.assertEqual(result["severity"], "info")
        joined = " ".join(result["details"])
        self.assertIn("LUKS header not inspected (needs root).", joined)
        self.assertIn("sudo cryptsetup luksDump /dev/nvme0n1p2", joined)
        self.assertIn("unlock token configured on kernel cmdline", joined)
        self.assertIn("TPM not present", joined)
        self.assertNotIn("Unencrypted swap", joined)

    def test_luks1_root_with_unencrypted_swap(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp, swaps=SWAPS_PARTITION, tpm=True, tpm_ver="2")
            result = check_disk_encryption(
                run=_lsblk_run(LSBLK_LUKS1_SWAP, virt="none", virt_rc=1),
                **paths,
            )
        self.assertTrue(result["applicable"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 7)  # 15 - 5 LUKS1 - 3 swap
        self.assertEqual(result["severity"], "medium")
        self.assertIn("/dev/sda2", result["description"])
        self.assertTrue(any("TPM present (version 2)" in line for line in result["details"]))
        self.assertTrue(any("LUKS1" in line for line in result["details"]))

    def test_plain_ext4_bare_metal_fails_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp)
            result = check_disk_encryption(
                run=_lsblk_run(LSBLK_EXT4, virt="none", virt_rc=1),
                **paths,
            )
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["severity"], "high")
        self.assertIn("not encrypted", result["description"].lower())

    def test_plain_ext4_vm_fails_low(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp)
            result = check_disk_encryption(
                run=_lsblk_run(LSBLK_EXT4, virt="qemu", virt_rc=0),
                **paths,
            )
        self.assertFalse(result["passed"])
        self.assertTrue(result["applicable"])
        self.assertEqual(result["score"], 10)
        self.assertEqual(result["severity"], "low")
        self.assertIn("qemu", result["description"].lower())

    def test_lsblk_missing_is_not_applicable(self):
        result = check_disk_encryption(run=fake_run({}))
        self.assertFalse(result["applicable"])
        self.assertIn("lsblk", result["description"].lower())

    def test_never_invokes_sudo(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._paths(tmp, swaps=SWAPS_ZRAM)
            run = _lsblk_run(LSBLK_LUKS2_ZRAM)
            check_disk_encryption(run=run, **paths)
            for argv in run.calls:
                self.assertNotIn("sudo", argv)


class BootChainTests(unittest.TestCase):
    def test_not_applicable_without_efi(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "no-efi"
            result = check_boot_chain(efi_dir=missing, run=fake_run({}))
        self.assertFalse(result["applicable"])
        self.assertEqual(result["id"], "boot_chain")
        self.assertIn("No EFI firmware", result["description"])

    def test_uki_preset_and_restricted_esp_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            efi = Path(tmp) / "efi"
            _write_efivar(efi, SECURE_BOOT_VAR, 1)
            _write_efivar(efi, SETUP_MODE_VAR, 0)
            presets = Path(tmp) / "mkinitcpio.d"
            presets.mkdir()
            (presets / "linux.preset").write_text(
                "PRESETS=('default')\n"
                "default_uki=\"/boot/EFI/Linux/omarchy.efi\"\n"
            )
            lockdown = Path(tmp) / "lockdown"
            lockdown.write_text("[integrity] none confidentiality\n")
            run = fake_run(
                {
                    ("findmnt",): "/boot rw,relatime,fmask=0077,dmask=0077\n",
                    ("pacman", "-Q", "limine"): "limine 10.0.1-1\n",
                    ("bootctl", "list"): BOOTCTL_LIST_TYPE1,
                }
            )
            result = check_boot_chain(
                efi_dir=efi,
                run=run,
                preset_dir=presets,
                lockdown_path=lockdown,
            )
        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], 5)
        self.assertTrue(any("limine" in line.lower() for line in result["details"]))
        self.assertTrue(any("Unified kernel image" in line for line in result["details"]))

    def test_no_uki_open_esp_lockdown_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            efi = Path(tmp) / "efi"
            _write_efivar(efi, SECURE_BOOT_VAR, 1)
            _write_efivar(efi, SETUP_MODE_VAR, 0)
            presets = Path(tmp) / "mkinitcpio.d"
            presets.mkdir()
            (presets / "linux.preset").write_text(
                "# default_uki=\"/boot/EFI/Linux/omarchy.efi\"\n"
                "default_image=\"/boot/initramfs-linux.img\"\n"
            )
            lockdown = Path(tmp) / "lockdown"
            lockdown.write_text("[none] integrity confidentiality\n")
            run = fake_run(
                {
                    ("findmnt",): "/boot rw,relatime,fmask=0022,dmask=0022\n",
                    ("bootctl", "list"): BOOTCTL_LIST_TYPE1,
                    ("pacman", "-Q", "limine"): (1, ""),
                }
            )
            result = check_boot_chain(
                efi_dir=efi,
                run=run,
                preset_dir=presets,
                lockdown_path=lockdown,
            )
        self.assertFalse(result["passed"])
        self.assertEqual(result["score"], 0)  # 5 - 2 UKI - 2 ESP - 1 lockdown
        self.assertEqual(result["severity"], "medium")
        self.assertIn("unified kernel image", result["description"].lower())
        self.assertTrue(any("limine is not installed" in line for line in result["details"]))

    def test_uki_from_bootctl_type2(self):
        with tempfile.TemporaryDirectory() as tmp:
            efi = Path(tmp) / "efi"
            efi.mkdir()
            (efi / "efivars").mkdir()
            lockdown = Path(tmp) / "lockdown"
            lockdown.write_text("none [integrity] confidentiality\n")
            run = fake_run(
                {
                    ("bootctl", "list"): BOOTCTL_LIST_UKI,
                    ("bootctl", "status"): BOOTCTL_STATUS_ENABLED,
                    ("findmnt",): (1, ""),
                    ("pacman", "-Q", "limine"): "limine 9.0-1\n",
                }
            )
            result = check_boot_chain(
                efi_dir=efi,
                run=run,
                preset_dir=Path(tmp) / "missing-presets",
                lockdown_path=lockdown,
            )
        self.assertTrue(result["passed"])
        self.assertEqual(result["score"], 5)
        self.assertTrue(any("ESP permissions skipped" in line for line in result["details"]))


if __name__ == "__main__":
    unittest.main()
