# OmaSecurity baseline (schemaVersion 2)

OmaSecurity scores a machine against this documented standard. The default
invocation is the **fast lane**: local files and process state only, no network,
target runtime under 150ms. Checks that are slower or that need the network
belong in the **slow lane**, run with `--slow` (the panel does this 10s after
load, then hourly), and are cached for two hours under
`$XDG_CACHE_HOME/omasecurity`.

## Score

`score = round(100 * sum(score) / sum(max_score))` over **applicable** checks
only. Not-applicable checks (`applicable: false`) are excluded from the score
and from `failedCount`. A check that raises is recorded in `errors`, marked
not-applicable, and also excluded.

Grades: **A** ≥ 90 (System Hardened), **B** ≥ 75 (Good Security),
**C** ≥ 60 (Warnings Detected), **F** below 60 (Critical Action Required).

## Not applicable

If the machine cannot have the feature (no EFI, no LUKS, no TPM, tool not
installed, no `~/.ssh`), the check returns `applicable: false` with a one-line
reason. Never fail a check for something the machine cannot have.

## Lanes

| Lane | When it runs | Network |
| :--- | :--- | :--- |
| `fast` | Every default scan | Never |
| `slow` | `--slow`, then cache | Allowed only here |

Uncached slow checks appear as pending N/A: "Not collected yet; runs in the background hourly".

## Exit codes

The default invocation **always exits 0** (the QML panel calls it this way).
With `--strict`:

| Code | Meaning |
| ---: | :--- |
| 0 | All applicable checks passed, no errors, no baseline regressions |
| 1 | An applicable check failed, or `--baseline` reported a regression |
| 2 | `errors` is non-empty (a check raised, or baseline file unreadable) |

The engine never calls `sudo`. Facts that need root are reported as unknown,
with the exact manual command in `details`.

---

## Checks

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| `plugins_deep` | Plugin Health | 25 | Static scan of `~/.config/omarchy/plugins` (this plugin's own tree is excluded) for pipe-to-shell, obfuscated exec, hardcoded keys/tokens, credential paths, and sudo/pkexec | No rule matches in scanned files | A compromised plugin runs inside the shell with the user's session | The plugins directory exists and contains at least one other plugin | fast | [Arch wiki: Security](https://wiki.archlinux.org/title/Security) |
| `firewall` | Network | 15 | `systemctl is-active` for ufw/nftables/firewalld/iptables, plus readable `/etc/ufw/ufw.conf` `ENABLED=yes` | At least one backend is active or UFW is enabled in its config | Unfiltered inbound ports expose services | Always (a host can run a firewall) | fast | [UFW](https://wiki.archlinux.org/title/Uncomplicated_Firewall), [nftables](https://wiki.archlinux.org/title/Nftables) |
| `kernel_hardening` | System Security | 15 | `yama.ptrace_scope`, `dmesg_restrict`, `kptr_restrict`, `mitigations=off` in `/proc/cmdline`, and `/sys/devices/system/cpu/vulnerabilities/*` starting with `Vulnerable` | All present sysctls ≥ 1, cmdline does not disable mitigations, no Vulnerable files | Weak isolation leaks credentials and eases kernel exploits | `/proc` sysctls, cmdline, or CPU vuln sysfs exist | fast | [kernel sysctl](https://docs.kernel.org/admin-guide/sysctl/kernel.html), [kernel parameters](https://docs.kernel.org/admin-guide/kernel-parameters.html), [hw-vuln](https://docs.kernel.org/admin-guide/hw-vuln/index.html), [Arch wiki: Security](https://wiki.archlinux.org/title/Security) |
| `privileges_path` | Authentication | 15 | `$PATH` has no `.` / empty / world-writable entries. NOPASSWD sudo is **not** auto-probed | PATH is clean | `.` in PATH enables binary hijacking | Always (PATH exists) | fast | [Sudo](https://wiki.archlinux.org/title/Sudo), [sudoers(5)](https://man.archlinux.org/man/sudoers.5) |
| `ssh_gpg_perms` | Authentication | 15 | `~/.ssh` is 700, private keys (`id_*`, `*.pem`) are 600, `~/.gnupg` is 700. Names and modes only | Modes are at least that strict | Group/world-readable keys are stolen credentials | `~/.ssh` or `~/.gnupg` exists | fast | [SSH keys](https://wiki.archlinux.org/title/SSH_keys), [GnuPG](https://wiki.archlinux.org/title/GnuPG) |
| `desktop_lock` | Desktop Security | 10 | hypridle `listener` blocks with `timeout > 0` and `on-timeout` containing `hyprlock`, `loginctl lock-session`, or `omarchy-lock-screen`; or `shell.json` `idle.lock > 0` | At least one lock source is configured | An unlocked session is full account compromise | `hypridle.conf` or `shell.json` exists | fast | [hypridle](https://wiki.hypr.land/Hypr-Ecosystem/hypridle/) |
| `network_ports` | Network | 5 | TCP LISTEN sockets from `ss -tlnH` bound to wildcard addresses; `PermitRootLogin` in `sshd_config`. UDP from `ss -ulnH` is details-only | ≤ 6 public TCP listeners and PermitRootLogin is not `yes` | Public listeners and root SSH are the remote attack surface | `ss` is available or `sshd_config` exists | fast | [ss(8)](https://man.archlinux.org/man/ss.8), [sshd_config(5)](https://man.archlinux.org/man/sshd_config.5) |

`privileges_path` reports NOPASSWD as unknown. Confirm by hand with
`sudo -l | grep NOPASSWD` (never from the scanner: `sudo -n` journals
"a password is required" on every scan).

---

## Future categories

Other agents append rows under their section. Do not remove the placeholder
row until the real check exists.

### Agent Surface

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| _placeholder_ | Agent Surface | — | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | slow? | — |

### Packages

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| _placeholder_ | Packages | — | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | slow? | — |

### Boot & Disk

VM and container guests that lack LUKS still **fail** `disk_encryption`, but the finding is severity **low** and only deducts 5 of 15: the virtual disk is often already encrypted by the host or is disposable, so missing guest LUKS is less severe than an unencrypted laptop.

LUKS header parameters (PBKDF, cipher, keyslot count, TPM2/FIDO2 tokens) need root and are **not** probed. The check prints the exact `cryptsetup luksDump` command instead.

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| `secure_boot` | Boot & Disk | 10 | EFI Secure Boot and Setup Mode from efivars (`SecureBoot-` / `SetupMode-` GUID `8be4df61-93ca-11d2-aa0d-00e098032b8c`, value at byte 4); `bootctl status` fallback; optional `sbctl status` details | Secure Boot enabled and setup mode off. Disabled deducts 7 (HIGH); setup mode on deducts 3 (HIGH). No `fix_cmd` (wrong key enrollment can brick firmware) | Unsigned bootloaders and kernels can be replaced on the ESP | `/sys/firmware/efi` exists | fast | [UEFI/Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot), [sbctl](https://github.com/Foxboron/sbctl) |
| `disk_encryption` | Boot & Disk | 15 | `lsblk -J` walk from `/` for `crypto_LUKS` ancestors; `/sys/block/dm-*/dm/uuid` `CRYPT-LUKS1/2`; unencrypted swap from `/proc/swaps` (zram skipped); TPM sysfs as details; `rd.luks.options` tpm2/fido2 tokens on the cmdline | LUKS2 root and no unencrypted disk/file swap. Unencrypted root: HIGH −15, or LOW −5 in a VM/container. LUKS1: MEDIUM −5. Unencrypted swap: MEDIUM −3 each | An unlocked disk is readable if the machine is stolen or the guest image is copied | `lsblk` is installed and a device is mounted at `/` | fast | [dm-crypt/Encrypting an entire system](https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system) |
| `boot_chain` | Boot & Disk | 5 | UKI via `default_uki` in `/etc/mkinitcpio.d/*.preset` or `bootctl list` Type #2 / Linux Boot Manager; ESP `findmnt` fmask/umask 0077 on `/boot` or `/efi`; kernel lockdown vs Secure Boot; `pacman -Q limine` as details | UKI in use (else LOW −2); ESP root-only if separately mounted (else MEDIUM −2); lockdown is not `[none]` while Secure Boot is on (else LOW −1) | A split kernel+initramfs on an unsigned ESP is tamperable; world-readable ESP leaks UKIs | `/sys/firmware/efi` exists | fast | [Unified kernel image](https://wiki.archlinux.org/title/Unified_kernel_image), [kernel lockdown](https://docs.kernel.org/security/lockdown.html), [UEFI/Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot) |

### Services

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| _placeholder_ | Services | — | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | fast? | — |
