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
| `privileges_path` | Authentication | 8 | `$PATH` has no `.` / empty / world-writable entries. NOPASSWD sudo is **not** auto-probed | PATH is clean | `.` in PATH enables binary hijacking | Always (PATH exists) | fast | [Sudo](https://wiki.archlinux.org/title/Sudo), [sudoers(5)](https://man.archlinux.org/man/sudoers.5) |
| `lsm_status` | System Security | 5 | `/sys/kernel/security/lsm` contains `yama` and `landlock`; lockdown mode and hardened kernel flavour in details. AppArmor is scored only if the package is installed | Yama and Landlock are loaded. Missing either is MEDIUM (−2 each). Installed AppArmor inactive or not in the LSM list is MEDIUM (−1). AppArmor is optional on Omarchy: not installed is details-only, no penalty. Never reads `/sys/kernel/security/apparmor/profiles` (needs root) | LSMs constrain ptrace, filesystem access, and (if enabled) MAC policy. Stock Omarchy does not enable AppArmor, so penalising every install would be wrong | `/sys/kernel/security/lsm` is readable | fast | [Kernel hardening](https://wiki.archlinux.org/title/Security#Kernel_hardening), [Mandatory access control](https://wiki.archlinux.org/title/Security#Mandatory_access_control), [AppArmor](https://wiki.archlinux.org/title/AppArmor), [LSM](https://docs.kernel.org/admin-guide/lsm/index.html) |
| `audit_framework` | System Security | 3 | `auditd` active state; count of readable files in `/etc/audit/rules.d`. Does not run `auditctl -l` (needs root). Omarchy ships no audit rules | `auditd` is active. Inactive is MEDIUM (−3). Unreadable `rules.d` is details-only with `sudo auditctl -l` | auditd records security-relevant syscalls; an inactive daemon collects nothing | `pacman -Qi audit` reports `Install Reason : Explicitly installed`, or `systemctl is-enabled auditd` is enabled. A dependency-only install with auditd not enabled is N/A | fast | [Audit framework](https://wiki.archlinux.org/title/Audit_framework) |
| `ssh_gpg_perms` | Authentication | 15 | `~/.ssh` is 700, private keys (`id_*`, `*.pem`) are 600, `~/.gnupg` is 700. Names and modes only | Modes are at least that strict | Group/world-readable keys are stolen credentials | `~/.ssh` or `~/.gnupg` exists | fast | [SSH keys](https://wiki.archlinux.org/title/SSH_keys), [GnuPG](https://wiki.archlinux.org/title/GnuPG) |
| `desktop_lock` | Desktop Security | 10 | hypridle `listener` blocks with `timeout > 0` and `on-timeout` containing `hyprlock`, `loginctl lock-session`, or `omarchy-lock-screen`; or `shell.json` `idle.lock > 0` | At least one lock source is configured | An unlocked session is full account compromise | `hypridle.conf` or `shell.json` exists | fast | [hypridle](https://wiki.hypr.land/Hypr-Ecosystem/hypridle/) |
| `network_ports` | Network | 5 | TCP LISTEN sockets from `ss -tlnH` bound to wildcard addresses; `PermitRootLogin` in `sshd_config`. UDP from `ss -ulnH` is details-only | ≤ 6 public TCP listeners and PermitRootLogin is not `yes` | Public listeners and root SSH are the remote attack surface | `ss` is available or `sshd_config` exists | fast | [ss(8)](https://man.archlinux.org/man/ss.8), [sshd_config(5)](https://man.archlinux.org/man/sshd_config.5) |

`privileges_path` reports NOPASSWD as unknown. Confirm by hand with
`sudo -l | grep NOPASSWD` (never from the scanner: `sudo -n` journals
"a password is required" on every scan).

---

## Additional categories

Checks added after the original seven live under their own category headings below and follow the same table columns.

### Agent Surface

Omarchy's migration
[`migrations/1786539345.sh`](https://github.com/omacom/omarchy/blob/quattro/migrations/1786539345.sh)
symlinks shipped skills into `~/.agents/skills`, `~/.claude/skills`,
`~/.codex/skills`, and `~/.pi/agent/skills`.
[`omarchy-agent`](https://github.com/omacom/omarchy/blob/quattro/bin/omarchy-agent)
then launches the default agent with approval prompts disabled
(`claude --permission-mode auto`, `opencode --auto`, `gemini --yolo`,
`copilot --allow-all`, `crush --yolo`). Anything in those trees is loaded
into an unattended agent.

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| `agent_skills` | Agent Surface | 15 | Top-level skills under `~/.agents/skills`, `~/.claude/skills`, `~/.codex/skills`, `~/.pi/agent/skills`, `~/.cursor/skills-cursor`, `~/.claude/commands`, `~/.claude/agents`, `~/.claude/plugins/marketplaces`. Marketplace plugins are inventoried as individual entries. Classifies Omarchy-shipped, vendor-shipped (`~/.cursor/skills-cursor`, `~/.codex/skills/.system`), third-party, and outside-home/broken symlinks. Scans by file class (scripts, instruction markdown, configs; skips README/CHANGELOG/LICENSE and `references/`/`examples/`/`docs/`). Flags auto-approve next to an agent binary, pipe-to-shell, sensitive writes, insecure fetch, and obfuscated exec (MEDIUM heuristic in scripts). Prompt-injection notes are LOW with no deduction, and are suppressed when the phrase is quoted as an example or the line carries defensive wording. Score caps at 2 hits per severity (CRITICAL 6, HIGH 3, MEDIUM 1) | No broken/outside symlinks and no CRITICAL/HIGH/MEDIUM scan hits | Unattended agents load every skill in those directories | At least one skill root exists | slow | [1786539345.sh](https://github.com/omacom/omarchy/blob/quattro/migrations/1786539345.sh), [omarchy-agent](https://github.com/omacom/omarchy/blob/quattro/bin/omarchy-agent) |
| `agent_mcp` | Agent Surface | 10 | MCP servers in `~/.claude.json`, Claude/Cursor/Gemini/OpenCode/Copilot settings, `~/.codex/config.toml`; unpinned `npx`/`uvx`/`bunx`/`pipx run`; credential-like env keys (names only); non-https remote URLs; `permissions.allow` Bash/`*`; `enableAllProjectMcpServers`; hooks vs `DEFAULT_RULES`. Details include the default agent and `omarchy-agent` auto-approve flag | No HIGH/MEDIUM findings | MCP servers and auto-approve launches run with the user's credentials | At least one of the listed config files exists | fast | [omarchy-agent](https://github.com/omacom/omarchy/blob/quattro/bin/omarchy-agent) |

### Packages

Omarchy's shipped default `/usr/share/omarchy/default/pacman/pacman-stable.conf`
leaves every repo at the global `SigLevel = Required DatabaseOptional`. A
machine that sets `TrustAll` or `Optional` on a network repo (including the
`[omarchy]` / `[try-omarchy]` repos) is below that baseline. The Omarchy
signing key `40DFB630FF42BCFFB047046CF0134EE680CAC571` is expected because
`/usr/share/omarchy/bin/omarchy-update-keyring` installs it with
`omarchy-keyring`. These checks never run `pacman -Sy`, `yay`, or any command
that writes.

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| `pacman_trust` | Packages | 10 | Per-repo effective `SigLevel` from `/etc/pacman.conf` (repo override, else `[options]`; `Include` under `/etc/pacman.d` is followed only for SigLevel/Server). Network repos (Server is not `file://`) must not use `TrustAll`, `Never`, or package-level `Optional`. `[options]` itself must not be weaker than `Required DatabaseOptional` | No weak SigLevel on a network repo; `[options]` meets the shipped default | Unsigned or optionally-signed packages from the network are a supply-chain bypass | `/etc/pacman.conf` is readable | fast | [pacman.conf SigLevel](https://man.archlinux.org/man/pacman.conf.5#PACKAGE_AND_DATABASE_SIGNATURE_CHECKING), [Package signing](https://wiki.archlinux.org/title/Pacman/Package_signing) |
| `pacman_keyring` | Packages | 5 | `pacman -Q` for `archlinux-keyring`, `omarchy-keyring`, and `archlinuxarm-keyring` if present. Omarchy key listed via `pacman-key --list-keys` when that finishes unprivileged in under 150ms, else `gpg --homedir /etc/pacman.d/gnupg --list-keys` | Keyring packages present; Omarchy key present when `[omarchy]` is configured. Listing timeouts are unknown (no deduction) | A missing Omarchy key while that repo is enabled means packages from it cannot be authenticated | `pacman` is installed | fast | [Package signing](https://wiki.archlinux.org/title/Pacman/Package_signing), `/usr/share/omarchy/bin/omarchy-update-keyring` |
| `pacman_updates` | Packages | 5 | Last 64KB of `/var/log/pacman.log` for the newest `starting full system upgrade` line | Upgrade within 14 days. 14–30 days is medium (−3); over 30 days is high (−5). No line: unknown, no deduction | Stale systems miss Arch Security Team fixes | `/var/log/pacman.log` is readable | fast | [System maintenance](https://wiki.archlinux.org/title/System_maintenance#Upgrading_the_system) |
| `pacman_inventory` | Packages | 5 | Local `pacman -Qq`, one `pacman -Sl` (all repos, grouped by first column), and `pacman -Qmq` (no sync). Details: per-repo installed counts once, up to 20 foreign names | Foreign count ≤ 25. Foreign packages alone are not a finding | More than 25 unsigned local/AUR builds widen the supply chain | `pacman` is installed | slow | [pacman](https://wiki.archlinux.org/title/Pacman) |
| `arch_audit` | Packages | 10 | If `arch-audit` is installed, run it with the JSON or `--format` flag discovered from `--help` (20s timeout) and count vulnerable packages by severity | No advisories. Critical/High −6, Medium-only −3, Low-only −1. Missing tool or network failure is N/A (no penalty) | Known CVEs in installed packages are the actionable end of the supply chain | `arch-audit` is installed and the advisory fetch succeeds | slow | [Arch Security Team](https://wiki.archlinux.org/title/Arch_Security_Team), extra repo `arch-audit` |

### Boot & Disk

VM and container guests that lack LUKS still **fail** `disk_encryption`, but the finding is severity **low** and only deducts 5 of 15: the virtual disk is often already encrypted by the host or is disposable, so missing guest LUKS is less severe than an unencrypted laptop.

LUKS header parameters (PBKDF, cipher, keyslot count, TPM2/FIDO2 tokens) need root and are **not** probed. The check prints the exact `cryptsetup luksDump` command instead.

The ESP `fmask`/`umask` 0077 finding is **provisional** (not yet confirmed against a real Omarchy ESP). It is severity LOW and deducts 1; observed mount options are listed in `details`.

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| `secure_boot` | Boot & Disk | 10 | EFI Secure Boot and Setup Mode from efivars (`SecureBoot-` / `SetupMode-` GUID `8be4df61-93ca-11d2-aa0d-00e098032b8c`, value at byte 4); `bootctl status` fallback; optional `sbctl status` details | Secure Boot enabled and setup mode off. Disabled deducts 7 (HIGH); setup mode on deducts 3 (HIGH). No `fix_cmd` (wrong key enrollment can brick firmware) | Unsigned bootloaders and kernels can be replaced on the ESP | `/sys/firmware/efi` exists | fast | [UEFI/Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot), [sbctl](https://github.com/Foxboron/sbctl) |
| `disk_encryption` | Boot & Disk | 15 | `lsblk -J` walk from `/` for `crypto_LUKS` ancestors; `/sys/block/dm-*/dm/uuid` `CRYPT-LUKS1/2`; unencrypted swap from `/proc/swaps` (zram skipped); TPM sysfs as details; `rd.luks.options` tpm2/fido2 tokens on the cmdline | LUKS2 root and no unencrypted disk/file swap. Unencrypted root: HIGH −15, or LOW −5 in a VM/container. LUKS1: MEDIUM −5. Unencrypted swap: MEDIUM −3 each | An unlocked disk is readable if the machine is stolen or the guest image is copied | `lsblk` is installed and a device is mounted at `/` | fast | [dm-crypt/Encrypting an entire system](https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system) |
| `boot_chain` | Boot & Disk | 5 | UKI via `default_uki` in `/etc/mkinitcpio.d/*.preset` or `bootctl list` Type #2 / Linux Boot Manager; ESP `findmnt` fmask/umask 0077 on `/boot` or `/efi`; kernel lockdown vs Secure Boot; `pacman -Q limine` as details | UKI in use (else LOW −2); ESP root-only if separately mounted (else LOW −1, provisional); lockdown is not `[none]` while Secure Boot is on (else LOW −1) | A split kernel+initramfs on an unsigned ESP is tamperable; world-readable ESP leaks UKIs | `/sys/firmware/efi` exists | fast | [Unified kernel image](https://wiki.archlinux.org/title/Unified_kernel_image), [kernel lockdown](https://docs.kernel.org/security/lockdown.html), [UEFI/Secure Boot](https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot) |

### Services

Stock Arch marks `udisks2` and `user@1000.service` as UNSAFE in `systemd-analyze security`. Those units do not face the network, so they are ignored. Only the candidate list below is scored. `systemd-analyze security` is unprivileged but ~170ms, so it is slow-lane.

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| `service_exposure` | Services | 10 | One `systemctl is-active` call for sshd, cups, avahi-daemon, smb, nmb, nfs-server, rpcbind, docker, libvirtd, tailscaled, syncthing, bluetooth, transmission, minidlna, plexmediaserver, jellyfin, nginx, httpd, caddy. Active units are scored with one `systemd-analyze security --no-pager` (`--json=short` when supported, otherwise the table) | No candidate is active, or every active candidate has exposure below 8.0. Active + exposure 8.0 or higher is MEDIUM (−2 each, floor 0). Timeout (10s) is N/A | Network-facing daemons with weak sandboxing are the remote attack surface | `systemctl` is available; `systemd-analyze` is available when any candidate is active | slow | [systemd-analyze security](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html) |
| `sshd_config` | Services | 5 | Effective `PasswordAuthentication`, `PermitRootLogin`, and `X11Forwarding` from `/etc/ssh/sshd_config` plus `sshd_config.d/*.conf` (first occurrence wins; drop-ins included at the top win). Unreadable files are skipped and named in details | PasswordAuthentication is explicitly `no` (unset defaults to yes: MEDIUM −2). PermitRootLogin is not `yes` (yes: HIGH −3). X11Forwarding is not `yes` (yes: LOW −1) | Password and root SSH are the usual brute-force path; X11 forwarding leaks the desktop | `systemctl is-enabled sshd` is enabled/enabled-runtime or `is-active` is active | fast | [OpenSSH](https://wiki.archlinux.org/title/OpenSSH), [sshd_config(5)](https://man.archlinux.org/man/sshd_config.5) |
| `user_services` | Services | 2 | Count of running user units from `systemctl --user list-units --type=service --state=running`. Each `~/.config/systemd/user/**/*.service` `ExecStart` is checked | No ExecStart path is under `/tmp`, `/var/tmp`, `/dev/shm`, or `~/Downloads`. A match is HIGH (−2) | User units that execute from world-writable locations are trivial persistence | User systemd (`systemctl --user`) is available | fast | [systemd/User](https://wiki.archlinux.org/title/Systemd/User) |
