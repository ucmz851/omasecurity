<h1 align="center">OmaSecurity</h1>

<p align="center">
  Security posture auditor, plugin code scanner, and agent-surface inventory for the Omarchy shell.
</p>

<p align="center">
  <a href="https://github.com/tcballard/omarchy-badges"><img alt="Built for Omarchy: Plugin" src="https://raw.githubusercontent.com/tcballard/omarchy-badges/75975e5b5bf75e7ede3764bcd2950046f7abfe2c/badges/v1/omarchy-plugin.svg"></a>
  <a href="#compatibility"><img alt="Supported Omarchy versions: 4.x" src="https://raw.githubusercontent.com/tcballard/omarchy-badges/8b0189738018961c1bd275d903dd37ceed6bf6ae/badges/v1/compatibility/omarchy-4.x.svg"></a>
</p>

<p align="center">
  <a href="manifest.json"><img alt="Version" src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fucmz851%2Fomasecurity%2Fmain%2Fmanifest.json&query=%24.version&label=version&color=2b3d4f"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2b3d4f"></a>
  <a href="scripts/audit.py"><img alt="Python 3, standard library only" src="https://img.shields.io/badge/python-3%20%C2%B7%20stdlib%20only-2b3d4f?logo=python&logoColor=white"></a>
  <a href="BASELINE.md"><img alt="Never calls sudo" src="https://img.shields.io/badge/sudo-never-2b3d4f"></a>
  <a href="BASELINE.md"><img alt="Fast lane under 150 ms" src="https://img.shields.io/badge/fast%20lane-%3C150%20ms-2b3d4f"></a>
</p>

<p align="center">
  <img src="preview.png" alt="OmaSecurity panel showing the security score, category tabs, and finding cards" width="420" />
</p>

**OmaSecurity** (`ucmz851.omasecurity`) is a zero-bloat security auditor for the Omarchy Quattro desktop (`omarchy-shell` / Quickshell). A shield in the bar shows your score at a glance. The panel breaks it into 22 checks across nine categories, each with a plain explanation, the evidence it used, and a copyable fix command where one is safe to give.

It never asks for root, never touches the network in the default scan, and documents every check and weight in [BASELINE.md](BASELINE.md).

---

## Install

```bash
omarchy plugin add https://github.com/ucmz851/omasecurity.git --enable
```

Remove it again with:

```bash
omarchy plugin remove ucmz851.omasecurity
```

---

## What it checks

Every check has an id, a weight, a pass condition, and references in [BASELINE.md](BASELINE.md). Checks that do not apply to a machine (no EFI, no LUKS, a tool not installed) are shown as **N/A** and left out of the score instead of failing it.

| Category | Checks | Points |
| :--- | :--- | ---: |
| Plugin Health | `plugins_deep` | 25 |
| System Security | `kernel_hardening`, `lsm_status`, `audit_framework` | 23 |
| Network | `firewall`, `network_ports` | 20 |
| Authentication | `privileges_path`, `ssh_gpg_perms` | 23 |
| Desktop Security | `desktop_lock` | 10 |
| Agent Surface | `agent_skills`, `agent_mcp` | 25 |
| Packages | `pacman_trust`, `pacman_keyring`, `pacman_updates`, `pacman_inventory`, `arch_audit` | 35 |
| Boot & Disk | `secure_boot`, `disk_encryption`, `boot_chain` | 30 |
| Services | `service_exposure`, `sshd_config`, `user_services` | 17 |

### Plugin Health
Scans every QML, JavaScript, Python, shell, JSON, and TOML file under `~/.config/omarchy/plugins/` (this plugin excludes itself by path and by manifest id):
- **Dangerous downloads:** `curl ... | sh` and `wget ... | bash`.
- **Dynamic or obfuscated code:** `eval()`, `new Function()`, base64 piped to a shell, in-memory byte execution.
- **Hardcoded secrets:** private key blocks, GitHub tokens, AWS access keys. Snippets for these are redacted.
- **Credential path access:** `~/.ssh/id_*`, `~/.gnupg/`, keyrings, browser profiles, `/etc/shadow`.
- **Privilege escalation:** `sudo`, `pkexec`, and `doas` inside user plugins.
- **Pinpoint reporting:** plugin, file, line, explanation, and the offending snippet.

### System Security
- **Kernel and memory:** `kernel.yama.ptrace_scope`, `kernel.dmesg_restrict`, `kernel.kptr_restrict`, `mitigations=off` on the kernel command line, and any CPU vulnerability sysfs entry that reports `Vulnerable`.
- **Linux Security Modules:** requires `yama` and `landlock` in `/sys/kernel/security/lsm`. Hardened kernel flavour and lockdown mode are reported. AppArmor is optional on Omarchy and only scored when installed.
- **Audit framework:** scored only when the `audit` package was installed on purpose or `auditd` is enabled. A dependency-only install is N/A.

### Network
- **Host firewall:** `ufw`, `nftables`, `firewalld`, or `iptables` active, or UFW enabled in its config. No sudo fallback.
- **Public listeners:** TCP sockets bound to `0.0.0.0` or `::`. UDP wildcard sockets are listed without penalty. `PermitRootLogin yes` in `sshd_config` is flagged.

### Authentication
- **PATH integrity:** no empty, relative, or world-writable entries. Passwordless sudo is not probed because a failed `sudo -n` writes to the journal; the manual command is shown instead.
- **Key permissions:** `700` on `~/.ssh` and `~/.gnupg`, `600` on private keys.

### Desktop Security
- **Idle lock:** a hypridle listener with a positive timeout that runs `hyprlock`, `loginctl lock-session`, or `omarchy-lock-screen`, or `idle.lock` in `shell.json`.

### Agent Surface
Omarchy links its shipped skills into `~/.agents/skills`, `~/.claude/skills`, `~/.codex/skills`, and `~/.pi/agent/skills`, then `omarchy-agent` launches the default agent with approval prompts disabled. Everything in those trees runs unattended, so it gets inventoried.
- **Skills inventory (`agent_skills`, slow lane):** counts Omarchy-shipped, vendor-shipped, and third-party skills across Claude, Codex, Cursor, Pi, and marketplace plugins. Scripts, instruction files, and configs each get their own rule set; README, CHANGELOG, LICENSE, and `references/`, `examples/`, `docs/` directories are skipped. Flags symlinks that leave `$HOME` and `/usr/share/omarchy`, broken links, auto-approve flags next to an agent binary, pipe-to-shell, writes to `~/.ssh`, shell rc files, Omarchy hooks, or `/etc`, and downloads over HTTP or from a bare IP. Prompt-injection phrasing in markdown is reported as LOW with no deduction. At most two hits per severity count against the score.
- **MCP, hooks, and permissions (`agent_mcp`):** reads the Claude, Codex, Cursor, Gemini, OpenCode, and Copilot configs. Flags unpinned `npx`, `uvx`, `bunx`, and `pipx run` servers, credential-like env values (key names only, never values), non-https remote URLs, unrestricted `Bash` permission allowlists, and `enableAllProjectMcpServers`. Reports the default agent and the auto-approve flag it is launched with.

### Packages
- **Repository trust:** parses `/etc/pacman.conf` and `/etc/pacman.d` overrides. Network repos with `TrustAll`, `Never`, or package-level `Optional` are flagged. Omarchy ships `Required DatabaseOptional`.
- **Keyrings:** `archlinux-keyring` and `omarchy-keyring` present, and the Omarchy signing key `40DFB630FF42BCFFB047046CF0134EE680CAC571` in the pacman keyring.
- **Update recency:** last full upgrade from `/var/log/pacman.log`. Over 14 days is medium, over 30 is high. Never runs `pacman -Sy`.
- **Inventory (slow lane):** per-repo and foreign package counts from the local database.
- **arch-audit (slow lane):** known CVEs in installed packages when `arch-audit` is installed. Missing tool or no network is N/A.

### Boot & Disk
- **UEFI Secure Boot:** state and setup mode from efivars, with a `bootctl status` fallback and `sbctl status` details when available. No one-click enroll command, because a bad key can brick firmware.
- **Disk encryption:** walks `lsblk` from `/` for LUKS, flags LUKS1, and treats unencrypted disk swap as medium (zram is fine). An unencrypted root inside a VM or container still fails, but as LOW. LUKS header parameters need root, so the exact `cryptsetup luksDump` command is shown instead.
- **Boot chain:** unified kernel image in use, ESP mount options, and kernel lockdown while Secure Boot is on. EFI-only checks are N/A on non-EFI machines.

### Services
- **Network-facing exposure (slow lane):** `systemd-analyze security` scores for active network daemons only (sshd, cups, avahi, docker, nginx, and similar). Units every Arch system marks unsafe but that do not face the network are ignored.
- **OpenSSH:** effective `PasswordAuthentication`, `PermitRootLogin`, and `X11Forwarding` across `sshd_config` and its drop-ins. Only applies when sshd is enabled or running.
- **User units:** `ExecStart` paths under `/tmp`, `/var/tmp`, `/dev/shm`, or `~/Downloads`.

---

## Panel and controls

- **Bar icon:** the shield (`󰒃`) tints by score and shows the score, status, and last scan time on hover.
- **Category tabs:** built from the results, so new categories get a tab automatically.
- **Cards:** pass, fail, or N/A badge, points, description, evidence lines, flagged plugin findings, recommendation, and a copyable fix command when one exists.
- **Two lanes:** the fast lane runs on open, on demand, and every 15 minutes with no network. Slow checks run in the background 10 seconds after load and hourly, and are cached for two hours.

| Action | How |
| :--- | :--- |
| Open or close the panel | Left-click the shield |
| Rescan now | Middle-click the shield, click the refresh icon, or press `R` |
| Move between cards | `Up` / `Down` |
| Copy the fix command | `Enter` / `Space`, or click the command box |
| Filter by category | Click a tab: All, Plugins, System, Network, Auth, Desktop, Agents, Packages, Boot, Services |
| Close | `Escape` |

---

## Headless and CI usage

The panel runs `python3 scripts/audit.py` with no flags and always gets exit code 0. The same script works from a terminal, a cron job, or CI:

```bash
python3 scripts/audit.py --format text
python3 scripts/audit.py --list
python3 scripts/audit.py --only firewall,kernel_hardening --format text
python3 scripts/audit.py --skip plugins_deep
python3 scripts/audit.py --slow                  # run slow checks now and refresh the cache
python3 scripts/audit.py --no-cache              # ignore cached slow results
python3 scripts/audit.py --baseline previous.json --strict
```

| Flag | Effect |
| :--- | :--- |
| `--format json\|text` | JSON (default) or a score table with one line per check |
| `--only ID[,ID]` | Run only these check ids |
| `--skip ID[,ID]` | Skip these check ids |
| `--list` | Print `id`, `category`, `lane`, `max_score` and exit |
| `--slow` | Run slow-lane checks, write `$XDG_CACHE_HOME/omasecurity`, then print |
| `--no-cache` | Ignore cached slow results (they show as pending N/A unless `--slow`) |
| `--baseline PATH` | Fill `baselineDiff` with `regressed`, `improved`, and `scoreDelta` against a previous JSON output |
| `--strict` | Exit `1` if an applicable check failed or a baseline id regressed, `2` if any check raised |

Example text output:

```
OmaSecurity 2.0.0  score=72  grade=C  Warnings Detected
omarchy  14:29:16  checks=22  failed=6  n/a=6

FAIL  plugins_deep         Plugin Health        fast   22/25  Scanned 3 plugins (16 files): 1 risk(s) flagged ...
FAIL  firewall             Network              fast    0/15  No active host firewall detected ...
PASS  lsm_status           System Security      fast     5/5  Yama and Landlock are present in the LSM list.
N/A   secure_boot          Boot & Disk          fast    0/10  No EFI firmware; Secure Boot is not applicable.
```

Every JSON document carries `schemaVersion: 2`, `tool`, `version`, `hostname`, `timestamp`, `score`, `grade`, `audits[]`, `errors[]`, and `baselineDiff`. Each audit carries `id`, `category`, `passed`, `applicable`, `score`, `max_score`, `severity`, `description`, `details[]`, `recommendation`, `fix_cmd`, `refs[]`, and `lane`. A check that raises is recorded in `errors` and excluded from the score rather than counted as a pass.

---

## Compatibility

- **Supported Omarchy versions:** 4.x, matching the badge above. This is a maintainer-declared range, not a certification.
- **Last tested:** Omarchy 4.0.2 (try-omarchy runtime on Arch Linux ARM, Apple Silicon virtual machine), 16 September 2026.
- **Checks performed:** full unit test suite, fast lane under 150 ms, no sudo journal entries, panel loaded and exercised in the running shell.
- **Known limitations:** the Boot & Disk checks, the ESP mount-option finding, and the LSM list on the stock x86 kernel have only been exercised through test fixtures and their not-applicable paths on the ARM virtual machine. Real x86 hardware with LUKS, limine, and a UKI has not been tested yet.

---

## File structure

```
omasecurity/
├── BarWidget.qml        # Bar icon, colour tint, tooltip
├── Panel.qml            # Flyout panel: score, tabs, cards, fast and slow scan processes
├── manifest.json        # Omarchy plugin manifest (id: ucmz851.omasecurity)
├── BASELINE.md          # Scoring contract, lanes, exit codes, and the check catalog
├── README.md
├── LICENSE              # MIT
├── preview.png          # Marketplace preview
├── screenshots/
└── scripts/
    ├── audit.py         # Runner: CLI flags, scoring, JSON and text output
    ├── checks/
    │   ├── __init__.py  # Result contract, registries, run_cmd (refuses sudo)
    │   ├── registry.py  # One import line per check module
    │   ├── cache.py     # Slow-lane cache under $XDG_CACHE_HOME/omasecurity
    │   ├── static_scan.py
    │   ├── plugins.py
    │   ├── firewall.py
    │   ├── kernel.py
    │   ├── lsm.py
    │   ├── privileges.py
    │   ├── keys.py
    │   ├── desktop.py
    │   ├── network.py
    │   ├── agents.py
    │   ├── packages.py
    │   ├── boot.py
    │   └── services.py
    └── tests/           # Unit tests using fixtures and patched subprocess output
```

---

## License

MIT © [ucmz851](https://github.com/ucmz851)
