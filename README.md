# OmaSecurity (`ucmz851.omasecurity`)

**OmaSecurity** is a lightweight, zero-bloat security posture auditor and deep plugin code health scanner designed specifically for the Omarchy Quattro desktop environment (`omarchy-shell` / Quickshell).

It provides continuous, glanceable security auditing on the status bar and expands into actionable recommendations with one-click copyable shell remediation commands.

---

## Installation

Install directly using the Omarchy plugin manager:

```bash
omarchy plugin add https://github.com/ucmz851/omasecurity.git --enable
```

---

## Core Security Capabilities

### 1. Deep Shell Plugin Code & Safety Analysis
Scans all installed QML, JavaScript, Python, Shell, and TOML files in `~/.config/omarchy/plugins/`:
- **Dangerous Downloads & Execution:** Detects unverified web piping (`curl ... | sh` / `wget ... | bash`).
- **Dynamic & Obfuscated Code:** Detects `eval()`, `new Function()`, base64 decoding piped to shell, and in-memory byte execution.
- **Hardcoded Secrets & Tokens:** Detects unencrypted private keys (`RSA`, `OPENSSH`, `EC`), GitHub Personal Access Tokens (`ghp_`), and cloud provider keys (`AKIA...`).
- **Protected Path Snooping:** Flags scripts attempting to access `~/.ssh/id_*`, `~/.gnupg/`, `~/.local/share/keyrings/`, browser profile data, or `/etc/shadow`.
- **Privilege Escalation (sudo/pkexec):** Flags unneeded root invocations inside user plugins.
- **Pinpoint Reporting:** Displays exact plugin name, relative file path, line number, risk explanation, and code snippet.

### 2. Linux Kernel & Memory Protections (Sysctl)
- **YAMA ptrace scope:** Verifies process memory inspection protections (`kernel.yama.ptrace_scope >= 1`) to stop unauthorized memory dumping of browser tokens or password managers.
- **Kernel Log Restrictions:** Verifies `kernel.dmesg_restrict` to prevent unprivileged users from reading kernel debug logs.
- **Kernel Symbol Hiding:** Checks `kernel.kptr_restrict` to prevent kernel exploit address targeting.

### 3. Privilege Boundaries & Execution Integrity
- **Sudoers Audit:** Detects dangerous `NOPASSWD: ALL` misconfigurations.
- **PATH Integrity:** Audits `$PATH` to ensure no relative directories (`.`) or world-writable directories are present that could allow binary hijacking.

### 4. Host Firewall & Exposure
- **Firewall State:** Audits `ufw`, `nftables`, or `firewalld` active states.
- **Listening Ports:** Audits public listeners bound to `0.0.0.0` or `::` vs localhost (`127.0.0.1`).
- **SSH Hardening:** Verifies `PermitRootLogin` settings in `/etc/ssh/sshd_config`.

### 5. Authentication & Key Permissions
- **SSH Directory & Private Keys:** Enforces `700` on `~/.ssh` and `600` on private keys.
- **GnuPG Keyring:** Enforces `700` permissions on `~/.gnupg/`.
- **Session Locking:** Verifies automated idle screen lock timeouts in `hypridle.conf` and `shell.json`.

---

## User Interface & Features

- **Glanceable Status Bar Widget:** Shield icon (`󰒃`) dynamically tints green, yellow, or urgent red based on security score.
- **Animated Rescan:** Spinning refresh button (``) provides immediate visual feedback.
- **Category Filter Tabs:** Quickly filter audit results by `All`, `Plugins`, `System`, `Network`, and `Auth`.
- **One-Click Remediation:** Click any fix command box or press `Enter`/`Space` to copy the exact shell command to your clipboard.
- **Zero-Bloat Performance:** Complete deep scan executes in **<120ms** without background daemons or battery drain.

---

## Controls & Keybindings

| Action | How to Trigger |
| :--- | :--- |
| **Open / Close Panel** | Left-click the shield icon on your top bar |
| **Immediate Rescan** | Middle-click the bar icon, click the `` refresh icon, or press `R` inside panel |
| **Navigate Issues** | `Up` / `Down` arrow keys |
| **Copy Fix Command** | `Enter` / `Space` on selected issue, or click the copy button |
| **Filter Categories** | Click category pills (`All`, `Plugins`, `System`, `Network`, `Auth`) |
| **Dismiss Panel** | `Escape` |

---

## File Structure

```
omasecurity/
├── BarWidget.qml       # Bar widget icon, dynamic color tinting, and tooltip
├── Panel.qml           # Anchored flyout panel with score, category filters, and finding cards
├── manifest.json       # Omarchy Quattro plugin manifest (namespaced id: ucmz851.omasecurity)
├── LICENSE             # MIT License
├── README.md           # Documentation & instructions
└── scripts/
    └── audit.py        # Fast, non-blocking Python audit engine (<120ms execution)
```

---

## License

MIT © [ucmz851](https://github.com/ucmz851)
