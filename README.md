# OmaSecurity (`omasecurity`)

**OmaSecurity** is a lightweight, native security posture auditor and shell plugin code health scanner designed for the Omarchy Quattro desktop environment (`omarchy-shell` / Quickshell).

---

## Installation

Install directly with the Omarchy plugin manager:

```bash
omarchy plugin add https://github.com/ucmz851/omasecurity.git --enable
```

---

## Features

- **Security Posture Score**: Glanceable overall health score (0–100%) and letter grade (A–F) directly on the status bar.
- **Omarchy Shell Plugin Health**: Continuously scans installed user plugins in `~/.config/omarchy/plugins/` for dangerous script execution patterns (e.g. `curl | sh`, hardcoded private keys or tokens, plaintext credentials).
- **Network & Exposure Audits**:
  - Checks host firewall state (`ufw`, `nftables`, `firewalld`).
  - Audits public listening ports bound to `0.0.0.0` or `::` vs localhost (`127.0.0.1`).
  - Verifies SSH daemon configuration (`PermitRootLogin`).
- **Desktop & Authentication Security**:
  - Verifies automated screen lock configuration in `hypridle.conf` and `shell.json`.
  - Checks strict permissions on `~/.ssh/` and private key files (`700`/`600`).
  - Checks permissions on `~/.gnupg/` (`700`).
- **One-Click Remediation**: Click any suggested fix or press `Enter` to instantly copy the recommended shell command to your clipboard.
- **Native Quattro Design**: Uses standard Quattro components (`Panel`, `BarWidget`, `Style`, `BorderSurface`) with dark/light theme inheritance and keyboard navigation.

---

## File Structure

```
omasecurity/
├── BarWidget.qml       # Bar icon, status color indicator, and tooltip
├── Panel.qml           # Anchored flyout panel with score, tabs, and fix commands
├── manifest.json       # Omarchy Quattro plugin manifest
├── LICENSE             # MIT License
├── README.md           # Documentation & instructions
└── scripts/
    └── audit.py        # Fast, non-blocking Python audit engine (<150ms execution)
```

---

## Bar Controls & Shortcuts

| Action | Control |
| :--- | :--- |
| **Open / Close Panel** | Left Click on Shield bar icon |
| **Immediate Rescan** | Middle Click on Shield bar icon, click the `` refresh icon, or press `R` inside panel |
| **Navigate Issues** | `Up` / `Down` arrow keys |
| **Copy Fix Command** | `Enter` / `Space` on selected issue, or click the copy icon |
| **Dismiss Panel** | `Escape` |

---

## License

MIT © [ucmz851](https://github.com/ucmz851)
