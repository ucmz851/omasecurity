# OmaSecurity (`omasecurity`)

**OmaSecurity** is a lightweight, native security posture auditor and shell plugin code health monitor designed specifically for the Omarchy Quattro desktop environment (`omarchy-shell` / Quickshell).

---

## Features

- **Security Posture Score**: Glanceable overall health score (0–100%) and Letter Grade (A–F) directly on the status bar.
- **Omarchy Shell Plugin Health**: Continuously scans installed user plugins in `~/.config/omarchy/plugins/` for dangerous script execution patterns (e.g. `curl | sh`, hardcoded private keys or tokens, plain text credentials).
- **Network & Exposure Audits**:
  - Checks host firewall state (`ufw`, `nftables`, `firewalld`).
  - Audits public listening ports bound to `0.0.0.0` or `::` vs localhost (`127.0.0.1`).
  - Verifies SSH daemon configuration (`PermitRootLogin`).
- **Desktop & Authentication Security**:
  - Verifies automated screen lock configuration in `hypridle.conf` and `shell.json`.
  - Checks strict permissions on `~/.ssh/` and private key files (`700`/`600`).
  - Checks permissions on `~/.gnupg/` (`700`).
- **One-Click Remediation**: Click any suggested fix or press `Enter` to instantly copy the recommended shell command to your clipboard.
- **Native Quattro Design**: Uses standard Quattro components (`Panel`, `BarWidget`, `Style`, `PanelHero`, `BorderSurface`) with dark/light theme inheritance and keyboard navigation.

---

## File Structure

```
omasecurity/
├── BarWidget.qml       # Bar icon, status color indicator, and tooltip
├── Panel.qml           # Anchored flyout panel with score, tabs, and fix commands
├── manifest.json       # Omarchy Quattro plugin manifest
├── README.md           # Documentation & instructions
└── scripts/
    └── audit.py        # Fast, non-blocking Python audit engine (<150ms execution)
```

---

## Bar Controls & Shortcuts

| Action | Control |
| :--- | :--- |
| **Open / Close Panel** | Left Click on Shield bar icon |
| **Immediate Rescan** | Middle Click on Shield bar icon, or press `R` inside panel |
| **Navigate Issues** | `Up` / `Down` arrow keys |
| **Copy Fix Command** | `Enter` / `Space` on selected issue, or click the copy icon |
| **Dismiss Panel** | `Escape` |

---

## Managing Placement

Add or move OmaSecurity on your Omarchy bar using the standard `omarchy bar` command:

```bash
# Add to right section
omarchy bar put omasecurity --section right

# Move next to tray
omarchy bar move omasecurity --after omarchy.tray
```
