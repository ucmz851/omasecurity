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
| `lsm_status` | System Security | 5 | `/sys/kernel/security/lsm` contains `yama` and `landlock`; lockdown mode and hardened kernel flavour in details. AppArmor is scored only if the package is installed | Yama and Landlock are loaded. Missing either is MEDIUM (−2 each). Installed AppArmor inactive or not in the LSM list is MEDIUM (−1). AppArmor is optional on Omarchy: not installed is details-only, no penalty. Never reads `/sys/kernel/security/apparmor/profiles` (needs root) | LSMs constrain ptrace, filesystem access, and (if enabled) MAC policy. Stock Omarchy does not enable AppArmor, so penalising every install would be wrong | `/sys/kernel/security/lsm` is readable | fast | [Kernel hardening](https://wiki.archlinux.org/title/Security#Kernel_hardening), [Mandatory access control](https://wiki.archlinux.org/title/Security#Mandatory_access_control), [AppArmor](https://wiki.archlinux.org/title/AppArmor), [LSM](https://docs.kernel.org/admin-guide/lsm/index.html) |
| `audit_framework` | System Security | 3 | `auditd` active state; count of readable files in `/etc/audit/rules.d`. Does not run `auditctl -l` (needs root). Omarchy ships no audit rules | `auditd` is active. Inactive is MEDIUM (−3). Unreadable `rules.d` is details-only with `sudo auditctl -l` | auditd records security-relevant syscalls; an inactive daemon collects nothing | `pacman -Qi audit` reports `Install Reason : Explicitly installed`, or `systemctl is-enabled auditd` is enabled. A dependency-only install with auditd not enabled is N/A | fast | [Audit framework](https://wiki.archlinux.org/title/Audit_framework) |
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

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| _placeholder_ | Boot & Disk | — | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | fast? | — |

### Services

Stock Arch marks `udisks2` and `user@1000.service` as UNSAFE in `systemd-analyze security`. Those units do not face the network, so they are ignored. Only the candidate list below is scored. `systemd-analyze security` is unprivileged but ~170ms, so it is slow-lane.

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| `service_exposure` | Services | 10 | One `systemctl is-active` call for sshd, cups, avahi-daemon, smb, nmb, nfs-server, rpcbind, docker, libvirtd, tailscaled, syncthing, bluetooth, transmission, minidlna, plexmediaserver, jellyfin, nginx, httpd, caddy. Active units are scored with one `systemd-analyze security --no-pager` (`--json=short` when supported, otherwise the table) | No candidate is active, or every active candidate has exposure below 8.0. Active + exposure 8.0 or higher is MEDIUM (−2 each, floor 0). Timeout (10s) is N/A | Network-facing daemons with weak sandboxing are the remote attack surface | `systemctl` is available; `systemd-analyze` is available when any candidate is active | slow | [systemd-analyze security](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html) |
| `sshd_config` | Services | 5 | Effective `PasswordAuthentication`, `PermitRootLogin`, and `X11Forwarding` from `/etc/ssh/sshd_config` plus `sshd_config.d/*.conf` (first occurrence wins; drop-ins included at the top win). Unreadable files are skipped and named in details | PasswordAuthentication is explicitly `no` (unset defaults to yes: MEDIUM −2). PermitRootLogin is not `yes` (yes: HIGH −3). X11Forwarding is not `yes` (yes: LOW −1) | Password and root SSH are the usual brute-force path; X11 forwarding leaks the desktop | `systemctl is-enabled sshd` is enabled/enabled-runtime or `is-active` is active | fast | [OpenSSH](https://wiki.archlinux.org/title/OpenSSH), [sshd_config(5)](https://man.archlinux.org/man/sshd_config.5) |
| `user_services` | Services | 2 | Count of running user units from `systemctl --user list-units --type=service --state=running`. Each `~/.config/systemd/user/**/*.service` `ExecStart` is checked | No ExecStart path is under `/tmp`, `/var/tmp`, `/dev/shm`, or `~/Downloads`. A match is HIGH (−2) | User units that execute from world-writable locations are trivial persistence | User systemd (`systemctl --user`) is available | fast | [systemd/User](https://wiki.archlinux.org/title/Systemd/User) |
