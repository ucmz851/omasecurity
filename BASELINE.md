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
| `pacman_keyring` | Packages | 5 | `pacman -Q` for `archlinux-keyring`, `omarchy-keyring`, and `archlinuxarm-keyring` if present. Omarchy key listed via `pacman-key --list-keys` when that finishes unprivileged in under 40ms, else `gpg --homedir /etc/pacman.d/gnupg --list-keys` | Keyring packages present; Omarchy key present when `[omarchy]` is configured. Listing timeouts are unknown (no deduction) | A missing Omarchy key while that repo is enabled means packages from it cannot be authenticated | `pacman` is installed | fast | [Package signing](https://wiki.archlinux.org/title/Pacman/Package_signing), `/usr/share/omarchy/bin/omarchy-update-keyring` |
| `pacman_updates` | Packages | 5 | Last 64KB of `/var/log/pacman.log` for the newest `starting full system upgrade` line | Upgrade within 14 days. 14–30 days is medium (−3); over 30 days is high (−5). No line: unknown, no deduction | Stale systems miss Arch Security Team fixes | `/var/log/pacman.log` is readable | fast | [System maintenance](https://wiki.archlinux.org/title/System_maintenance#Upgrading_the_system) |
| `pacman_inventory` | Packages | 5 | Local `pacman -Qq` / `pacman -Sl <repo>` / `pacman -Qmq` counts (no sync). Details: per-repo installed counts, omarchy count, up to 20 foreign names | Foreign count ≤ 25. Foreign packages alone are not a finding | More than 25 unsigned local/AUR builds widen the supply chain | `pacman` is installed | fast | [pacman](https://wiki.archlinux.org/title/Pacman) |
| `arch_audit` | Packages | 10 | If `arch-audit` is installed, run it with the JSON or `--format` flag discovered from `--help` (20s timeout) and count vulnerable packages by severity | No advisories. Critical/High −6, Medium-only −3, Low-only −1. Missing tool or network failure is N/A (no penalty) | Known CVEs in installed packages are the actionable end of the supply chain | `arch-audit` is installed and the advisory fetch succeeds | slow | [Arch Security Team](https://wiki.archlinux.org/title/Arch_Security_Team), extra repo `arch-audit` |

### Boot & Disk

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| _placeholder_ | Boot & Disk | — | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | fast? | — |

### Services

| id | category | weight | what is verified | pass condition | why it matters | applicable when | lane | references |
| :--- | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |
| _placeholder_ | Services | — | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | _(agent fills)_ | fast? | — |
