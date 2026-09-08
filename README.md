<img width="1387" height="462" alt="2026-09-08 18_08_09-2026-08-14 15_32_55-Greenshot" src="https://github.com/user-attachments/assets/47ba4ff5-0e7c-4bd8-a870-1c0ae87e756f" />

# LOCKmeAD

**A lightweight, JSON-driven Active Directory hardening & security deployment tool, made by pentesters**

LOCKmeAD hardens, structures, and locks down Active Directory environments through a modular PowerShell toolkit. Instead of importing bulky pre-configured GPO backups or running opaque scripts, every security policy is defined in simple, human-readable JSON files. The PowerShell modules read those configs and create everything in AD for you : groups, OUs, GPOs, password policies, authentication silos, and more. LOCKmeAD is made by pentesters who know actual AD gaps and attacks path so that admin teams are provided with real remediations

> **Full documentation is available on the [Wiki](https://github.com/y00ga-sec/LOCKmeAD/wiki).**

---

## Why LOCKmeAD?

- **JSON-first configuration** — No GPO imports, no XML blobs. Every setting lives in clean JSON files you can read, diff, version, and customize in seconds.
- **Modular deployment** — Pick what you need: tiering, RBAC, hardening, GPOs, password policies, authentication silos, or JIT access. Deploy them individually, in specific combinations, or all at once.
- **GUIs included** — A full WPF graphical interface lets you configure and deploy every module visually. No need to touch the command line if you don't want to.
- **JIT Access Manager** — A dedicated GUI tool deployed to admin machines for adding, removing and managing temporary, time-limited group memberships (PAM TTL). Request access, set a duration, watch the countdown, revoke early if needed.
- **Idempotent & safe** — Every operation checks existing state before acting. Built-in `‑WhatIf` simulation mode lets you preview all changes without touching AD.

In order to avoid breaking your environnement when deploying, LOCKmeAD includes by default :

- GPOs with APPLY/DENY security filtering groups - after linking LOCKmeAD GPOs to its target OU, add machines/users to the APPLY group and exceptions to the DENY one for smooth and step-by-step pilot phases
- Silos deployed in **audit mode** (non-enforced) — monitor Kerberos logs before switching to enforce
- PSOs that applies on groups you chose - so that your current admin team does not have a surprise at next password renewal
  
---

## Modules

| Module | What it does |
|---|---|
| **Tiering** | Creates the OU structure for AD tiering (T0 / T1 / T2) |
| **RBAC** | Deploys roles using AGDLP methodology — groups, memberships, NTFS / AD / ADCS permissions |
| **Hardening** | Applies AD hardening tasks — MachineAccountQuota, functional levels, Recycle Bin, PAM, LAPS, Central Store, etc. |
| **GPO** | Creates security GPOs from JSON templates — disables LLMNR, mDNS, NBT-NS, NTLMv1, Wdigest, SMBv1, and more |
| **PSO** | Creates Fine-Grained Password Policies with full AD Admin Center parity |
| **Silo** | Creates Authentication Policy Silos to restrict service account lateral movement — deployed in **audit mode** by default, switch to enforce after validating no auth failures |
| **JIT** | Deploys the JIT Access Manager tool to T0 admin workstations via GPO |

---

## Quick Start

```powershell
# Interactive menu — select modules to deploy
.\LOCKmeAD.ps1

# Or launch the GUI
.\LOCKmeAD.ps1 -Module GUI

# Deploy specific modules
.\LOCKmeAD.ps1 -Module Tiering,RBAC,GPO

# Preview changes without modifying AD
.\LOCKmeAD.ps1 -Module All -WhatIf
```

---

## Requirements

PowerShell 7.5 and local administrator privileges. Which PowerShell modules you need depends on
what you deploy:

| LOCKmeAD module | Required PowerShell modules |
|---|---|
| Tiering | `ActiveDirectory` |
| RBAC | `ActiveDirectory` |
| PSO | `ActiveDirectory` |
| Silo | `ActiveDirectory` |
| GPO | `ActiveDirectory` + `GroupPolicy` |
| JIT (deployment) | `ActiveDirectory` + `GroupPolicy` |
| Hardening | `ActiveDirectory` + `LAPS`¹ + `DnsServer`² |
| GUI / menu | `ActiveDirectory` |

¹ only for the `ExtendLAPSSchema` and `ConfigureLAPSADPermissions` tasks
² only for the `AddDNSSecurityRecords` task

`ActiveDirectory` is the only hard requirement — LOCKmeAD refuses to start without it. The others
are checked when the module that needs them is actually deployed.

```powershell
# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell, GPMC, RSAT-DNS-Server

# Windows 10 / 11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0
```

Nothing has to be imported by hand — LOCKmeAD loads what it needs. Two modules are never installed
manually: `LAPS` ships in-box with Windows Server 2019+ and Windows 10+ (April 11 2023 update
onward), and `SmbShare` is only needed on the file server, not on the host running LOCKmeAD.

**Running from a non-domain-joined host** — LOCKmeAD does not require a domain-joined machine. With
`-Server` / `-Credential`, `GroupPolicy` and `LAPS` are **not** needed locally: those cmdlets accept
no `-Credential`, so LOCKmeAD runs them inside a WinRM session on the domain controller, where they
must be present instead. `ActiveDirectory` is then enough on your own host, plus `DnsServer` if you
use `AddDNSSecurityRecords`.

---

## How It Works

1. **Edit the JSON configs** in `Config/` to match your environment — role names, OU paths, GPO settings, password policies, silo definitions.
2. **Run LOCKmeAD** via CLI or GUI.
3. **The PowerShell modules create everything in AD** based on your JSON — no manual steps, no GPO imports, no pre-built templates to maintain.

Safe deployment order is enforced automatically: Hardening > Tiering > RBAC > PSO > Silo > GPO > JIT.

---

## Simulation mode (`-WhatIf`)

Every module supports `-WhatIf`, and the GUI exposes it as the **WhatIf mode** toggle. Nothing is written to Active Directory: no GPO, no group, no OU, no ACL, no policy, no schema change. The run is logged to `Logs/<run>/` exactly like a real one, with every action prefixed `[WhatIf]`, and the GUI reports it as `SIM/SUCCESS` in blue rather than `SUCCESS` in green.

Two things a simulation still changes, both outside the directory:

- **The GUI writes your configs.** *Deploy selected* always saves `Config/*.json` first, in simulation as in a real run. This is required for fidelity: the deployment scripts read the configuration from disk, so skipping the save would simulate the previous state rather than what is on screen. Use the CLI with `-ConfigPath` pointing at a copy if you need your JSON files left untouched.
- **Local process state.** The ownership tasks enable `SeRestorePrivilege` on the running process, and `AddDNSSecurityRecords` opens its CIM session, before reaching the point where they would write. Deliberately so — a simulation that skipped them would stop being faithful to a real run, and a connectivity problem that would break the deployment must break the simulation too.

### Reading a multi-module simulation

Simulating several modules at once **will report errors that a real deployment would not**. Later modules reference objects the earlier ones create, and in simulation nothing gets created, so those references cannot resolve:

| Reported by | Trigger | Affects |
|---|---|---|
| `Set-GPOUserRightsAssignment` | groups named in `UserRightsAssignments` | `SEC-Tiering-*-DenyLogon` |
| `Set-GPORestrictedGroups` | members named in `RestrictedGroups` | `SEC-Tiering-*-LocalAdmins` |
| `Add-PSOSubject` | the PSO itself, not created yet | any policy with a non-empty `AppliesTo` |

Group names are resolved to SIDs *before* the write is attempted, on purpose: a missing group has to surface as a clean configuration error rather than as a half-written `GptTmpl.inf`.

**How to read it** — a `Group '<name>' not found` raised by the GPO or PSO module is expected noise when `<name>` is declared in `RBAC-Config.json` and RBAC is part of the same run. Any other name (a group you typed yourself, `Domain Admins`, `Enterprise Admins`) is a real configuration error worth fixing.

**How to avoid it** — deploy RBAC for real first; it is idempotent and only creates empty groups. Then simulate GPO. The directory now holds the state it would have when GPO actually runs, so the simulation is exact.

Tiering → RBAC is not affected: RBAC checks its target OU inside the write guard, so an OU that does not exist yet raises nothing during a simulation.

---

## Documentation

For detailed configuration guides, JSON schema references, and deployment walkthroughs, head to the **[Wiki](https://github.com/y00ga-sec/LOCKmeAD/wiki)**.
