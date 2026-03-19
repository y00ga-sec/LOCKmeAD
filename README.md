# LOCKmeAD

**A lightweight, JSON-driven Active Directory security model and deployment tool.**

LOCKmeAD hardens, structures, and locks down Active Directory environments through a modular PowerShell toolkit. Instead of importing bulky pre-configured GPO backups or running opaque scripts, every security policy is defined in simple, human-readable JSON files. The PowerShell modules read those configs and create everything in AD for you — groups, OUs, GPOs, password policies, authentication silos, and more.

> **Full documentation is available on the [Wiki](https://github.com/y00ga-sec/LOCKmeAD/wiki).**

---

## Why LOCKmeAD?

- **JSON-first configuration** — No GPO imports, no XML blobs. Every setting lives in clean JSON files you can read, diff, version, and customize in seconds.
- **Modular deployment** — Pick what you need: tiering, RBAC, hardening, GPOs, password policies, authentication silos, or JIT access. Deploy them individually, in specific combinations, or all at once.
- **GUIs included** — A full WPF graphical interface lets you configure and deploy every module visually. No need to touch the command line if you don't want to.
- **JIT Access Manager** — A dedicated GUI tool deployed to admin machines for adding, removing and managing temporary, time-limited group memberships (PAM TTL). Request access, set a duration, watch the countdown, revoke early if needed.
- **Idempotent & safe** — Every operation checks existing state before acting. Built-in `‑WhatIf` simulation mode lets you preview all changes without touching AD.

In order to avoid breaking your environnement when deploying, LOCKmeAD includes by default :

- GPOs with APPLY/DENY security filtering groups
- Empty Silos
- PSOs based on LOCKmeAD groups
  
---

## Modules

| Module | What it does |
|---|---|
| **Tiering** | Creates the OU structure for AD tiering (T0 / T1 / T2) |
| **RBAC** | Deploys roles using AGDLP methodology — groups, memberships, NTFS / AD / ADCS permissions |
| **Hardening** | Applies AD hardening tasks — MachineAccountQuota, functional levels, Recycle Bin, PAM, LAPS, Central Store, etc. |
| **GPO** | Creates security GPOs from JSON templates — disables LLMNR, mDNS, NBT-NS, NTLMv1, Wdigest, SMBv1, and more |
| **PSO** | Creates Fine-Grained Password Policies with full AD Admin Center parity |
| **Silo** | Creates Authentication Policy Silos to restrict service account lateral movement |
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

**Requirements:** PowerShell 5.1+, ActiveDirectory module, GroupPolicy module, domain-joined machine, administrator privileges.

---

## How It Works

1. **Edit the JSON configs** in `Config/` to match your environment — role names, OU paths, GPO settings, password policies, silo definitions.
2. **Run LOCKmeAD** via CLI or GUI.
3. **The PowerShell modules create everything in AD** based on your JSON — no manual steps, no GPO imports, no pre-built templates to maintain.

Safe deployment order is enforced automatically: Hardening > Tiering > RBAC > PSO > Silo > GPO > JIT.

---

## Documentation

For detailed configuration guides, JSON schema references, and deployment walkthroughs, head to the **[Wiki](https://github.com/y00ga-sec/LOCKmeAD/wiki)**.
