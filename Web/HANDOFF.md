# LOCKmeAD Web UI — Handoff / Status

This document exists so a fresh Claude Code session (e.g. on a different machine than the one
that did this work) can pick up the web-UI migration without re-deriving context or repeating
already-solved bugs. Read this before touching `Web/`.

## Why this exists

The WPF desktop GUI (`Launch-GUI.ps1` + `GUI/Controller.ps1` + `GUI/Views.ps1`) crashes
depending on host specs (DPI scaling, .NET Desktop runtime version, RDP-session rendering).
The user asked for it to be replaced with a local web server instead. Full plan/rationale is in
the git history of this conversation; the short version:

- **Backend**: [Pode](https://github.com/Badgerati/Pode) (`Install-Module Pode`), a
  PowerShell-native web framework. Routes call the existing `Modules/*.psm1` functions
  directly — zero rewrite of deployment logic.
- **Frontend**: vendored Alpine.js (`Web/wwwroot/vendor/alpine.min.js`, no CDN, no build step)
  + hand-written CSS. No React/Vue/webpack.
- **Scope**: full feature parity with the WPF GUI, including the ~15 interactive config-builder
  dialogs (Add Role, Permission builder, AD/Schema/CA search-pickers, Tiering OU tree editor,
  etc.) — not just "click deploy and watch logs."
- **Access**: localhost only (127.0.0.1), never LAN-exposed — this tool executes privileged
  AD/GPO changes.
- **Live logs**: deployment output streams to the browser via Server-Sent Events (SSE), not a
  spinner-then-results view.
- WPF (`Launch-GUI.ps1`, `GUI/`) stays in place until the web UI reaches parity, then gets
  retired. The CLI (`LOCKmeAD.ps1`) is untouched throughout.

## Status

| Task | Status |
|---|---|
| 1. Pode server skeleton + connection flow + Dashboard | ✅ Done |
| 2. First full module vertical slice — Hardening (config CRUD + deploy + live SSE logs) | ✅ Done |
| 3. Remaining module pages (GPO, Tiering, RBAC, PSO, Silo, JIT) | ⬜ Not started |
| 4. RBAC permission builder + AD/Schema/CA search-picker modals | ⬜ Not started |
| 5. Retire WPF GUI, update `LOCKmeAD.ps1` entry points, update README | ⬜ Not started |

**What works right now**: Connect screen, Dashboard (env info + per-module summary cards), and
a fully functional **Hardening** tab (view/edit every task's enabled state + parameters, Save,
Deploy with WhatIf toggle, live colored streaming log). GPO/Tiering/RBAC/PSO/Silo/JIT tabs are
placeholders ("This module's page is not built yet").

## Key architectural finding (from reading GUI/Controller.ps1, 4921 lines)

Every WPF "builder" dialog just edits an in-memory config object and saves it back to
`Config/*.json` (`Load-AllConfigs`/`Save-AllConfigs` in `Controller.ps1`). **No dialog writes to
AD directly** — AD/GPO is only touched when the user clicks Deploy, which shells out to the same
`Scripts/Deploy-*.ps1` the CLI uses. A handful of dialogs do live **read-only** AD queries (4
near-identical search-pickers: AD Group/Object/CA/Schema search, plus a GUID→name resolver
cache). This means:
- Config-editing pages are simple `GET`/`PUT` JSON round-trips (`Web/Routes/Config.ps1`, already
  generic across all 7 modules — Task 3 doesn't need to touch it).
- The 4 search-pickers should become ONE reusable frontend modal parameterized by endpoint, not
  4 bespoke ones.
- The only genuinely new/stateful backend work was deployment execution + log streaming
  (`Web/Routes/Deploy.ps1`, already built and proven).

## Critical Pode gotchas discovered the hard way — read before writing more routes/tasks

These cost real debugging time. All confirmed with minimal reproductions, not guesses.

1. **`$using:` does not work inside `Start-PodeServer`'s scriptblock** (Pode 2.13.4). Throws "A
   Using variable cannot be retrieved." Use plain variable names instead — Pode's `-NoNewClosure`
   handling makes outer script variables available by name inside that *top-level* setup block
   (it runs synchronously, once, as part of `Start-PodeServer`'s own invocation).

2. **That plain-variable availability does NOT extend to `Add-PodeRoute`/`Add-PodeTask`
   `-ScriptBlock` bodies.** Those are deferred and re-invoked later via
   `Invoke-PodeScriptBlock -NoNewClosure` in a runspace that only inherits Pode's initial
   session-state snapshot. A plain variable or a function merely *dot-sourced* during the setup
   block's one-time execution is invisible inside a route/task body (confirmed: both throw/return
   null). **Fix**: put shared data in `Set-PodeState`/`Get-PodeState` instead of plain variables
   (see `ConfigModuleMap`/`DeployScriptMap` in `Start-LOCKmeADWeb.ps1`); if a helper needs to be a
   function, define it *inside* the route's own scriptblock (see the OU-counting scriptblock in
   `Routes/Dashboard.ps1`), not at the dot-sourced file's top level.

3. **`Import-Module`'d functions don't reliably survive into that snapshot either** — this is the
   subtle one. Pode's automatic propagation of already-loaded modules into its runspace pools is
   **order-dependent**, and breaks under nested-module-scoping: when Module B (e.g.
   `Hardening.psm1`) does `Import-Module ..\Common\Connection.psm1 -Force` from *inside its own
   module scope* (which every feature module does, to reach `Connection.psm1`'s functions for its
   own use), PowerShell attaches the re-imported `Connection` as a nested module scoped to B,
   tearing down and replacing whatever was previously registered globally under that module name.
   Import `Connection.psm1` before the 7 feature modules → it becomes invisible at the top level
   once the last one's internal re-import runs. Import it after them (matching every
   `Scripts\Deploy-*.ps1`'s existing convention) → fixes the *top-level script's own* visibility,
   but **still doesn't guarantee visibility inside deferred route bodies**, because Pode's
   automatic propagation into worker runspaces can itself be affected by the same nested-scoping
   dance happening *again* when Pode captures its module snapshot.
   **The real fix**: `Import-PodeModule -Path <...>` — Pode's own documented cmdlet for exactly
   this ("Imports a Module into the current, and all runspaces that Pode uses"). Call it
   explicitly for every module (`Connection.psm1` + all 7 feature modules) inside the
   `Start-PodeServer { }` setup block, right after `Add-PodeEndpoint`. Don't rely on Pode's
   implicit propagation of the plain `Import-Module` calls made before `Start-PodeServer`.

4. **`#Requires -Modules ActiveDirectory[, GroupPolicy]` at the top of a `Modules/*.psm1` file
   breaks Pode's internal module re-import.** `Import-PodeModulesInternal` (Pode's own internal
   mechanism, separate from the `Import-PodeModule` cmdlet above) re-validates each module's
   `#Requires` in a fresh runspace, and `GroupPolicy` specifically fails to resolve there even
   though it's genuinely installed and the exact same `Import-Module` call already succeeded
   moments earlier in the main script (`ActiveDirectory` resolves fine in the same fresh
   runspaces — only `GroupPolicy` doesn't, for reasons not fully root-caused, possibly related to
   how RSAT registers its module path). **Fix applied**: removed `#Requires -Modules ...` from
   all 7 `Modules/*.psm1` files. Safe to remove because every entry point
   (`LOCKmeAD.ps1`, each `Scripts\Deploy-*.ps1`, `Web\Start-LOCKmeADWeb.ps1`) already checks for
   these modules being installed *before* importing anything — the per-module `#Requires` was
   always a redundant second layer, just one that happens to be actively harmful under Pode.
   **Open risk not yet hit**: since real `Get-GPO`/`New-GPO`/etc. calls (not just the `#Requires`
   static check) might *also* fail to resolve inside a Pode task runspace if `GroupPolicy` truly
   isn't loadable there — this hasn't been tested yet because GPO/JIT deploy isn't built (Task 3).
   If it happens, the diagnosis pattern is: enable `-StatusPageExceptions Show` on
   `Start-PodeServer` temporarily to see the real stack trace instead of Pode's blank 500 page,
   hit the failing endpoint, read the trace, revert the flag once fixed.

5. **`Write-Host` (used by every `Write-*Log` function in every module) is not captured by
   `2>&1`** — that only merges the error stream. It IS captured by **`*>&1`** (all streams),
   which also preserves color: a captured `InformationRecord`'s `.MessageData.ForegroundColor`
   round-trips correctly. This is how `Web/Routes/Deploy.ps1` gets colored live log lines. (The
   WPF GUI's own log panel likely never worked correctly for this exact reason — it used `2>&1`.)

6. **`PSCredential` objects survive `Invoke-PodeTask -ArgumentList` intact** (same-process
   runspaces, not remoting — no serialization boundary). Confirmed empirically; safe to pass
   `$conn.Credential` straight through.

## File structure

```
Web/
  Start-LOCKmeADWeb.ps1     # entry point: module checks, imports, connection resolution,
                             # Pode server + Import-PodeModule calls + state init + route wiring
  Routes/
    Connection.ps1           # POST /api/connect, GET /api/connection, POST /api/disconnect
    Dashboard.ps1             # GET /api/dashboard (env info + per-module summary)
    Config.ps1                # GET/PUT /api/config/{module} -- generic, all 7 modules already
    Deploy.ps1                 # POST /api/deploy/{module}, GET /api/deploy/{jobId}/stream (SSE)
  wwwroot/
    index.html                # single-page app shell (Alpine.js x-data="lockmeadApp()")
    js/app.js                  # all frontend logic/state
    css/style.css               # WPF-ish blue/gray theme
    vendor/alpine.min.js         # vendored, do not fetch from CDN
```

## How to run / test

```powershell
Install-Module -Name Pode -Scope CurrentUser   # one-time
.\Web\Start-LOCKmeADWeb.ps1                     # opens http://127.0.0.1:8080
# useful flags: -Server / -Credential / -RememberConnection / -Port / -NoBrowser
```

Needs: PowerShell 7, `ActiveDirectory` + `GroupPolicy` RSAT modules, admin elevation (same
requirements as the CLI/WPF GUI). Add `-StatusPageExceptions Show` to the `Start-PodeServer` call
temporarily if you need to see real stack traces instead of Pode's blank 500 page while debugging
a new route.

## Next steps (in order)

1. **Task 3**: Build GPO, Tiering, RBAC, PSO, Silo, JIT pages following the exact pattern
   already proven for Hardening (`Routes/Config.ps1` + `Routes/Deploy.ps1` already work
   generically for all 7 — just need frontend pages in `index.html`/`app.js`, following the
   `modules.Hardening` state-object pattern). Special cases to handle per module:
   - **GPO**: filtering-OU field + per-GPO link-target lists + a dedicated LAPS settings
     sub-form (see `GUI/Controller.ps1`'s `Save-AllConfigs`, GPO section, for the exact field
     set to replicate).
   - **Tiering**: OU tree editor — needs a recursive Alpine component to edit a nested JSON
     tree client-side (replaces the WPF `TreeView`; see `Controller.ps1`'s
     `ConvertFrom-TreeView` for the shape).
   - **Hardening/GPO's functional-level prerequisite dialog** (`Show-FunctionalLevelPrereqDialog`
     in `Controller.ps1`) — needs a new route wrapping `Test-HardeningXPrerequisites` functions.
   - **First real test of the GroupPolicy-in-Pode-runspace risk** (gotcha #4 above) will happen
     here, once GPO/JIT deploy is wired up.
2. **Task 4**: RBAC permission builder (`Show-PermissionDialog` in `Controller.ps1` — AD/NTFS/
   ADCS/Share type-switcher form) + Add Role/Add DL Group/Pick Existing DL Group dialogs + the
   one reusable search-and-pick modal (AD Group/Object/CA/Schema search + GUID-to-name map).
3. **Task 5**: repoint `LOCKmeAD.ps1`'s `-Module GUI` path to `Web\Start-LOCKmeADWeb.ps1`, add a
   Pode availability check there (mirroring the existing `ActiveDirectory`/`GroupPolicy` check),
   remove `Launch-GUI.ps1`/`GUI/`, update `README.md`.
