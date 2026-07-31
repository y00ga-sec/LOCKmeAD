// Maps PowerShell ConsoleColor names (as sent by the server, taken from
// Write-Host -ForegroundColor / InformationRecord.MessageData) to CSS colors
// for the live deployment log panel.
const CONSOLE_COLOR_MAP = {
  Cyan: '#0078D4',
  Green: '#2E7D32',
  Yellow: '#B8860B',
  Red: '#C0392B',
  White: '#333333',
  Gray: '#777777',
  DarkGray: '#999999',
  Black: '#000000'
};

// Canonical safe execution order, matching GUI/Controller.ps1's
// $script:DeploySafeOrder and LOCKmeAD.ps1's $script:SafeOrder exactly:
// infrastructure first, then OU-dependent modules. Selected modules are
// always re-sorted into this order regardless of checkbox click order.
const DEPLOY_SAFE_ORDER = ['Hardening', 'Tiering', 'RBAC', 'PSO', 'Silo', 'GPO', 'JIT'];

function lockmeadApp() {
  return {
    activeTab: 'dashboard',
    connection: { connected: false, mode: 'none', server: null },
    connectForm: { server: '', username: '', password: '', remember: false },
    connectError: '',
    connecting: false,
    dashboard: { environment: null, summary: {} },
    dashboardError: '',

    // Multi-module "Deploy Selected" state -- lets the user pick a subset of
    // modules and deploys them sequentially in DEPLOY_SAFE_ORDER, mirroring
    // GUI/Controller.ps1's Start-SelectedDeployments (one shared log, doesn't
    // stop on first module's failure, ends with a summary line).
    deployBatch: {
      selected: { Hardening: false, Tiering: false, RBAC: false, PSO: false, Silo: false, GPO: false, JIT: false },
      whatIf: false,
      running: false,
      log: []
    },

    // Per-module page state, keyed by the same names the backend uses
    // (Hardening, GPO, Tiering, RBAC, PSO, Silo, JIT).
    modules: {
      Hardening: lockmeadModuleState(),
      GPO: lockmeadModuleState(),
      Tiering: lockmeadModuleState(),
      RBAC: lockmeadModuleState(),
      PSO: lockmeadModuleState(),
      Silo: lockmeadModuleState(),
      JIT: lockmeadModuleState()
    },

    moduleCards: [
      {
        key: 'hardening', title: 'Hardening',
        value: (s) => s.Hardening ? `${s.Hardening.enabled} / ${s.Hardening.total}` : '—',
        label: (s) => s.Hardening ? s.Hardening.label : ''
      },
      {
        key: 'gpo', title: 'GPO',
        value: (s) => s.GPO ? `${s.GPO.enabled} / ${s.GPO.total}` : '—',
        label: (s) => s.GPO ? s.GPO.label : ''
      },
      {
        key: 'tiering', title: 'Tiering',
        value: (s) => s.Tiering ? `${s.Tiering.count}` : '—',
        label: (s) => s.Tiering ? s.Tiering.label : ''
      },
      {
        key: 'rbac', title: 'RBAC',
        value: (s) => s.RBAC ? `${s.RBAC.count}` : '—',
        label: (s) => s.RBAC ? s.RBAC.label : ''
      },
      {
        key: 'pso', title: 'PSO',
        value: (s) => s.PSO ? `${s.PSO.enabled} / ${s.PSO.total}` : '—',
        label: (s) => s.PSO ? s.PSO.label : ''
      },
      {
        key: 'silo', title: 'Silo',
        value: (s) => s.Silo ? `${s.Silo.enabled} / ${s.Silo.total}` : '—',
        label: (s) => s.Silo ? s.Silo.label : ''
      },
      {
        key: 'jit', title: 'JIT',
        value: (s) => s.JIT ? (s.JIT.gpoConfigured ? '1 GPO' : '—') : '—',
        label: (s) => s.JIT ? `${s.JIT.linkCount} ${s.JIT.label}` : ''
      }
    ],

    async init() {
      await this.refreshConnection();
      if (this.connection.connected) {
        await this.loadDashboard();
      }
    },

    colorFor(name) {
      return CONSOLE_COLOR_MAP[name] || '#333333';
    },

    async refreshConnection() {
      try {
        const res = await fetch('/api/connection');
        this.connection = await res.json();
      } catch (e) {
        this.connection = { connected: false, mode: 'none', server: null };
      }
    },

    async connect() {
      this.connectError = '';
      if (!this.connectForm.server || !this.connectForm.username || !this.connectForm.password) {
        this.connectError = 'Domain controller, username, and password are all required.';
        return;
      }
      this.connecting = true;
      try {
        const res = await fetch('/api/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.connectForm)
        });
        const data = await res.json();
        if (!res.ok) {
          this.connectError = data.error || 'Connection failed.';
          return;
        }
        this.connection = data;
        this.connectForm.password = '';
        await this.loadDashboard();
      } catch (e) {
        this.connectError = `${e}`;
      } finally {
        this.connecting = false;
      }
    },

    async disconnect() {
      try {
        await fetch('/api/disconnect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ forget: false })
        });
      } finally {
        this.connection = { connected: false, mode: 'none', server: null };
        this.dashboard = { environment: null, summary: {} };
      }
    },

    async loadDashboard() {
      this.dashboardError = '';
      try {
        const res = await fetch('/api/dashboard');
        const data = await res.json();
        if (!res.ok) {
          this.dashboardError = data.error || 'Unable to load dashboard.';
          return;
        }
        this.dashboard = data;
      } catch (e) {
        this.dashboardError = `${e}`;
      }
    },

    // Switches tabs, lazily loading a module's config the first time its page
    // is visited (and re-loading the dashboard so its summary cards reflect
    // any changes made while a module page was open).
    async setActiveTab(tab) {
      this.activeTab = tab;
      if (tab === 'dashboard') {
        await this.loadDashboard();
        return;
      }
      const moduleName = lockmeadModuleNameForTab(tab);
      if (moduleName && this.modules[moduleName] && !this.modules[moduleName].config) {
        await this.loadModuleConfig(moduleName);
      }
    },

    async loadModuleConfig(moduleName) {
      const state = this.modules[moduleName];
      state.error = '';
      try {
        const res = await fetch(`/api/config/${moduleName}`);
        const data = await res.json();
        if (!res.ok) {
          state.error = data.error || `Unable to load ${moduleName} configuration.`;
          return;
        }
        state.config = data;
        if (moduleName === 'Tiering') this.rebuildTreeRows();
      } catch (e) {
        state.error = `${e}`;
      }
    },

    async saveConfig(moduleName) {
      const state = this.modules[moduleName];
      state.error = '';
      state.savedMessage = '';
      state.saving = true;
      try {
        const res = await fetch(`/api/config/${moduleName}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(state.config)
        });
        const data = await res.json();
        if (!res.ok) {
          state.error = data.error || `Unable to save ${moduleName} configuration.`;
          return;
        }
        state.savedMessage = 'Saved.';
        setTimeout(() => { state.savedMessage = ''; }, 2500);
      } catch (e) {
        state.error = `${e}`;
      } finally {
        state.saving = false;
      }
    },

    async deploy(moduleName) {
      const state = this.modules[moduleName];
      state.error = '';
      state.log = [];
      state.deploying = true;
      try {
        const res = await fetch(`/api/deploy/${moduleName}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ whatIf: state.whatIf })
        });
        const data = await res.json();
        if (!res.ok) {
          state.error = data.error || `Unable to start ${moduleName} deployment.`;
          state.deploying = false;
          return;
        }
        this.streamDeployLog(moduleName, data.jobId);
      } catch (e) {
        state.error = `${e}`;
        state.deploying = false;
      }
    },

    streamDeployLog(moduleName, jobId) {
      const state = this.modules[moduleName];
      const source = new EventSource(`/api/deploy/${jobId}/stream`);

      source.onmessage = (evt) => {
        try {
          state.log.push(JSON.parse(evt.data));
        } catch (e) { /* ignore malformed lines */ }
      };

      source.addEventListener('done', () => {
        state.deploying = false;
        source.close();
      });

      source.onerror = () => {
        // EventSource retries automatically on transient errors; only treat it
        // as terminal once the connection is fully closed.
        if (source.readyState === EventSource.CLOSED) {
          state.deploying = false;
        }
      };
    },

    // ---- Multi-module "Deploy Selected" (Deploy tab) ----

    deployOrderHint() {
      const sel = DEPLOY_SAFE_ORDER.filter(m => this.deployBatch.selected[m]);
      return sel.length > 1 ? `Order: ${sel.join(' > ')}` : '';
    },

    setAllDeploySelection(value) {
      for (const key of Object.keys(this.deployBatch.selected)) {
        this.deployBatch.selected[key] = value;
      }
    },

    // Runs one module's deploy to completion (POST + drain its SSE stream),
    // appending every line into the shared batch log, and never rejects --
    // failures are logged as a Red line so the caller's sequential loop
    // always continues to the next module, matching Start-SingleDeployment's
    // try/catch-and-continue behavior.
    deployOneAndWait(moduleName, whatIf) {
      return new Promise((resolve) => {
        (async () => {
          try {
            const res = await fetch(`/api/deploy/${moduleName}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ whatIf })
            });
            const data = await res.json();
            if (!res.ok) {
              this.deployBatch.log.push({ color: 'Red', text: `${moduleName} deployment failed to start: ${data.error || res.status}` });
              resolve();
              return;
            }
            const source = new EventSource(`/api/deploy/${data.jobId}/stream`);
            source.onmessage = (evt) => {
              try { this.deployBatch.log.push(JSON.parse(evt.data)); } catch (e) { /* ignore malformed lines */ }
            };
            source.addEventListener('done', () => {
              source.close();
              resolve();
            });
            source.onerror = () => {
              if (source.readyState === EventSource.CLOSED) resolve();
            };
          } catch (e) {
            this.deployBatch.log.push({ color: 'Red', text: `${moduleName} deployment failed: ${e}` });
            resolve();
          }
        })();
      });
    },

    async runSelectedDeployments() {
      const ordered = DEPLOY_SAFE_ORDER.filter(m => this.deployBatch.selected[m]);
      if (ordered.length === 0) {
        this.deployBatch.log = [{ color: 'Yellow', text: 'No modules selected for deployment.' }];
        return;
      }
      this.deployBatch.running = true;
      const whatIfLabel = this.deployBatch.whatIf ? ' (WhatIf)' : '';
      this.deployBatch.log = [{ color: 'Cyan', text: `Deploying: ${ordered.join(' > ')}${whatIfLabel}` }];

      for (const moduleName of ordered) {
        this.deployBatch.log.push({ color: 'Cyan', text: `=== ${moduleName} ===` });
        await this.deployOneAndWait(moduleName, this.deployBatch.whatIf);
      }

      this.deployBatch.log.push({ color: 'Green', text: 'All selected deployments completed.' });
      this.deployBatch.running = false;
      await this.loadDashboard();
    },

    // ---- Shared helpers reused by the GPO/Tiering/RBAC/PSO/Silo/JIT pages ----

    // Newline-separated <textarea> binding for string-array fields (LinkTargets,
    // Members, Groups, ServiceAccounts, Computers, ...). Mirrors the pattern
    // already used inline for Hardening's array Parameters.
    arrayText(arr) {
      return (arr || []).join('\n');
    },
    setArrayText(obj, key, text) {
      obj[key] = text.split('\n').map(s => s.trim()).filter(s => s);
    },

    addItem(arr, factory) {
      arr.push(factory());
    },
    removeItem(arr, item, label) {
      if (!confirm(`Delete ${label || 'this item'}? This only affects the in-memory config until you click Save.`)) return;
      const i = arr.indexOf(item);
      if (i !== -1) arr.splice(i, 1);
    },

    // Flattens Tiering's nested OUStructure into a display-ordered list of
    // {node, parentArray, depth} rows. Alpine has no clean way to recurse an
    // x-for template to arbitrary depth without a build step, so the tree is
    // walked in plain JS instead; each row holds a live reference to its real
    // node object and containing array, so in-place edits/splices mutate the
    // actual config tree directly -- this list is just its display projection
    // and gets rebuilt after every structural change (add/delete).
    flattenTree(nodes, depth = 0, rows = []) {
      for (const node of (nodes || [])) {
        rows.push({ node, parentArray: nodes, depth });
        if (node.Children && node.Children.length) {
          this.flattenTree(node.Children, depth + 1, rows);
        }
      }
      return rows;
    },
    rebuildTreeRows() {
      const state = this.modules.Tiering;
      state.treeRows = this.flattenTree(state.config?.OUStructure || []);
    },
    addChildOU(row) {
      if (!row.node.Children) row.node.Children = [];
      row.node.Children.push(newOUNode());
      this.rebuildTreeRows();
    },
    addSiblingOU(row) {
      const i = row.parentArray.indexOf(row.node);
      row.parentArray.splice(i + 1, 0, newOUNode());
      this.rebuildTreeRows();
    },
    deleteOUNode(row) {
      const count = 1 + this.flattenTree(row.node.Children || []).length;
      if (!confirm(`Delete "${row.node.Name}"${count > 1 ? ` and its ${count - 1} descendant OU(s)` : ''}? This only affects the in-memory config until you click Save.`)) return;
      const i = row.parentArray.indexOf(row.node);
      if (i !== -1) row.parentArray.splice(i, 1);
      this.rebuildTreeRows();
    }
  };
}

function newOUNode() {
  return { Name: 'NewOU', Description: '' };
}

function newGPO() {
  return { Name: 'NEW-GPO', Description: '', Enabled: true, GpoStatus: 'AllSettingsEnabled', LinkTargets: [] };
}

function newGPOSetting(type) {
  switch (type) {
    case 'SecurityOptions':
    case 'RegistrySettings':
    case 'RegistryPreferences':
      return { Key: '', ValueName: '', Value: '', Type: 'DWord', Description: '' };
    case 'UserRightsAssignments':
      return { Right: '', Description: '', Groups: [] };
    case 'RestrictedGroups':
      return { Group: 'Administrators', Members: [], Description: '' };
    case 'SystemServices':
      return { Name: '', StartupType: 4, Description: '' };
    case 'Scripts':
      return { Type: 'Startup', ScriptName: '', ScriptPath: '', Parameters: '', Description: '' };
    default:
      return {};
  }
}

function newRootGroup() {
  return { Name: '', Description: '', OU: '', Members: [] };
}

function newRole() {
  return {
    Name: 'NewRole',
    Description: '',
    GlobalGroup: { Name: '', Description: '', OU: '' },
    DomainLocalGroups: []
  };
}

function newDLGroup() {
  return { Name: '', Description: '', OU: '', Permissions: [] };
}

function newPermission(type) {
  switch (type) {
    case 'NTFS':
      return { Type: 'NTFS', Path: '', Rights: 'Modify', InheritanceFlags: 'ContainerInherit, ObjectInherit', PropagationFlags: 'None', AccessControlType: 'Allow' };
    case 'ADCS':
      return { Type: 'ADCS', CAName: '', CAHostname: '', Right: 'Enroll' };
    case 'Share':
      return { Type: 'Share', ShareServer: '', ShareName: '', ShareRight: 'Change' };
    case 'AD':
    default:
      return { Type: 'AD', TargetOU: '', ADRights: 'GenericAll', ObjectType: '00000000-0000-0000-0000-000000000000', InheritanceType: 'Descendents', InheritedObjectType: '00000000-0000-0000-0000-000000000000', AccessControlType: 'Allow' };
  }
}

function newPSOPolicy() {
  return {
    Name: 'NewPolicy', Description: '', Enabled: true, Precedence: 50,
    ComplexityEnabled: true, MinPasswordLength: 12, MinPasswordAgeDays: 1, MaxPasswordAgeDays: 90,
    PasswordHistoryCount: 24, LockoutThreshold: 5, LockoutDurationMinutes: 30,
    LockoutObservationWindowMinutes: 30, ReversibleEncryptionEnabled: false,
    ProtectedFromAccidentalDeletion: true, AppliesTo: ''
  };
}

function newSilo() {
  return { Name: 'NewSilo', Description: '', Enabled: true, Enforce: false, TGTLifetimeMinutes: 240, ServiceAccounts: [], Computers: [] };
}

function lockmeadModuleState() {
  return {
    config: null,
    whatIf: false,
    saving: false,
    deploying: false,
    error: '',
    savedMessage: '',
    log: []
  };
}

function lockmeadModuleNameForTab(tab) {
  const map = {
    hardening: 'Hardening',
    gpo: 'GPO',
    tiering: 'Tiering',
    rbac: 'RBAC',
    pso: 'PSO',
    silo: 'Silo',
    jit: 'JIT'
  };
  return map[tab];
}
