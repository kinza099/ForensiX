/**
 * ForensiX — Master Incident Response & Digital Forensics Application Controller
 * Handles tactical state, case CRUD, strict case isolation, visualizations & workflows
 */

const ForensiXApp = {
  state: {
    user: null,
    currentCaseId: null,
    currentCase: null,
    currentView: 'dashboard',
    cases: [],
    evidenceList: [],
    timelineEvents: [],
    indicators: [],
    findings: [],
    browserArtifacts: [],
    logs: [],
    suspiciousArtifacts: [],
    reports: [],
    theme: localStorage.getItem('forensix_theme') || 'dark',
    caseToDelete: null
  },

  async init() {
    this.applyTheme(this.state.theme);
    this.startDigitalClock();
    // Restore sidebar collapsed state
    if (localStorage.getItem('forensix_sidebar_collapsed') === '1') {
      const sidebar = document.getElementById('app-sidebar');
      if (sidebar) {
        sidebar.classList.add('collapsed');
        const icon = document.getElementById('collapse-icon');
        if (icon) icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 5l7 7-7 7M5 5l7 7-7 7"/>';
      }
    }
    await this.checkAuth();
    if (this.state.user) {
      await this.loadCases();
      this.initEventListeners();
      this.renderCurrentView();
    } else {
      this.showLoginModal();
    }
  },

  toggleSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    const icon = document.getElementById('collapse-icon');
    if (!sidebar) return;
    sidebar.classList.toggle('collapsed');
    const isCollapsed = sidebar.classList.contains('collapsed');
    localStorage.setItem('forensix_sidebar_collapsed', isCollapsed ? '1' : '0');
    if (icon) {
      icon.innerHTML = isCollapsed
        ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 5l7 7-7 7M5 5l7 7-7 7"/>'
        : '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 19l-7-7 7-7m8 14l-7-7 7-7"/>';
    }
  },

  startDigitalClock() {
    const update = () => {
      const el = document.getElementById('hud-clock');
      if (el) {
        const now = new Date();
        const iso = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
        el.textContent = iso;
      }
    };
    update();
    setInterval(update, 1000);
  },

  applyTheme(theme) {
    this.state.theme = theme;
    localStorage.setItem('forensix_theme', theme);
    if (theme === 'light') {
      document.body.classList.add('light-theme');
    } else {
      document.body.classList.remove('light-theme');
    }
  },

  toggleTheme() {
    this.applyTheme(this.state.theme === 'dark' ? 'light' : 'dark');
  },

  async checkAuth() {
    try {
      const res = await fetch('/api/me');
      const data = await res.json();
      if (data.authenticated) {
        this.state.user = data.user;
        this.updateUserUI();
      }
    } catch (e) {
      console.error("Auth check failed:", e);
    }
  },

  showLoginModal() {
    document.getElementById('login-modal').classList.add('active');
  },

  async login(username, password) {
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (res.ok) {
        this.state.user = data.user;
        document.getElementById('login-modal').classList.remove('active');
        this.updateUserUI();
        this.showToast("Authenticated successfully. Welcome to ForensiX.", "success");
        await this.loadCases();
        this.renderCurrentView();
      } else {
        this.showToast(data.error || "Authentication failed", "error");
      }
    } catch (e) {
      this.showToast("Network error during login", "error");
    }
  },

  async logout() {
    await fetch('/api/logout', { method: 'POST' });
    this.state.user = null;
    this.showToast("Investigator session terminated.", "info");
    location.reload();
  },

  updateUserUI() {
    if (!this.state.user) return;
    const nameEl = document.getElementById('sidebar-user-name');
    const roleEl = document.getElementById('sidebar-user-role');
    const avatarEl = document.getElementById('sidebar-user-avatar');
    if (nameEl) nameEl.textContent = this.state.user.full_name;
    if (roleEl) roleEl.textContent = this.state.user.role;
    if (avatarEl) avatarEl.textContent = this.state.user.full_name.split(' ').map(n => n[0]).join('').slice(0, 2);
  },

  async loadCases() {
    try {
      const res = await fetch('/api/cases?include_archived=true');
      const data = await res.json();
      this.state.cases = data.cases || [];

      // Update case dropdown
      const select = document.getElementById('case-select-dropdown');
      if (select) {
        if (this.state.cases.length === 0) {
          select.innerHTML = '<option value="">(No Cases Registered)</option>';
        } else {
          select.innerHTML = this.state.cases.map(c => `
            <option value="${c.id}" ${c.id === this.state.currentCaseId ? 'selected' : ''}>
              ${c.case_number} : ${c.name.slice(0, 32)}
            </option>
          `).join('');
        }
      }

      const casePill = document.getElementById('dock-count-cases');
      if (casePill) casePill.textContent = this.state.cases.length;

      // Select first case if none active
      if (!this.state.currentCaseId && this.state.cases.length > 0) {
        await this.switchCase(this.state.cases[0].id);
      } else if (this.state.currentCaseId) {
        await this.switchCase(this.state.currentCaseId);
      }
    } catch (e) {
      console.error("Failed to load cases:", e);
    }
  },

  async switchCase(caseId) {
    if (!caseId) {
      this.state.currentCaseId = null;
      this.state.currentCase = null;
      this.updateCaseHeroUI();
      this.renderCurrentView();
      return;
    }

    this.state.currentCaseId = parseInt(caseId);
    try {
      const res = await fetch(`/api/cases/${caseId}`);
      if (!res.ok) {
        // If not found, fall back
        this.state.currentCaseId = null;
        this.state.currentCase = null;
        await this.loadCases();
        return;
      }
      const data = await res.json();
      this.state.currentCase = data.case;

      // Sync dropdown
      const select = document.getElementById('case-select-dropdown');
      if (select) select.value = caseId;

      this.updateCaseHeroUI();
      this.updateDockBadges();
      this.renderCurrentView();
    } catch (e) {
      console.error("Error switching case:", e);
    }
  },

  updateCaseHeroUI() {
    const c = this.state.currentCase;
    const banner = document.getElementById('case-hero-banner');
    if (!banner) return;

    if (!c) {
      banner.style.display = 'none';
      return;
    }
    banner.style.display = 'flex';

    document.getElementById('hero-case-num').textContent = c.case_number;
    document.getElementById('hero-case-title').innerHTML = `
      ${c.name}
      ${c.name.includes('[DEMO]') ? '<span class="badge badge-normal" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b;">DEMO / SAMPLE DATA</span>' : ''}
    `;
    document.getElementById('hero-case-investigator').textContent = c.investigator;
    
    const prioEl = document.getElementById('hero-case-priority');
    prioEl.textContent = c.priority;
    prioEl.className = `badge badge-${c.priority.toLowerCase()}`;

    const statusEl = document.getElementById('hero-case-status');
    statusEl.textContent = c.status;
    statusEl.className = `badge badge-${c.status === 'Completed' ? 'verified' : c.status === 'Under Investigation' ? 'critical' : 'normal'}`;

    document.getElementById('hero-case-category').textContent = c.category;
  },

  updateDockBadges() {
    const c = this.state.currentCase;
    if (!c) return;
    const setDock = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val !== undefined ? val : '-';
    };
    setDock('dock-count-evidence', c.evidence_count);
    setDock('dock-count-suspicious', c.suspicious_count);
    setDock('dock-count-timeline', c.timeline_count);
    setDock('dock-count-indicators', c.indicator_count);
    setDock('dock-count-findings', c.finding_count);
  },

  navigate(viewName) {
    this.state.currentView = viewName;
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.view === viewName);
    });
    this.renderCurrentView();
  },

  renderCurrentView() {
    const main = document.getElementById('view-content');
    if (!main) return;

    if (!this.state.currentCase && this.state.currentView !== 'cases') {
      main.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-title">No Active Investigation Case Selected</div>
          <div class="empty-state-desc">Select an existing case, initialize a new case, or load the demo scenario.</div>
          <div style="display: flex; gap: 10px; justify-content: center; margin-top: 14px;">
            <button class="btn btn-primary" onclick="ForensiXApp.showNewCaseModal()">+ New Case</button>
            <button class="btn btn-secondary" onclick="ForensiXApp.seedDemoCase()">Seed Demo Scenario</button>
            <button class="btn btn-secondary" onclick="ForensiXApp.navigate('cases')">View Case Registry</button>
          </div>
        </div>
      `;
      return;
    }

    switch (this.state.currentView) {
      case 'dashboard':
        this.renderDashboard(main);
        break;
      case 'cases':
        this.renderCasesList(main);
        break;
      case 'evidence':
        this.renderEvidenceView(main);
        break;
      case 'browser':
        this.renderBrowserView(main);
        break;
      case 'logs':
        this.renderLogsView(main);
        break;
      case 'suspicious':
        this.renderSuspiciousView(main);
        break;
      case 'indicators':
        this.renderIndicatorsView(main);
        break;
      case 'timeline':
        this.renderTimelineView(main);
        break;
      case 'graph':
        this.renderGraphView(main);
        break;
      case 'visualization':
        this.renderVisualizationView(main);
        break;
      case 'findings':
        this.renderFindingsView(main);
        break;
      case 'custody':
        this.renderCustodyView(main);
        break;
      case 'examiner':
        this.renderExaminerView(main);
        break;
      case 'reports':
        this.renderReportsView(main);
        break;
      default:
        this.renderDashboard(main);
    }
  },

  // ==========================================
  // DASHBOARD VIEW (Tactical Telemetry Matrix)
  // ==========================================
  async renderDashboard(container) {
    const c = this.state.currentCase;
    if (!c) return;

    container.innerHTML = `
      <!-- Telemetry Grid Cards -->
      <div class="telemetry-grid">
        <div class="telemetry-card">
          <div class="telemetry-card-title">
            <span>Evidence Items</span>
            <span>📁</span>
          </div>
          <div class="telemetry-card-val">${c.evidence_count}</div>
          <div class="telemetry-card-sub"><span style="color: var(--accent-mint);">✓ 100%</span> Integrity locked</div>
        </div>
        <div class="telemetry-card ${c.suspicious_count > 0 ? 'alert-threat' : ''}">
          <div class="telemetry-card-title">
            <span>Suspicious Artifacts</span>
            <span>⚠️</span>
          </div>
          <div class="telemetry-card-val">${c.suspicious_count}</div>
          <div class="telemetry-card-sub">Heuristic detections</div>
        </div>
        <div class="telemetry-card">
          <div class="telemetry-card-title">
            <span>Threat IOCs</span>
            <span>🎯</span>
          </div>
          <div class="telemetry-card-val">${c.indicator_count}</div>
          <div class="telemetry-card-sub">IPs, Hashes, Domains</div>
        </div>
        <div class="telemetry-card">
          <div class="telemetry-card-title">
            <span>Timeline Events</span>
            <span>⏱️</span>
          </div>
          <div class="telemetry-card-val">${c.timeline_count}</div>
          <div class="telemetry-card-sub">Chronological span</div>
        </div>
        <div class="telemetry-card">
          <div class="telemetry-card-title">
            <span>Formal Findings</span>
            <span>📝</span>
          </div>
          <div class="telemetry-card-val">${c.finding_count}</div>
          <div class="telemetry-card-sub">Case conclusions</div>
        </div>
        <div class="telemetry-card">
          <div class="telemetry-card-title">
            <span>Custody Records</span>
            <span>🔒</span>
          </div>
          <div class="telemetry-card-val">${c.custody_count}</div>
          <div class="telemetry-card-sub">Audited actions</div>
        </div>
      </div>

      <!-- Investigation Lifecycle Stepper -->
      <div class="stepper-container">
        <div class="panel-header-bar">
          <span>Lifecycle Progress Track — [${c.case_number}]</span>
          <span>Status: <b style="color: var(--text-main);">${c.status}</b></span>
        </div>
        <div class="stepper-row">
          <div class="stepper-item">
            <div class="stepper-lbl"><span>1. Evidence Acquisition</span><span>${c.progress.evidence_collection}%</span></div>
            <div class="stepper-rail"><div class="stepper-fill" style="width: ${c.progress.evidence_collection}%"></div></div>
          </div>
          <div class="stepper-item">
            <div class="stepper-lbl"><span>2. Artifact Analysis</span><span>${c.progress.artifact_analysis}%</span></div>
            <div class="stepper-rail"><div class="stepper-fill" style="width: ${c.progress.artifact_analysis}%"></div></div>
          </div>
          <div class="stepper-item">
            <div class="stepper-lbl"><span>3. Timeline Analysis</span><span>${c.progress.timeline_analysis}%</span></div>
            <div class="stepper-rail"><div class="stepper-fill" style="width: ${c.progress.timeline_analysis}%"></div></div>
          </div>
          <div class="stepper-item">
            <div class="stepper-lbl"><span>4. Examiner Review</span><span>${c.progress.investigation_review}%</span></div>
            <div class="stepper-rail"><div class="stepper-fill" style="width: ${c.progress.investigation_review}%"></div></div>
          </div>
          <div class="stepper-item">
            <div class="stepper-lbl"><span>5. Reporting Deliverable</span><span>${c.progress.reporting}%</span></div>
            <div class="stepper-rail"><div class="stepper-fill" style="width: ${c.progress.reporting}%"></div></div>
          </div>
        </div>
      </div>

      <!-- Split Visualizations -->
      <div class="split-row">
        <div class="card-panel">
          <div class="panel-header-bar">
            <span class="panel-title-text">📈 Incident Activity Over Time</span>
            <button class="btn btn-secondary btn-sm" onclick="ForensiXApp.navigate('timeline')">Open Timeline Stream</button>
          </div>
          <div class="panel-body-content">
            <div style="height: 220px; width: 100%;">
              <canvas id="chart-activity"></canvas>
            </div>
          </div>
        </div>

        <div class="card-panel">
          <div class="panel-header-bar">
            <span class="panel-title-text">📊 Evidence Category Distribution</span>
            <button class="btn btn-secondary btn-sm" onclick="ForensiXApp.navigate('evidence')">Vault Inventory</button>
          </div>
          <div class="panel-body-content">
            <div style="height: 220px; width: 100%;">
              <canvas id="chart-evidence-categories"></canvas>
            </div>
          </div>
        </div>
      </div>

      <!-- Split Triage: Suspicious Artifacts & Findings -->
      <div class="split-row">
        <div class="card-panel">
          <div class="panel-header-bar">
            <span class="panel-title-text">⚠️ Priority Suspicious Detections</span>
            <button class="btn btn-secondary btn-sm" onclick="ForensiXApp.navigate('suspicious')">View All Detections</button>
          </div>
          <div class="panel-body-content" style="padding: 0;">
            <div id="dashboard-suspicious-list">Loading telemetry...</div>
          </div>
        </div>

        <div class="card-panel">
          <div class="panel-header-bar">
            <span class="panel-title-text">📝 Formal Case Findings</span>
            <button class="btn btn-secondary btn-sm" onclick="ForensiXApp.navigate('findings')">View All Findings</button>
          </div>
          <div class="panel-body-content" style="padding: 0;">
            <div id="dashboard-findings-list">Loading findings...</div>
          </div>
        </div>
      </div>
    `;


    this.loadDashboardData(c.id);
  },

  async loadDashboardData(caseId) {
    try {
      const visRes = await fetch(`/api/cases/${caseId}/visualization`);
      const visData = await visRes.json();

      ForensiXCharts.drawDonut('chart-evidence-categories', visData.evidence_categories || {});
      ForensiXCharts.drawBarChart('chart-activity', visData.activity_over_time || [], 'slot', 'count');

      // Load suspicious artifacts strictly for this case
      const suspRes = await fetch(`/api/cases/${caseId}/suspicious-artifacts`);
      const suspData = await suspRes.json();
      const suspList = document.getElementById('dashboard-suspicious-list');
      if (suspList) {
        if (!suspData.suspicious_artifacts || suspData.suspicious_artifacts.length === 0) {
          suspList.innerHTML = `<div style="padding: 24px; text-align: center; color: var(--text-muted);">No suspicious artifacts flagged in this case.</div>`;
        } else {
          suspList.innerHTML = `
            <table class="forensic-table">
              <thead>
                <tr>
                  <th>Evidence</th>
                  <th>Risk</th>
                  <th>Entropy</th>
                  <th>Explainable Detection Reason</th>
                </tr>
              </thead>
              <tbody>
                ${suspData.suspicious_artifacts.slice(0, 4).map(s => `
                  <tr class="clickable" onclick="ForensiXApp.inspectEvidence(${s.evidence_id})">
                    <td><b>${s.evidence_number}</b><br/><span style="font-size: 11px; color: var(--text-dim);">${s.name}</span></td>
                    <td><span class="badge badge-${s.risk_level.toLowerCase()}">${s.risk_level}</span></td>
                    <td class="mono-cell">${s.entropy.toFixed(2)}</td>
                    <td style="font-size: 11.5px; color: var(--text-muted);">${(s.reasons[0] || 'Heuristic alert')}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `;
        }
      }

      // Load findings strictly for this case
      const findRes = await fetch(`/api/cases/${caseId}/findings`);
      const findData = await findRes.json();
      const findList = document.getElementById('dashboard-findings-list');
      if (findList) {
        if (!findData.findings || findData.findings.length === 0) {
          findList.innerHTML = `<div style="padding: 24px; text-align: center; color: var(--text-muted);">No formal findings recorded for this case.</div>`;
        } else {
          findList.innerHTML = `
            <table class="forensic-table">
              <thead>
                <tr>
                  <th>Finding ID</th>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                ${findData.findings.slice(0, 4).map(f => `
                  <tr>
                    <td class="mono-cell"><b>${f.finding_number}</b></td>
                    <td><b>${f.title}</b></td>
                    <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
                    <td><span class="badge badge-normal">${f.status}</span></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `;
        }
      }
    } catch (e) {
      console.error("Failed loading dashboard visuals:", e);
    }
  },

  // ==========================================
  // CASE MANAGEMENT (FULL CRUD)
  // ==========================================
  async renderCasesList(container) {
    const res = await fetch('/api/cases?include_archived=true');
    const data = await res.json();
    const cases = data.cases || [];

    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <div>
          <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Case Management Registry (Full CRUD)</h2>
          <div style="font-size: 12px; color: var(--text-muted);">Create, inspect, modify, and delete digital forensics cases</div>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-secondary" onclick="ForensiXApp.seedDemoCase()">Seed Demo Scenario</button>
          <button class="btn btn-primary" onclick="ForensiXApp.showNewCaseModal()">+ Initialize New Case</button>
        </div>
      </div>

      <div class="card-panel">
        <div class="table-responsive">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>Case Number</th>
                <th>Case Name & Scope</th>
                <th>Category</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Lead Examiner</th>
                <th>Evidence Items</th>
                <th>Findings</th>
                <th style="text-align: right;">Operations (CRUD)</th>
              </tr>
            </thead>
            <tbody>
              ${cases.length === 0 ? '<tr><td colspan="9" style="text-align: center; padding: 30px;">No cases found in database. Create one to begin.</td></tr>' :
                cases.map(c => `
                  <tr class="clickable ${c.id === this.state.currentCaseId ? 'row-active' : ''}" onclick="ForensiXApp.switchCase(${c.id})">
                    <td class="mono-cell"><b>${c.case_number}</b></td>
                    <td>
                      <b>${c.name}</b>
                      <div style="font-size: 11px; color: var(--text-muted); max-width: 280px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
                        ${c.description || '-'}
                      </div>
                    </td>
                    <td>${c.category}</td>
                    <td><span class="badge badge-${c.priority.toLowerCase()}">${c.priority}</span></td>
                    <td><span class="badge badge-normal">${c.status}</span></td>
                    <td>${c.investigator}</td>
                    <td style="text-align: center;"><b>${c.evidence_count}</b></td>
                    <td style="text-align: center;"><b>${c.finding_count}</b></td>
                    <td style="text-align: right;" onclick="event.stopPropagation()">
                      <button class="btn btn-sm btn-primary" onclick="ForensiXApp.switchCase(${c.id}); ForensiXApp.navigate('dashboard');">Open</button>
                      <button class="btn btn-sm btn-secondary" onclick="ForensiXApp.showEditCaseModal(${c.id})">Edit</button>
                      <button class="btn btn-sm btn-danger" onclick="ForensiXApp.confirmDeleteCase(${c.id})">Delete</button>
                    </td>
                  </tr>
                `).join('')
              }
            </tbody>
          </table>
        </div>
      </div>
    `;
  },

  async showEditCaseModal(caseId) {
    try {
      const res = await fetch(`/api/cases/${caseId}`);
      const data = await res.json();
      const c = data.case;
      if (!c) return;

      document.getElementById('edit-case-id').value = c.id;
      document.getElementById('edit-case-name').value = c.name;
      document.getElementById('edit-case-status').value = c.status;
      document.getElementById('edit-case-priority').value = c.priority;
      document.getElementById('edit-case-category').value = c.category;
      document.getElementById('edit-case-investigator').value = c.investigator;
      document.getElementById('edit-case-desc').value = c.description || '';

      document.getElementById('edit-case-modal').classList.add('active');
    } catch (e) {
      this.showToast("Could not load case details for editing", "error");
    }
  },

  confirmDeleteCase(caseId) {
    const c = this.state.cases.find(x => x.id === caseId) || this.state.currentCase;
    if (!c) return;

    this.state.caseToDelete = caseId;
    document.getElementById('delete-case-details').textContent = `${c.case_number} : ${c.name}`;
    document.getElementById('delete-case-modal').classList.add('active');
  },

  async executeDeleteCase() {
    const caseId = this.state.caseToDelete;
    if (!caseId) return;

    try {
      const res = await fetch(`/api/cases/${caseId}`, { method: 'DELETE' });
      const data = await res.json();
      this.closeModal('delete-case-modal');

      if (res.ok) {
        this.showToast(data.message || "Case successfully deleted.", "success");
        await this.loadCases();
        if (this.state.currentCaseId === caseId) {
          await this.switchCase(data.next_case_id);
        }
      } else {
        this.showToast(data.error || "Failed to delete case", "error");
      }
    } catch (e) {
      this.showToast("Network error deleting case", "error");
    }
  },

  // ==========================================
  // SENIOR INVESTIGATION & EXAMINER DOSSIER VIEW
  // ==========================================
  async renderExaminerView(container) {
    const c = this.state.currentCase;
    const user = this.state.user || { full_name: "Alex Vance", role: "Investigator", username: "investigator" };

    let notesHtml = '';
    try {
      const res = await fetch(`/api/notes?case_id=${c ? c.id : 1}`);
      const data = await res.json();
      const notes = data.notes || [];
      notesHtml = notes.map(n => `
        <div style="background: rgba(0,0,0,0.3); border-left: 3px solid var(--accent-cyan); padding: 10px 14px; margin-bottom: 8px; border-radius: 4px;">
          <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 4px;">
            <b style="color: #f1f5f9;">${n.author}</b>
            <span class="mono-cell">${n.created_at}</span>
          </div>
          <div style="font-size: 12px; color: var(--text-muted);">${n.content}</div>
        </div>
      `).join('');
    } catch (e) {}

    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <div>
          <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Investigator Profile</h2>
          <div style="font-size: 12px; color: var(--text-muted);">Active session, assigned case, and investigation notes</div>
        </div>
      </div>

      <div class="split-row">
        <!-- Examiner Profile Card -->
        <div class="card-panel">
          <div class="panel-header-bar">
            <span class="panel-title-text">🕵️ Examiner Credentials</span>
            <span class="badge badge-verified">ACTIVE SESSION</span>
          </div>
          <div class="panel-body-content">
            <div style="display: flex; gap: 16px; align-items: center; margin-bottom: 20px;">
              <div style="width: 56px; height: 56px; border-radius: 8px; background: linear-gradient(135deg, #0284c7, #00f0ff); display: flex; align-items: center; justify-content: center; font-size: 22px; font-weight: 900; color: #05080f;">
                ${user.full_name.split(' ').map(n=>n[0]).join('').slice(0, 2)}
              </div>
              <div>
                <h3 style="font-size: 16px; font-weight: 800; color: #fff;">${user.full_name}</h3>
                <div style="font-size: 12px; color: var(--accent-cyan);">${user.role}</div>
                <div style="font-size: 11px; color: var(--text-dim);">Account: @${user.username}</div>
              </div>
            </div>

            <div class="kv-grid">
              <div class="kv-key">Security Clearance:</div>
              <div class="kv-value"><span class="badge badge-critical">LEVEL 5 // SPECIAL ACCESS FORENSICS</span></div>
              <div class="kv-key">Assigned Case:</div>
              <div class="kv-value"><b>${c ? `${c.case_number} - ${c.name}` : 'None'}</b></div>
              <div class="kv-key">Case Category:</div>
              <div class="kv-value">${c ? c.category : 'N/A'}</div>
              <div class="kv-key">Forensic Role:</div>
              <div class="kv-value">Investigator</div>
              <div class="kv-key">Signing Fingerprint:</div>
              <div class="kv-value mono-cell" style="font-size: 10px;">SHA256:d8a4f91b72e90c41b83d... (VALID)</div>
            </div>
          </div>
        </div>

        <!-- Case Notes & Investigator Journal -->
        <div class="card-panel">
          <div class="panel-header-bar">
            <span class="panel-title-text">📓 Examiner Journal & Case Notes</span>
          </div>
          <div class="panel-body-content">
            <div style="margin-bottom: 14px;">
              <textarea id="examiner-new-note" class="form-control" placeholder="Log technical forensic notes or examination observations..." style="min-height: 70px;"></textarea>
              <div style="display: flex; justify-content: flex-end; margin-top: 6px;">
                <button class="btn btn-primary btn-sm" onclick="ForensiXApp.addExaminerNote()">+ Append Examiner Note</button>
              </div>
            </div>
            <div style="font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase; margin-bottom: 8px;">Case Examination Log:</div>
            <div style="max-height: 220px; overflow-y: auto;">
              ${notesHtml || '<div style="color: var(--text-dim); font-size: 12px;">No investigator notes recorded yet.</div>'}
            </div>
          </div>
        </div>
      </div>
    `;
  },

  async addExaminerNote() {
    const input = document.getElementById('examiner-new-note');
    if (!input || !input.value.trim()) return;

    try {
      const res = await fetch('/api/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: this.state.currentCaseId,
          target_type: 'case',
          target_id: this.state.currentCaseId,
          content: input.value.trim()
        })
      });
      if (res.ok) {
        this.showToast("Examiner note appended.", "success");
        input.value = '';
        this.renderExaminerView(document.getElementById('view-content'));
      }
    } catch (e) {
      this.showToast("Failed to save note", "error");
    }
  },

  // ==========================================
  // EVIDENCE INVENTORY (Strictly Scoped)
  // ==========================================
  async renderEvidenceView(container) {
    const caseId = this.state.currentCaseId;
    const res = await fetch(`/api/cases/${caseId}/evidence`);
    const data = await res.json();
    this.state.evidenceList = data.evidence || [];

    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div>
          <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Evidence Vault & Inventory</h2>
          <div style="font-size: 12px; color: var(--text-muted);">Cryptographic baseline verification for Case <b>[${this.state.currentCase.case_number}]</b></div>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-secondary btn-sm" onclick="ForensiXApp.showHashCompareModal()">Hash Verification Tool</button>
          <button class="btn btn-primary btn-sm" onclick="ForensiXApp.showUploadEvidenceModal()">+ Add Evidence</button>
        </div>
      </div>

      <div style="display: flex; gap: 10px; margin-bottom: 14px;">
        <select class="form-control" style="width: 170px;" onchange="ForensiXApp.filterEvidence(this.value, 'category')">
          <option value="All">All Categories</option>
          <option value="Documents">Documents</option>
          <option value="Images">Images</option>
          <option value="Executables">Executables</option>
          <option value="Logs">Logs</option>
          <option value="Browser Artifacts">Browser Artifacts</option>
          <option value="Archives">Archives</option>
        </select>
        <select class="form-control" style="width: 170px;" onchange="ForensiXApp.filterEvidence(this.value, 'status')">
          <option value="All">All Review Statuses</option>
          <option value="Not Reviewed">Not Reviewed</option>
          <option value="Under Review">Under Review</option>
          <option value="Reviewed">Reviewed</option>
          <option value="Requires Attention">Requires Attention</option>
        </select>
        <input type="text" class="form-control" style="width: 250px;" placeholder="Search name, location, or hash..." oninput="ForensiXApp.filterEvidence(this.value, 'search')" />
      </div>

      <div class="card-panel">
        <div class="table-responsive">
          <table class="forensic-table" id="evidence-table">
            <thead>
              <tr>
                <th>Item ID</th>
                <th>Evidence Name</th>
                <th>Category</th>
                <th>Original Location</th>
                <th>Size</th>
                <th>SHA-256 Hash</th>
                <th>Integrity</th>
                <th>Review Status</th>
                <th style="text-align: right;">Action</th>
              </tr>
            </thead>
            <tbody>
              ${this.renderEvidenceRows(this.state.evidenceList)}
            </tbody>
          </table>
        </div>
      </div>
    `;
  },

  renderEvidenceRows(items) {
    if (!items || items.length === 0) {
      return `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 30px;">No evidence records found for this case.</td></tr>`;
    }
    return items.map(ev => {
      const hashShort = ev.sha256 ? `${ev.sha256.slice(0, 16)}...` : 'None';
      const isSusp = ev.is_suspicious;
      return `
        <tr class="clickable" onclick="ForensiXApp.inspectEvidence(${ev.id})">
          <td class="mono-cell"><b>${ev.evidence_number}</b></td>
          <td>
            <b>${ev.name}</b>
            ${isSusp ? `<br/><span class="badge badge-suspicious" style="font-size: 10px;">⚠️ ${ev.risk_level} Risk</span>` : ''}
          </td>
          <td>${ev.category}</td>
          <td style="font-size: 11px; color: var(--text-dim); max-width: 200px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">
            ${ev.original_location || '-'}
          </td>
          <td>${ev.file_size ? `${(ev.file_size / 1024).toFixed(1)} KB` : '0 KB'}</td>
          <td class="mono-cell" title="${ev.sha256}">${hashShort}</td>
          <td>
            <span class="badge ${ev.integrity_status === 'VERIFIED' ? 'badge-verified' : 'badge-suspicious'}">
              ✓ ${ev.integrity_status}
            </span>
          </td>
          <td>
            <span class="badge ${ev.review_status === 'Requires Attention' ? 'badge-suspicious' : ev.review_status === 'Reviewed' ? 'badge-verified' : 'badge-normal'}">
              ${ev.review_status}
            </span>
          </td>
          <td style="text-align: right;" onclick="event.stopPropagation()">
            <button class="btn btn-sm btn-secondary" onclick="ForensiXApp.verifyEvidenceHash(${ev.id})">Verify</button>
            <button class="btn btn-sm btn-primary" onclick="ForensiXApp.inspectEvidence(${ev.id})">Inspect</button>
          </td>
        </tr>
      `;
    }).join('');
  },

  filterEvidence(val, type) {
    const q = (val || '').toLowerCase();
    const rows = this.state.evidenceList.filter(ev => {
      if (type === 'category' && val !== 'All') return ev.category === val;
      if (type === 'status' && val !== 'All') return ev.review_status === val;
      if (type === 'search') {
        return ev.name.toLowerCase().includes(q) || (ev.original_location && ev.original_location.toLowerCase().includes(q)) || (ev.sha256 && ev.sha256.toLowerCase().includes(q));
      }
      return true;
    });
    const tbody = document.querySelector('#evidence-table tbody');
    if (tbody) tbody.innerHTML = this.renderEvidenceRows(rows);
  },

  // ==========================================
  // BROWSER VIEW (Strictly Scoped)
  // ==========================================
  async renderBrowserView(container) {
    const caseId = this.state.currentCaseId;
    const res = await fetch(`/api/cases/${caseId}/browser-artifacts`);
    const data = await res.json();
    const artifacts = data.artifacts || [];

    container.innerHTML = `
      <div style="margin-bottom: 16px;">
        <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Browser Artifacts & Web Telemetry</h2>
        <div style="font-size: 12px; color: var(--text-muted);">Extracted web history, downloads, search queries, and cookies for Case <b>[${this.state.currentCase.case_number}]</b></div>
      </div>

      <div class="card-panel">
        <div class="table-responsive">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Type</th>
                <th>Browser</th>
                <th>Domain</th>
                <th>Target URL / Title</th>
                <th>Details</th>
                <th>Source Item</th>
              </tr>
            </thead>
            <tbody>
              ${artifacts.length === 0 ? '<tr><td colspan="7" style="text-align: center; padding: 24px;">No browser artifacts extracted for this case.</td></tr>' : 
                artifacts.map(b => `
                  <tr>
                    <td class="mono-cell">${b.timestamp}</td>
                    <td><span class="badge badge-normal">${b.artifact_type}</span></td>
                    <td>${b.browser}</td>
                    <td><b>${b.domain || '-'}</b></td>
                    <td>
                      <div style="font-weight: 600;">${b.title}</div>
                      <div style="font-size: 11px; color: var(--accent-cyan); word-break: break-all;">${b.url}</div>
                    </td>
                    <td style="font-size: 11px; color: var(--text-dim);">${b.details || '-'}</td>
                    <td><span class="mono-cell">${b.evidence_number || '-'}</span></td>
                  </tr>
                `).join('')
              }
            </tbody>
          </table>
        </div>
      </div>
    `;
  },

  // ==========================================
  // FORENSIC LOGS VIEW (Strictly Scoped)
  // ==========================================
  async renderLogsView(container) {
    const caseId = this.state.currentCaseId;
    const res = await fetch(`/api/cases/${caseId}/logs`);
    const data = await res.json();
    const logs = data.logs || [];

    container.innerHTML = `
      <div style="margin-bottom: 16px;">
        <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Forensic Log Analysis & Explanations</h2>
        <div style="font-size: 12px; color: var(--text-muted);">Parsed security, system, and web access logs for Case <b>[${this.state.currentCase.case_number}]</b></div>
      </div>

      <div class="card-panel">
        <div class="table-responsive">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>User</th>
                <th>Source IP</th>
                <th>Dest IP</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Heuristic Flag</th>
                <th>Details / Reason</th>
              </tr>
            </thead>
            <tbody>
              ${logs.length === 0 ? '<tr><td colspan="9" style="text-align: center; padding: 24px;">No log records present for this case.</td></tr>' : 
                logs.map(l => `
                  <tr>
                    <td class="mono-cell">${l.timestamp}</td>
                    <td><b>${l.event_type}</b></td>
                    <td>${l.username}</td>
                    <td class="mono-cell">${l.source_ip}</td>
                    <td class="mono-cell">${l.dest_ip}</td>
                    <td>${l.status}</td>
                    <td><span class="badge badge-${l.severity.toLowerCase()}">${l.severity}</span></td>
                    <td>
                      <span class="badge ${l.suspicious_flag === 'Potentially Suspicious' ? 'badge-suspicious' : l.suspicious_flag === 'Requires Review' ? 'badge-high' : 'badge-normal'}">
                        ${l.suspicious_flag}
                      </span>
                    </td>
                    <td style="font-size: 11.5px;">
                      <div>${l.message}</div>
                      ${l.flag_reason ? `<div style="color: var(--accent-red); font-weight: 600; font-size: 11px; margin-top: 2px;">• ${l.flag_reason}</div>` : ''}
                    </td>
                  </tr>
                `).join('')
              }
            </tbody>
          </table>
        </div>
      </div>
    `;
  },

  // ==========================================
  // SUSPICIOUS DETECTIONS VIEW
  // ==========================================
  async renderSuspiciousView(container) {
    const caseId = this.state.currentCaseId;
    const res = await fetch(`/api/cases/${caseId}/suspicious-artifacts`);
    const data = await res.json();
    const artifacts = data.suspicious_artifacts || [];

    container.innerHTML = `
      <div style="margin-bottom: 16px;">
        <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Suspicious Detections & Entropy Analysis</h2>
        <div style="font-size: 12px; color: var(--text-muted);">Explainable rule-based flags for Case <b>[${this.state.currentCase.case_number}]</b></div>
      </div>

      <div style="display: flex; flex-direction: column; gap: 14px;">
        ${artifacts.length === 0 ? `
          <div class="empty-state">
            <div class="empty-state-title">No Suspicious Artifacts Flagged</div>
            <div class="empty-state-desc">All evaluated evidence items in this case conform to standard security baselines.</div>
          </div>
        ` : 
          artifacts.map(s => `
            <div class="card-panel" style="border-left: 4px solid var(--accent-red);">
              <div class="panel-header-bar">
                <div style="display: flex; align-items: center; gap: 10px;">
                  <span class="badge badge-${s.risk_level.toLowerCase()}">${s.risk_level} Risk</span>
                  <span style="font-size: 14px; font-weight: 800; color: #fff;">[${s.evidence_number}] ${s.name}</span>
                </div>
                <button class="btn btn-primary btn-sm" onclick="ForensiXApp.inspectEvidence(${s.evidence_id})">Inspect Full Evidence</button>
              </div>
              <div class="panel-body-content">
                <div class="kv-grid" style="margin-bottom: 12px;">
                  <div class="kv-key">Original Location:</div>
                  <div class="kv-value mono-cell">${s.original_location || 'Not Available'}</div>
                  <div class="kv-key">Shannon Entropy:</div>
                  <div class="kv-value mono-cell"><b>${s.entropy.toFixed(3)}</b> / 8.000 ${s.entropy > 7.2 ? '<span style="color: var(--accent-red); font-weight: 700;">(Elevated Packing/Encryption)</span>' : ''}</div>
                  <div class="kv-key">SHA-256 Hash:</div>
                  <div class="kv-value mono-cell">${s.sha256}</div>
                </div>

                <div style="background: rgba(255, 51, 75, 0.08); border: 1px solid rgba(255, 51, 75, 0.25); border-radius: var(--radius-xs); padding: 10px 14px;">
                  <div style="font-size: 11px; font-weight: 800; text-transform: uppercase; color: var(--accent-red); margin-bottom: 6px;">
                    Explainable Detection Reasons:
                  </div>
                  <ul style="padding-left: 18px; font-size: 12px;">
                    ${s.reasons.map(r => `<li style="margin-bottom: 3px;">${r}</li>`).join('')}
                  </ul>
                </div>
              </div>
            </div>
          `).join('')
        }
      </div>
    `;
  },

  // ==========================================
  // TIMELINE VIEW
  // ==========================================
  async renderTimelineView(container) {
    const caseId = this.state.currentCaseId;
    const res = await fetch(`/api/cases/${caseId}/timeline`);
    const data = await res.json();
    this.state.timelineEvents = data.events || [];

    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div>
          <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Master Forensic Timeline</h2>
          <div style="font-size: 12px; color: var(--text-muted);">Correlated chronological event sequence for Case <b>[${this.state.currentCase.case_number}]</b></div>
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
        <div style="display: flex; gap: 6px;">
          <button class="btn btn-sm btn-secondary active" onclick="ForensiXTimeline.filterCategory('All')">All</button>
          <button class="btn btn-sm btn-secondary" onclick="ForensiXTimeline.filterCategory('File System')">File System</button>
          <button class="btn btn-sm btn-secondary" onclick="ForensiXTimeline.filterCategory('Authentication')">Authentication</button>
          <button class="btn btn-sm btn-secondary" onclick="ForensiXTimeline.filterCategory('Browser')">Browser</button>
          <button class="btn btn-sm btn-secondary" onclick="ForensiXTimeline.filterCategory('Network')">Network</button>
          <button class="btn btn-sm btn-secondary" onclick="ForensiXTimeline.filterCategory('System')">System</button>
          <button class="btn btn-sm btn-secondary" onclick="ForensiXTimeline.filterCategory('Investigation')">Investigation</button>
        </div>
        <input type="text" class="form-control" style="width: 240px;" placeholder="Search timeline events..." oninput="ForensiXTimeline.filterSearch(this.value)" />
      </div>

      <div class="card-panel" style="padding: 20px;">
        <div id="timeline-stream-container" class="timeline-stream"></div>
      </div>
    `;

    ForensiXTimeline.setEvents(this.state.timelineEvents);
  },

  // ==========================================
  // RELATIONSHIP GRAPH VIEW
  // ==========================================
  async renderGraphView(container) {
    const caseId = this.state.currentCaseId;

    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
        <div>
          <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Evidence Entity Relationship Graph</h2>
          <div style="font-size: 12px; color: var(--text-muted);">Interactive force-directed graph connecting evidence, hashes, IPs, and domains for <b>[${this.state.currentCase.case_number}]</b></div>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="window.graphInstance.resetZoom()">Reset Center View</button>
      </div>

      <div class="graph-viewport-container">
        <div class="graph-toolbar">
          <span style="font-size: 10.5px; font-weight: 800; color: var(--accent-cyan); padding: 4px 6px;">TACTICAL CANVAS</span>
          <span style="font-size: 10.5px; color: var(--text-dim); padding: 4px 6px;">• Scroll: Zoom • Drag Node / Pan Camera</span>
        </div>

        <div class="graph-legend">
          <div class="legend-item"><div class="legend-dot" style="background: #f59e0b;"></div> Case</div>
          <div class="legend-item"><div class="legend-dot" style="background: #6366f1;"></div> Evidence</div>
          <div class="legend-item"><div class="legend-dot" style="background: #a855f7;"></div> Hash</div>
          <div class="legend-item"><div class="legend-dot" style="background: #f43f5e;"></div> IP Address</div>
          <div class="legend-item"><div class="legend-dot" style="background: #10b981;"></div> Domain / URL</div>
          <div class="legend-item"><div class="legend-dot" style="background: #06b6d4;"></div> Username</div>
        </div>

        <div id="graph-inspector" class="graph-inspector-panel"></div>
        <canvas id="relationship-canvas" class="graph-canvas"></canvas>
      </div>
    `;

    const res = await fetch(`/api/cases/${caseId}/graph`);
    const graphData = await res.json();

    window.graphInstance = new ForensiXGraph('relationship-canvas', 'graph-inspector');
    window.graphInstance.setData(graphData);
  },

  // ==========================================
  // INDICATORS (IOC) VIEW
  // ==========================================
  async renderIndicatorsView(container) {
    const caseId = this.state.currentCaseId;
    const res = await fetch(`/api/cases/${caseId}/indicators`);
    const data = await res.json();
    this.state.indicators = data.indicators || [];

    container.innerHTML = `
      <div style="margin-bottom: 16px;">
        <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Threat Indicators & IOC Registry</h2>
        <div style="font-size: 12px; color: var(--text-muted);">Extracted network indicators, malicious domains, and hashes for Case <b>[${this.state.currentCase.case_number}]</b></div>
      </div>

      <div class="card-panel">
        <div class="table-responsive">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>Mark</th>
                <th>Indicator Value</th>
                <th>Type</th>
                <th>Hits</th>
                <th>Source Item</th>
                <th>Tags</th>
                <th>Forensic Context</th>
              </tr>
            </thead>
            <tbody>
              ${this.state.indicators.length === 0 ? '<tr><td colspan="7" style="text-align: center; padding: 24px;">No indicators registered for this case.</td></tr>' :
                this.state.indicators.map(ind => `
                  <tr>
                    <td style="text-align: center; cursor: pointer;" onclick="ForensiXApp.toggleBookmark(${ind.id})">
                      ${ind.is_bookmarked ? '⭐' : '☆'}
                    </td>
                    <td><b>${ind.indicator_value}</b></td>
                    <td><span class="badge badge-normal">${ind.indicator_type}</span></td>
                    <td style="text-align: center;"><b>${ind.occurrence_count}</b></td>
                    <td>${ind.evidence_number ? `<a href="javascript:void(0)" onclick="ForensiXApp.inspectEvidence(${ind.evidence_id})">${ind.evidence_number}</a>` : '-'}</td>
                    <td>${ind.tags ? `<span class="badge badge-normal">${ind.tags}</span>` : '-'}</td>
                    <td style="font-size: 11.5px; color: var(--text-muted);">${ind.notes || '-'}</td>
                  </tr>
                `).join('')
              }
            </tbody>
          </table>
        </div>
      </div>
    `;
  },

  async toggleBookmark(indId) {
    await fetch(`/api/indicators/${indId}/bookmark`, { method: 'POST' });
    this.renderIndicatorsView(document.getElementById('view-content'));
  },

  // ==========================================
  // FINDINGS VIEW
  // ==========================================
  async renderFindingsView(container) {
    const caseId = this.state.currentCaseId;
    const res = await fetch(`/api/cases/${caseId}/findings`);
    const data = await res.json();
    this.state.findings = data.findings || [];

    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <div>
          <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Formal Case Findings</h2>
          <div style="font-size: 12px; color: var(--text-muted);">Validated conclusions for Case <b>[${this.state.currentCase.case_number}]</b></div>
        </div>
        <button class="btn btn-primary btn-sm" onclick="ForensiXApp.showNewFindingModal()">+ Log New Finding</button>
      </div>

      <div style="display: flex; flex-direction: column; gap: 14px;">
        ${this.state.findings.length === 0 ? `
          <div class="empty-state">
            <div class="empty-state-title">No Findings Recorded</div>
            <div class="empty-state-desc">Document confirmed intrusion milestones or analysis conclusions.</div>
          </div>
        ` : 
          this.state.findings.map(f => `
            <div class="card-panel">
              <div class="panel-header-bar">
                <div style="display: flex; align-items: center; gap: 10px;">
                  <span class="mono-cell"><b>${f.finding_number}</b></span>
                  <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
                  <span style="font-size: 14px; font-weight: 800; color: #fff;">${f.title}</span>
                </div>
                <span class="badge badge-normal">${f.status}</span>
              </div>
              <div class="panel-body-content">
                <p style="font-size: 13px; color: var(--text-main); margin-bottom: 12px;">${f.description}</p>
                ${f.explainable_basis ? `
                  <div style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); border-radius: var(--radius-xs); padding: 10px; font-size: 12px;">
                    <b style="color: var(--accent-cyan);">Explainable Evidentiary Basis:</b> ${f.explainable_basis}
                  </div>
                ` : ''}
              </div>
            </div>
          `).join('')
        }
      </div>
    `;
  },

  // ==========================================
  // ANALYTICS & VISUALIZATION VIEW
  // ==========================================
  async renderVisualizationView(container) {
    const caseId = this.state.currentCaseId;
    const res = await fetch(`/api/cases/${caseId}/visualization`);
    const data = await res.json();

    container.innerHTML = `
      <div style="margin-bottom: 16px;">
        <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Investigation Telemetry Analytics</h2>
        <div style="font-size: 12px; color: var(--text-muted);">Visual distributions for Case <b>[${this.state.currentCase.case_number}]</b></div>
      </div>

      <div class="split-row">
        <div class="card-panel">
          <div class="panel-header-bar"><span class="panel-title-text">Evidence Category Breakdown</span></div>
          <div class="panel-body-content"><div style="height: 240px;"><canvas id="vis-evidence-cats"></canvas></div></div>
        </div>
        <div class="card-panel">
          <div class="panel-header-bar"><span class="panel-title-text">Indicator (IOC) Types</span></div>
          <div class="panel-body-content"><div style="height: 240px;"><canvas id="vis-indicators-types"></canvas></div></div>
        </div>
      </div>

      <div class="split-row">
        <div class="card-panel">
          <div class="panel-header-bar"><span class="panel-title-text">Evidence Review Status</span></div>
          <div class="panel-body-content"><div style="height: 240px;"><canvas id="vis-review-status"></canvas></div></div>
        </div>
        <div class="card-panel">
          <div class="panel-header-bar"><span class="panel-title-text">Timeline Event Categories</span></div>
          <div class="panel-body-content"><div style="height: 240px;"><canvas id="vis-timeline-cats"></canvas></div></div>
        </div>
      </div>
    `;

    ForensiXCharts.drawDonut('vis-evidence-cats', data.evidence_categories || {});
    ForensiXCharts.drawDonut('vis-indicators-types', data.indicator_distribution || {});
    ForensiXCharts.drawDonut('vis-review-status', data.review_status || {});
    ForensiXCharts.drawDonut('vis-timeline-cats', data.timeline_categories || {});
  },

  // ==========================================
  // CHAIN OF CUSTODY VIEW
  // ==========================================
  async renderCustodyView(container) {
    const caseId = this.state.currentCaseId;
    const res = await fetch(`/api/cases/${caseId}/chain-of-custody`);
    const data = await res.json();
    const custody = data.custody_log || [];

    container.innerHTML = `
      <div style="margin-bottom: 16px;">
        <h2 style="font-size: 18px; font-weight: 800; color: var(--text-main);">Immutable Chain of Custody Ledger</h2>
        <div style="font-size: 12px; color: var(--text-muted);">Audited evidence handling history for Case <b>[${this.state.currentCase.case_number}]</b></div>
      </div>

      <div class="card-panel">
        <div class="table-responsive">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Evidence ID</th>
                <th>Evidence Name</th>
                <th>Action Taken</th>
                <th>Examiner</th>
                <th>Integrity Information / Hashes</th>
                <th>Custody Notes</th>
              </tr>
            </thead>
            <tbody>
              ${custody.length === 0 ? '<tr><td colspan="7" style="text-align: center; padding: 24px;">No chain of custody events recorded for this case.</td></tr>' :
                custody.map(c => `
                  <tr>
                    <td class="mono-cell">${c.timestamp}</td>
                    <td class="mono-cell"><b>${c.evidence_number}</b></td>
                    <td>${c.evidence_name}</td>
                    <td><b>${c.action}</b></td>
                    <td>${c.performed_by}</td>
                    <td class="mono-cell" style="font-size: 11px;">${c.integrity_hash || '-'}</td>
                    <td style="font-size: 11.5px; color: var(--text-muted);">${c.description || '-'}</td>
                  </tr>
                `).join('')
              }
            </tbody>
          </table>
        </div>
      </div>
    `;
  },

  // ==========================================
  // REPORTS VIEW
  // ==========================================
  async renderReportsView(container) {
    const caseId = this.state.currentCaseId;
    const res = await fetch(`/api/cases/${caseId}/reports`);
    const data = await res.json();
    const reports = data.reports || [];
    const caseNum = this.state.currentCase.case_number;

    container.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; flex-wrap:wrap; gap:8px;">
        <div>
          <h2 style="font-size:18px; font-weight:800; color:var(--text-main);">Reports &amp; Exports</h2>
          <div style="font-size:12px; color:var(--text-muted);">Case <b>${caseNum}</b></div>
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
          <button class="btn btn-primary" onclick="ForensiXApp.generateReportNow()">PDF Report</button>
          <button class="btn btn-secondary" onclick="ForensiXApp.generateDocxNow()">Word (.docx)</button>
          <a href="/api/cases/${caseId}/export/json" class="btn btn-secondary" download>JSON Export</a>
          <a href="/api/cases/${caseId}/export/csv" class="btn btn-secondary" download>CSV Export</a>
        </div>
      </div>

      <div class="card-panel">
        <div class="table-responsive">
          <table class="forensic-table">
            <thead>
              <tr>
                <th>Report ID</th>
                <th>Title</th>
                <th>Generated By</th>
                <th>Timestamp</th>
                <th style="text-align:right;">Download</th>
              </tr>
            </thead>
            <tbody>
              ${reports.length === 0
                ? '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-muted);">No reports yet. Click a button above to generate one.</td></tr>'
                : reports.map(r => `
                  <tr>
                    <td class="mono-cell"><b>${r.report_number}</b></td>
                    <td>${r.title}</td>
                    <td>${r.generated_by}</td>
                    <td class="mono-cell">${r.created_at}</td>
                    <td style="text-align:right;">
                      <a href="/api/reports/${r.id}/download" class="btn btn-sm btn-primary" target="_blank">PDF</a>
                      <a href="/api/reports/${r.id}/download/docx" class="btn btn-sm btn-secondary" target="_blank">DOCX</a>
                    </td>
                  </tr>
                `).join('')
              }
            </tbody>
          </table>
        </div>
      </div>
    `;
  },

  async generateReportNow() {
    const caseId = this.state.currentCaseId;
    this.showToast("Generating PDF report...", "info");
    try {
      const res = await fetch(`/api/cases/${caseId}/reports/generate`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        this.showToast("PDF report ready!", "success");
        if (this.state.currentView === 'reports') {
          this.renderReportsView(document.getElementById('view-content'));
        }
      } else {
        this.showToast(data.error || "Report generation failed", "error");
      }
    } catch (e) {
      this.showToast("Network error", "error");
    }
  },

  async generateDocxNow() {
    const caseId = this.state.currentCaseId;
    this.showToast("Generating Word report...", "info");
    try {
      const res = await fetch(`/api/cases/${caseId}/reports/generate/docx`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        this.showToast("Word report ready! Download DOCX from table below.", "success");
        if (this.state.currentView === 'reports') {
          this.renderReportsView(document.getElementById('view-content'));
        }
      } else {
        this.showToast(data.error || "DOCX generation failed", "error");
      }
    } catch (e) {
      this.showToast("Network error", "error");
    }
  },

  // ==========================================
  // EVIDENCE INSPECTOR DRAWER
  // ==========================================
  async inspectEvidence(evId) {
    const drawer = document.getElementById('evidence-drawer');
    const backdrop = document.getElementById('drawer-backdrop');
    if (!drawer || !backdrop) return;

    backdrop.classList.add('active');
    drawer.classList.add('open');

    const body = document.getElementById('drawer-content');
    body.innerHTML = `<div class="loading-indicator"><div class="spinner"></div> Extracting forensic metadata...</div>`;

    try {
      const res = await fetch(`/api/evidence/${evId}`);
      const data = await res.json();
      const ev = data.evidence;

      document.getElementById('drawer-evidence-title').textContent = `[${ev.evidence_number}] ${ev.name}`;

      let metaHtml = '';
      (ev.metadata || []).forEach(m => {
        metaHtml += `<div class="kv-key">${m.meta_key}:</div><div class="kv-value">${m.meta_value}</div>`;
      });

      let previewContent = '';
      if (ev.preview.type === 'text') {
        previewContent = `<div class="preview-box">${ev.preview.content}</div>`;
      } else if (ev.preview.type === 'hex') {
        previewContent = `<div class="preview-box">${ev.preview.content}</div>`;
      } else {
        previewContent = `<div style="font-size: 12px; color: var(--text-dim);">No direct binary preview available for this file type.</div>`;
      }

      body.innerHTML = `
        <div style="display: flex; gap: 8px; margin-bottom: 16px;">
          <span class="badge ${ev.integrity_status === 'VERIFIED' ? 'badge-verified' : 'badge-suspicious'}">
            ✓ ${ev.integrity_status}
          </span>
          <span class="badge badge-normal">${ev.category}</span>
          ${ev.suspicious_analysis ? `<span class="badge badge-suspicious">⚠️ ${ev.suspicious_analysis.risk_level} Risk</span>` : ''}
        </div>

        <div class="tabs-header">
          <button class="tab-btn active" onclick="ForensiXApp.switchDrawerTab('tab-meta', this)">Metadata</button>
          <button class="tab-btn" onclick="ForensiXApp.switchDrawerTab('tab-hashes', this)">Hashes</button>
          <button class="tab-btn" onclick="ForensiXApp.switchDrawerTab('tab-preview', this)">File Preview</button>
          <button class="tab-btn" onclick="ForensiXApp.switchDrawerTab('tab-custody', this)">Custody Trail</button>
        </div>

        <div id="tab-meta" class="drawer-tab-pane">
          <div class="kv-grid">
            <div class="kv-key">Original File:</div><div class="kv-value">${ev.original_filename}</div>
            <div class="kv-key">Acquired Path:</div><div class="kv-value mono-cell">${ev.original_location || 'Not Available'}</div>
            <div class="kv-key">File Size:</div><div class="kv-value">${ev.file_size ? `${ev.file_size.toLocaleString()} bytes` : 'Not Available'}</div>
            <div class="kv-key">Acquisition Date:</div><div class="kv-value">${ev.acquisition_date}</div>
            <div class="kv-key">Lead Examiner:</div><div class="kv-value">${ev.investigator}</div>
            ${metaHtml}
          </div>
        </div>

        <div id="tab-hashes" class="drawer-tab-pane" style="display: none;">
          <div class="kv-grid">
            <div class="kv-key">MD5:</div><div class="kv-value mono-cell">${ev.md5 || 'Not Available'}</div>
            <div class="kv-key">SHA-1:</div><div class="kv-value mono-cell">${ev.sha1 || 'Not Available'}</div>
            <div class="kv-key">SHA-256:</div><div class="kv-value mono-cell">${ev.sha256 || 'Not Available'}</div>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="ForensiXApp.verifyEvidenceHash(${ev.id})">Re-Verify Integrity Now</button>
        </div>

        <div id="tab-preview" class="drawer-tab-pane" style="display: none;">
          <div style="font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase; margin-bottom: 6px;">Forensic Raw Extract:</div>
          ${previewContent}
        </div>

        <div id="tab-custody" class="drawer-tab-pane" style="display: none;">
          <div style="display: flex; flex-direction: column; gap: 8px;">
            ${(ev.custody_log || []).map(c => `
              <div style="background: rgba(0,0,0,0.25); border-left: 2px solid var(--accent-cyan); padding: 8px 10px; font-size: 11.5px;">
                <div style="display: flex; justify-content: space-between; font-weight: 600; color: #f1f5f9;">
                  <span>${c.action}</span>
                  <span class="mono-cell">${c.timestamp}</span>
                </div>
                <div style="color: var(--text-dim); font-size: 10.5px;">By: ${c.performed_by}</div>
                <div style="color: var(--text-muted); margin-top: 4px;">${c.description}</div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    } catch (e) {
      body.innerHTML = `<div style="color: var(--accent-red); padding: 20px;">Failed to inspect evidence: ${e.message}</div>`;
    }
  },

  closeDrawer() {
    const drawer = document.getElementById('evidence-drawer');
    const backdrop = document.getElementById('drawer-backdrop');
    if (drawer) drawer.classList.remove('open');
    if (backdrop) backdrop.classList.remove('active');
  },

  switchDrawerTab(paneId, btn) {
    document.querySelectorAll('.drawer-tab-pane').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    const target = document.getElementById(paneId);
    if (target) target.style.display = 'block';
    if (btn) btn.classList.add('active');
  },

  async verifyEvidenceHash(evId) {
    this.showToast("Calculating cryptographic hashes against disk vault...", "info");
    try {
      const res = await fetch(`/api/evidence/${evId}/verify`, { method: 'POST' });
      const data = await res.json();
      if (data.is_match) {
        this.showToast("Integrity verified: SHA-256 match confirmed.", "success");
      } else {
        this.showToast("INTEGRITY MISMATCH: Hash differs from recorded baseline!", "error");
      }
      if (this.state.currentView === 'evidence') {
        this.renderEvidenceView(document.getElementById('view-content'));
      }
    } catch (e) {
      this.showToast("Verification failed", "error");
    }
  },

  // ==========================================
  // MODALS & EVENT HANDLERS
  // ==========================================
  showUploadEvidenceModal() {
    document.getElementById('upload-evidence-modal').classList.add('active');
  },

  showNewCaseModal() {
    document.getElementById('new-case-modal').classList.add('active');
  },

  showNewFindingModal() {
    document.getElementById('new-finding-modal').classList.add('active');
  },

  showHashCompareModal() {
    document.getElementById('hash-compare-modal').classList.add('active');
  },

  closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
  },

  async seedDemoCase() {
    this.showToast("Seeding complete forensic scenario FL-2026-001...", "info");
    try {
      const res = await fetch('/api/cases/seed-demo', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        this.showToast("Sample case seeded successfully.", "success");
        await this.loadCases();
        await this.switchCase(data.case_id);
      }
    } catch (e) {
      this.showToast("Failed to seed demo scenario", "error");
    }
  },

  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span>${type === 'success' ? '✓' : type === 'error' ? '✖' : 'ℹ'}</span> <div>${message}</div>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 250);
    }, 4000);
  },

  initEventListeners() {
    // Search
    const searchInput = document.getElementById('global-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => this.handleGlobalSearch(e.target.value));
    }

    // Upload Evidence form
    const uploadForm = document.getElementById('form-upload-evidence');
    if (uploadForm) {
      uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(uploadForm);
        this.showToast("Uploading and hashing forensic evidence...", "info");
        try {
          const res = await fetch(`/api/cases/${this.state.currentCaseId}/evidence/upload`, {
            method: 'POST',
            body: formData
          });
          const data = await res.json();
          if (res.ok) {
            this.showToast(`Evidence ${data.evidence_number} imported and hashed!`, "success");
            this.closeModal('upload-evidence-modal');
            uploadForm.reset();
            this.switchCase(this.state.currentCaseId);
          } else {
            this.showToast(data.error || "Upload failed", "error");
          }
        } catch (err) {
          this.showToast("Network error during upload", "error");
        }
      });
    }

    // New Case Form
    const newCaseForm = document.getElementById('form-new-case');
    if (newCaseForm) {
      newCaseForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
          name: document.getElementById('new-case-name').value,
          description: document.getElementById('new-case-desc').value,
          priority: document.getElementById('new-case-priority').value,
          category: document.getElementById('new-case-category').value
        };
        try {
          const res = await fetch('/api/cases', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          const data = await res.json();
          if (res.ok) {
            this.showToast(`Case ${data.case_number} created successfully.`, "success");
            this.closeModal('new-case-modal');
            newCaseForm.reset();
            await this.loadCases();
            await this.switchCase(data.case_id);
          }
        } catch (err) {
          this.showToast("Failed to create case", "error");
        }
      });
    }

    // Edit Case Form
    const editCaseForm = document.getElementById('form-edit-case');
    if (editCaseForm) {
      editCaseForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const caseId = document.getElementById('edit-case-id').value;
        const payload = {
          name: document.getElementById('edit-case-name').value,
          status: document.getElementById('edit-case-status').value,
          priority: document.getElementById('edit-case-priority').value,
          category: document.getElementById('edit-case-category').value,
          investigator: document.getElementById('edit-case-investigator').value,
          description: document.getElementById('edit-case-desc').value
        };

        try {
          const res = await fetch(`/api/cases/${caseId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          if (res.ok) {
            this.showToast("Case information updated successfully.", "success");
            this.closeModal('edit-case-modal');
            await this.loadCases();
            await this.switchCase(caseId);
          } else {
            this.showToast("Failed to update case", "error");
          }
        } catch (err) {
          this.showToast("Network error updating case", "error");
        }
      });
    }

    // New Finding Form
    const newFindingForm = document.getElementById('form-new-finding');
    if (newFindingForm) {
      newFindingForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
          title: document.getElementById('finding-title').value,
          description: document.getElementById('finding-desc').value,
          severity: document.getElementById('finding-severity').value,
          explainable_basis: document.getElementById('finding-basis').value
        };
        try {
          const res = await fetch(`/api/cases/${this.state.currentCaseId}/findings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          const data = await res.json();
          if (res.ok) {
            this.showToast(`Finding ${data.finding_number} recorded!`, "success");
            this.closeModal('new-finding-modal');
            newFindingForm.reset();
            this.renderFindingsView(document.getElementById('view-content'));
          }
        } catch (err) {
          this.showToast("Failed to record finding", "error");
        }
      });
    }
  },

  async handleGlobalSearch(q) {
    const dropdown = document.getElementById('search-results-dropdown');
    if (!dropdown) return;
    if (!q || q.length < 2) {
      dropdown.style.display = 'none';
      return;
    }

    try {
      const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
      const data = await res.json();
      const results = data.results || [];

      if (results.length === 0) {
        dropdown.innerHTML = `<div style="padding: 12px; font-size: 11.5px; color: var(--text-dim);">No matching forensic records found.</div>`;
      } else {
        dropdown.innerHTML = results.map(r => `
          <div style="padding: 8px 12px; border-bottom: 1px solid var(--border-color); cursor: pointer;" onclick="ForensiXApp.selectSearchResult('${r.target}', ${r.case_id})">
            <div style="display: flex; justify-content: space-between;">
              <span style="font-weight: 700; font-size: 12px; color: #f1f5f9;">${r.title}</span>
              <span class="badge badge-normal" style="font-size: 9.5px;">${r.type}</span>
            </div>
            <div style="font-size: 11px; color: var(--text-dim);">${r.subtitle}</div>
          </div>
        `).join('');
      }
      dropdown.style.display = 'block';
    } catch (e) {
      console.error("Search error:", e);
    }
  },

  selectSearchResult(target, caseId) {
    document.getElementById('search-results-dropdown').style.display = 'none';
    if (caseId && caseId !== this.state.currentCaseId) {
      this.switchCase(caseId);
    }
    const [type, id] = target.split('_');
    if (type === 'evidence') {
      this.inspectEvidence(parseInt(id));
    } else if (type === 'case') {
      this.navigate('dashboard');
    } else if (type === 'indicator') {
      this.navigate('indicators');
    } else if (type === 'finding') {
      this.navigate('findings');
    } else if (type === 'timeline') {
      this.navigate('timeline');
    }
  },

  async compareHashesAction() {
    const hashA = document.getElementById('compare-hash-a').value;
    const hashB = document.getElementById('compare-hash-b').value;
    const resBox = document.getElementById('compare-hash-result');

    try {
      const res = await fetch('/api/evidence/compare-hashes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash_a: hashA, hash_b: hashB })
      });
      const data = await res.json();
      resBox.style.display = 'block';
      if (data.is_match) {
        resBox.style.background = 'rgba(5, 213, 84, 0.15)';
        resBox.style.borderColor = 'rgba(5, 213, 84, 0.4)';
        resBox.style.color = '#05d554';
      } else {
        resBox.style.background = 'rgba(255, 51, 75, 0.15)';
        resBox.style.borderColor = 'rgba(255, 51, 75, 0.4)';
        resBox.style.color = '#ff4d63';
      }
      resBox.innerHTML = `<b>${data.result_message}</b> (Identified Algorithm: ${data.algorithm})`;
    } catch (e) {
      alert("Error comparing hashes");
    }
  }
};

window.addEventListener('DOMContentLoaded', () => {
  ForensiXApp.init();
});
