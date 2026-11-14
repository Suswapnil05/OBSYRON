// ═══════════════════════════════════════════════════════════════════════════
// OBSYRON — Autonomous Forensic Investigation & Attack Graph Reconstruction
// HackInnovision 2026 (Track C) — Enterprise SOC Frontend Engine
// ═══════════════════════════════════════════════════════════════════════════

const state = {
  analysisResult: null,
  cy: null,
  timelineMin: null,
  timelineMax: null,
  currentSettings: {
    shuffle: true,
    inject_skew: true,
    drop_telemetry: false,
    drop_rate: 0.15
  },
  currentDataset: 'builtin',
  graphViewMode: 'threat', // 'threat' = clean simple kill chain (default), 'all' = full network
  graphLayoutName: 'breadthfirst',
  searchQuery: '',
  sliderTimeout: null,
  isPlayingTimeline: false,
  timelineInterval: null,
  isSpeaking: false,
  currentEvidenceJson: ''
};

// ── 0. THEME MANAGEMENT ───────────────────────────────────────────────────

function isDarkMode() {
  return document.body.classList.contains('dark-theme');
}

function initTheme() {
  const saved = localStorage.getItem('obsyron_theme');
  // Default is Filigran Dark Midnight mode unless user explicitly selected 'light'
  if (saved === 'light') {
    document.body.classList.remove('dark-theme');
  } else {
    document.body.classList.add('dark-theme');
  }
  updateThemeUI();
}

function setTheme(mode) {
  if (mode === 'light') {
    document.body.classList.remove('dark-theme');
    localStorage.setItem('obsyron_theme', 'light');
  } else {
    document.body.classList.add('dark-theme');
    localStorage.setItem('obsyron_theme', 'dark');
  }
  updateThemeUI();
  if (state.analysisResult) {
    renderGraph(state.analysisResult);
  }
}

function toggleTheme() {
  const isDark = document.body.classList.toggle('dark-theme');
  localStorage.setItem('obsyron_theme', isDark ? 'dark' : 'light');
  updateThemeUI();
  if (state.analysisResult) {
    renderGraph(state.analysisResult);
  }
}

function updateThemeUI() {
  const dark = isDarkMode();

  // Floating bottom button
  const floatIcon = document.getElementById('floating-theme-icon');
  const floatText = document.getElementById('floating-theme-text');
  if (floatIcon) floatIcon.textContent = dark ? '🌙' : '☀️';
  if (floatText) floatText.textContent = dark ? 'Dark Mode' : 'Light Mode';

  // Bottom form segmented control buttons
  const segDark = document.getElementById('seg-dark');
  const segLight = document.getElementById('seg-light');
  if (segDark && segLight) {
    if (dark) {
      segDark.classList.add('active');
      segLight.classList.remove('active');
    } else {
      segLight.classList.add('active');
      segDark.classList.remove('active');
    }
  }

  // Header theme icon & tooltip
  const icon = document.getElementById('theme-icon');
  const themeBtn = document.getElementById('btn-theme');
  if (icon) icon.textContent = dark ? '🌙' : '☀️';
  if (themeBtn) themeBtn.title = dark ? 'Switch to Light Mode' : 'Switch to Dark Mode';

  // Mobile drawer theme icon
  const mobileThemeIcon = document.getElementById('mobile-theme-icon');
  if (mobileThemeIcon) mobileThemeIcon.textContent = dark ? '🌙' : '☀️';
}

// ── 0.1 MOBILE NAVIGATION DRAWER ENGINE ───────────────────────────────────

function toggleMobileMenu() {
  const drawer = document.getElementById('mobile-nav-drawer');
  if (!drawer) return;
  if (drawer.classList.contains('is-open')) {
    closeMobileMenu();
  } else {
    openMobileMenu();
  }
}

function openMobileMenu() {
  const drawer = document.getElementById('mobile-nav-drawer');
  const overlay = document.getElementById('mobile-nav-overlay');
  const btn = document.getElementById('btn-hamburger');
  if (drawer) drawer.classList.add('is-open');
  if (overlay) overlay.classList.add('is-open');
  if (btn) {
    btn.classList.add('is-active');
    btn.setAttribute('aria-expanded', 'true');
  }
  document.body.classList.add('menu-open');
}

function closeMobileMenu() {
  const drawer = document.getElementById('mobile-nav-drawer');
  const overlay = document.getElementById('mobile-nav-overlay');
  const btn = document.getElementById('btn-hamburger');
  if (drawer) drawer.classList.remove('is-open');
  if (overlay) overlay.classList.remove('is-open');
  if (btn) {
    btn.classList.remove('is-active');
    btn.setAttribute('aria-expanded', 'false');
  }
  document.body.classList.remove('menu-open');
}

// Global escape key handler to dismiss overlays
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeMobileMenu();
    if (typeof closeAuthModal === 'function') closeAuthModal();
    if (typeof closeDrawer === 'function') closeDrawer();
  }
});

// ── 1. API INTEGRATION & AUTOMATIC FAILOVER ────────────────────────────────

async function apiFetch(url, options = {}) {
  try {
    const res = await fetch(url, options);
    if (res.status === 404 && url.startsWith('/api/')) {
      const fallbackUrl = url.replace('/api/', '/');
      const res2 = await fetch(fallbackUrl, options);
      return res2;
    }
    return res;
  } catch (err) {
    if (url.startsWith('/api/')) {
      return await fetch(url.replace('/api/', '/'), options);
    }
    throw err;
  }
}

async function runAnalysis(settings) {
  showLoading(true);
  try {
    const res = await apiFetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings || state.currentSettings),
    });
    if (!res.ok) {
      throw new Error(`Server returned ${res.status}: ${await res.text()}`);
    }
    const data = await res.json();
    state.analysisResult = data;
    renderAll(data);
  } catch (err) {
    console.error('Analysis execution failed:', err);
    alert('Analysis failed: ' + err.message);
  } finally {
    showLoading(false);
  }
}

async function fetchSnapshot(timestamp) {
  if (!state.analysisResult) return;
  showLoading(true);
  try {
    const res = await apiFetch(`/api/graph/snapshot?timestamp=${encodeURIComponent(timestamp)}`);
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    renderGraph(data);
    renderKPIs(data);
  } catch (err) {
    console.error('Snapshot fetch error:', err);
  } finally {
    showLoading(false);
  }
}

async function fetchEvidence(logId) {
  if (!logId) return;
  try {
    const res = await apiFetch(`/api/evidence/${encodeURIComponent(logId)}`);
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    renderEvidenceDNA(data);
    openDrawer();
  } catch (err) {
    console.error('Evidence lookup error for ' + logId + ':', err);
  }
}

async function handleFileUpload(file) {
  if (!file) return;
  const form = new FormData();
  form.append('file', file);
  showLoading(true);
  try {
    const res = await apiFetch('/api/upload', {
      method: 'POST',
      body: form
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    state.analysisResult = data;
    state.currentDataset = 'upload';
    document.getElementById('btn-builtin').classList.remove('active');
    renderAll(data);
  } catch (err) {
    alert('Log file upload failed: ' + err.message);
  } finally {
    showLoading(false);
  }
}

function downloadBlob(blob, filename) {
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.style.display = 'none';
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  a.remove();
}

async function exportInvestigation(format = 'json') {
  try {
    showLoading(true);
    const res = await apiFetch('/api/reports/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format: format, investigation_id: 'OBS-INV-20261114-001' })
    });
    if (!res.ok) throw new Error(`Export failed with HTTP ${res.status}`);

    const extMap = { 'json': 'json', 'csv': 'csv', 'markdown': 'md', 'md': 'md' };
    const ext = extMap[format.toLowerCase()] || 'json';
    const blob = await res.blob();
    downloadBlob(blob, `obsyron-investigation-report-OBS-INV-20261114-001.${ext}`);
  } catch (err) {
    console.error('Report export failed:', err);
    alert('Export error: ' + err.message);
  } finally {
    showLoading(false);
  }
}

// ── 2. UNIFIED RENDER DISPATCHER ───────────────────────────────────────────

function renderAll(data) {
  try { renderKPIs(data); } catch (e) { console.error('Error in renderKPIs:', e); }
  try { renderGraph(data); } catch (e) { console.error('Error in renderGraph:', e); }
  try { renderXAI(data); } catch (e) { console.error('Error in renderXAI:', e); }
  try { renderPlaybook(data); } catch (e) { console.error('Error in renderPlaybook:', e); }
  try { renderMatrix(data); } catch (e) { console.error('Error in renderMatrix:', e); }
  try { initTimelineSlider(data); } catch (e) { console.error('Error in initTimelineSlider:', e); }
  try { renderQuickActions(data); } catch (e) { console.error('Error in renderQuickActions:', e); }
}

// ── 3. TOP KPI STRIP ───────────────────────────────────────────────────────

function renderKPIs(data) {
  document.getElementById('kpi-snr').textContent =
    `${data.raw_log_count} → ${data.malicious_signal_count}`;
  document.getElementById('kpi-snr-sub').textContent = 'Raw Enterprise Logs → Malicious Signals';

  const ia = data.initial_access || {};
  document.getElementById('kpi-pz').textContent = ia.entity || '—';
  document.getElementById('kpi-pz-sub').textContent = ia.timestamp
    ? `${ia.mitre_tactic} @ ${formatTimeOnly(ia.timestamp)}`
    : (ia.mitre_tactic || 'Patient Zero Identity');

  const br = data.blast_radius || {};
  document.getElementById('kpi-br').textContent = `${br.count || 0} Assets`;
  document.getElementById('kpi-br-sub').textContent = `${br.affected_nodes ? br.affected_nodes.length : 0} Downstream Targets Exposed`;

  const conf = data.overall_confidence || 0;
  const confEl = document.getElementById('kpi-conf');
  const chipEl = document.getElementById('kpi-conf-chip');
  const confSub = document.getElementById('kpi-conf-sub');
  const confPct = (conf * 100).toFixed(1);

  confEl.textContent = `${confPct}%`;
  if (conf < 0.75) {
    confEl.style.color = 'var(--color-warning)';
    chipEl.className = 'kpi-chip chip-amber';
    chipEl.textContent = 'INFERRED GAP BRIDGE';
    confSub.textContent = 'Telemetry gap bridged with penalized confidence';
  } else {
    confEl.style.color = 'var(--color-info-light)';
    chipEl.className = 'kpi-chip chip-cyan';
    chipEl.textContent = 'CORROBORATED';
    confSub.textContent = 'Multi-signal forensic log corroboration';
  }
}

// ── 4. CYTOSCAPE ATTACK GRAPH (SIMPLIFIED & USER RESPONSIVE) ───────────────

function entityBadge(type) {
  const map = {
    USER: '👤 [USER]',
    DEVICE: '💻 [DEVICE]',
    SERVICE: '⚙️ [SERVICE]',
    AUTH_ENDPOINT: '🌐 [EXT_IP]'
  };
  return map[type] || '⬡ [NODE]';
}

function formatNodeLabel(n) {
  const id = n.id;
  if (id === '185.220.101.47') return '🌐 185.220.101.47\n[EXT] TOR Ingress / C2';
  if (id === 'emp_rohan') return '👤 emp_rohan\n[USER] Compromised Identity';
  if (id === 'wkst-04-dev') return '💻 wkst-04-dev\n[PIVOT] Dev Workstation';
  if (id === 'svc_ci_deploy') return '🔑 svc_ci_deploy\n[SERVICE] Abused Token';
  if (id === 'db-prod-01') return '🗄️ db-prod-01\n[TARGET] Production DB';
  if (id === 'dc-01') return '🏛️ dc-01\n[INFRA] Active Directory';

  const iconMap = { USER: '👤', DEVICE: '💻', SERVICE: '⚙️', AUTH_ENDPOINT: '🌐' };
  const icon = iconMap[n.entity_type] || '⬡';
  return `${icon} ${n.label || id}\n[${n.entity_type || 'ASSET'}]`;
}

function formatEdgeLabel(e) {
  const confVal = Math.round((e.confidence || 0.75) * 100);
  if (e.is_inferred) {
    return `③ [INFERRED] Priv Esc\n${confVal}% [T1558] ⚠️`;
  }

  const isThreat = Boolean(e.is_malicious) ||
    (e.log_ids || []).some(id => String(id).startsWith('LOG-APT') || String(id).startsWith('UPLOAD-MAL'));

  if (isThreat) {
    const src = e.source;
    const tgt = e.target;
    if (src === '185.220.101.47' && tgt === 'emp_rohan') {
      return `① Ingress Auth\n${confVal}% [T1078]`;
    }
    if (src === 'emp_rohan' && tgt === 'wkst-04-dev') {
      return `② AD Discovery\n${confVal}% [T1087]`;
    }
    if (src === 'wkst-04-dev' && tgt === 'svc_ci_deploy') {
      return `③ Priv Escalation\n${confVal}% [T1558]`;
    }
    if (src === 'svc_ci_deploy' && tgt === 'db-prod-01') {
      return `④ Lateral Move\n${confVal}% [T1021]`;
    }
    if (src === 'db-prod-01' && tgt === '185.220.101.47') {
      return `⑤ Exfiltration\n${confVal}% [T1048]`;
    }
    if (src === '185.220.101.47' && tgt === 'db-prod-01') {
      return `⑥ C2 Callback\n${confVal}% [T1048]`;
    }
  }

  return `${e.action || 'TRAFFIC'}\n${confVal}%`;
}

function entityFillColor(type, isMalicious) {
  const dark = isDarkMode();
  if (dark) {
    if (isMalicious) {
      const mal = {
        USER: '#081E38',
        DEVICE: '#1E1838',
        SERVICE: '#2D1B06',
        AUTH_ENDPOINT: '#2E0C14'
      };
      return mal[type] || '#1E1838';
    }
    return '#0D1224';
  } else {
    if (isMalicious) {
      const mal = {
        USER: '#E0F2FE',
        DEVICE: '#F3E8FF',
        SERVICE: '#FEF3C7',
        AUTH_ENDPOINT: '#FEE2E2'
      };
      return mal[type] || '#FEE2E2';
    }
    return '#F8FAFC';
  }
}

function entityStrokeColor(type) {
  const dark = isDarkMode();
  if (dark) {
    const map = {
      USER: '#38BDF8',
      DEVICE: '#818CF8',
      SERVICE: '#F59E0B',
      AUTH_ENDPOINT: '#EF4444'
    };
    return map[type] || '#818CF8';
  } else {
    const map = {
      USER: '#0284C7',
      DEVICE: '#6366F1',
      SERVICE: '#D97706',
      AUTH_ENDPOINT: '#DC2626'
    };
    return map[type] || '#64748B';
  }
}

function renderGraph(data) {
  const container = document.getElementById('cy');
  if (!container) return;
  const dark = isDarkMode();

  const nodeTextColor = dark ? '#FFFFFF' : '#0F172A';
  const edgeLineColor = dark ? '#334155' : '#94A3B8';
  const edgeCriticalColor = dark ? '#EF4444' : '#DC2626';
  const edgeInferredColor = dark ? '#F59E0B' : '#D97706';
  const edgeTextBg = dark ? '#00020C' : '#FFFFFF';
  const edgeTextColor = dark ? '#E2E8F0' : '#0F172A';
  const selectBorderColor = dark ? '#6FD7FF' : '#0284C7';
  const ancestorColor = dark ? '#38BDF8' : '#0284C7';
  const descendantColor = dark ? '#EF4444' : '#DC2626';

  // 1. Identify Threat-Relevant Edges (Clean & Focused Kill Chain)
  const allEdges = data.edges || [];
  let threatEdges = allEdges.filter(e => {
    return Boolean(e.is_malicious) ||
      Boolean(e.is_inferred) ||
      (e.log_ids || []).some(id => String(id).startsWith('LOG-APT') || String(id).startsWith('UPLOAD-MAL'));
  });

  // Fallback if custom uploaded dataset has no pre-flagged APT IDs
  if (threatEdges.length === 0) {
    threatEdges = allEdges.filter(e => e.severity === 'CRITICAL');
  }
  if (threatEdges.length === 0) {
    threatEdges = allEdges.slice(0, 8);
  }

  // 2. Identify Threat-Relevant Nodes
  const threatNodeIds = new Set();
  threatEdges.forEach(e => {
    threatNodeIds.add(e.source);
    threatNodeIds.add(e.target);
  });
  if (data.initial_access && data.initial_access.entity) {
    threatNodeIds.add(data.initial_access.entity);
  }
  (data.nodes || []).forEach(n => {
    if (n.is_malicious) threatNodeIds.add(n.id);
  });

  // 3. Filter Nodes based on state.graphViewMode ('threat' vs 'all')
  const nodesToRender = (state.graphViewMode === 'threat' && threatNodeIds.size > 0)
    ? (data.nodes || []).filter(n => threatNodeIds.has(n.id))
    : (data.nodes || []);

  const nodeSet = new Set(nodesToRender.map(n => n.id));

  // 4. Filter Edges
  let edgesToRender = [];
  if (state.graphViewMode === 'threat') {
    edgesToRender = threatEdges.filter(e => nodeSet.has(e.source) && nodeSet.has(e.target));
  } else {
    edgesToRender = allEdges.filter(e => nodeSet.has(e.source) && nodeSet.has(e.target));
  }

  const elements = [];

  // Add Nodes
  nodesToRender.forEach(n => {
    const isThreatNode = threatNodeIds.has(n.id) || n.is_malicious;
    elements.push({
      group: 'nodes',
      data: {
        id: n.id,
        label: formatNodeLabel(n),
        entity_type: n.entity_type,
        is_malicious: isThreatNode,
        centrality: n.centrality,
        log_ids: n.log_ids || [],
        mitre_tags: n.mitre_tags || [],
        color: isThreatNode ? (n.id === '185.220.101.47' ? '#EF4444' : entityStrokeColor(n.entity_type)) : (dark ? '#475569' : '#94A3B8'),
        bg: entityFillColor(n.entity_type, isThreatNode),
      }
    });
  });

  // Add Edges
  edgesToRender.forEach((e, i) => {
    const isThreatEdge = Boolean(e.is_inferred) || Boolean(e.is_malicious) ||
      (e.log_ids || []).some(id => String(id).startsWith('LOG-APT') || String(id).startsWith('UPLOAD-MAL'));
    elements.push({
      group: 'edges',
      data: {
        id: e.id || `edge-${i}`,
        source: e.source,
        target: e.target,
        label: formatEdgeLabel(e),
        is_inferred: Boolean(e.is_inferred),
        confidence: e.confidence,
        mitre_tag: e.mitre_tag,
        log_ids: e.log_ids || [],
        severity: e.severity,
        raw_payload: e.raw_payload,
        normalized_timestamp: e.normalized_timestamp,
        is_threat: isThreatEdge
      }
    });
  });

  if (state.cy) {
    state.cy.destroy();
    state.cy = null;
  }

  container.innerHTML = '';

  if (elements.filter(e => e.group === 'nodes').length === 0) {
    container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--text-tertiary);font-size:12px;font-family:var(--font-mono)">No attack graph nodes found</div>';
    return;
  }

  // Layout configuration
  const rootId = (data.initial_access && data.initial_access.entity) || '185.220.101.47';
  const hasRoot = elements.some(e => e.group === 'nodes' && e.data.id === rootId);
  const rootSelector = hasRoot ? `[id = "${rootId}"]` : undefined;

  let layoutOpts = {
    name: 'breadthfirst',
    directed: true,
    roots: rootSelector,
    padding: 45,
    spacingFactor: 1.5,
    avoidOverlap: true,
    maximal: true,
    animate: false
  };

  if (state.graphLayoutName === 'concentric') {
    layoutOpts = {
      name: 'concentric',
      concentric: function(node) {
        return (node.data('centrality') || 0) * 100 + (node.data('is_malicious') ? 50 : 0);
      },
      levelWidth: function() { return 25; },
      padding: 35,
      animate: false
    };
  } else if (state.graphLayoutName === 'cose') {
    layoutOpts = {
      name: 'cose',
      animate: false,
      padding: 35,
      componentSpacing: 60,
      nodeRepulsion: 6000,
      idealEdgeLength: 100
    };
  } else if (state.graphLayoutName === 'circle') {
    layoutOpts = {
      name: 'circle',
      padding: 35,
      animate: false
    };
  }

  const cyStyle = [
    {
      selector: 'node',
      style: {
        'background-color': 'data(bg)',
        'border-color': 'data(color)',
        'border-width': 2.0,
        'label': 'data(label)',
        'text-valign': 'center',
        'text-halign': 'center',
        'color': nodeTextColor,
        'font-size': 9.5,
        'font-weight': 600,
        'font-family': 'JetBrains Mono, monospace',
        'text-wrap': 'wrap',
        'width': 130,
        'height': 52,
        'shape': 'roundrectangle',
        'text-max-width': 122,
        'transition-property': 'background-color, border-color, opacity, border-width',
        'transition-duration': '0.2s',
        'cursor': 'pointer'
      }
    },
    {
      selector: 'node[entity_type = "USER"]',
      style: { shape: 'roundrectangle', width: 125, height: 50 }
    },
    {
      selector: 'node[entity_type = "SERVICE"]',
      style: { shape: 'roundrectangle', width: 130, height: 50 }
    },
    {
      selector: 'node[entity_type = "AUTH_ENDPOINT"]',
      style: { shape: 'hexagon', width: 135, height: 54 }
    },
    {
      selector: 'node[?is_malicious]',
      style: {
        'border-width': 2.6,
      }
    },
    {
      selector: 'node[id = "185.220.101.47"]',
      style: {
        'border-color': '#EF4444',
        'border-width': 3.0,
      }
    },
    {
      selector: 'node[id = "wkst-04-dev"]',
      style: {
        'border-color': '#38BDF8',
        'border-width': 2.8,
      }
    },
    {
      selector: 'edge',
      style: {
        'width': 2.2,
        'line-color': edgeLineColor,
        'target-arrow-color': edgeLineColor,
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': 8.5,
        'font-weight': 600,
        'font-family': 'JetBrains Mono, monospace',
        'color': edgeTextColor,
        'text-background-color': edgeTextBg,
        'text-background-opacity': 0.95,
        'text-background-padding': 3,
        'text-wrap': 'wrap',
        'text-max-width': 105,
        'edge-text-rotation': 'autorotate',
        'arrow-scale': 1.15,
        'cursor': 'pointer'
      }
    },
    {
      selector: 'edge[?is_threat]',
      style: {
        'line-color': edgeCriticalColor,
        'target-arrow-color': edgeCriticalColor,
        'width': 2.6,
        'color': dark ? '#FCA5A5' : '#991B1B',
      }
    },
    {
      selector: 'edge[?is_inferred]',
      style: {
        'line-color': edgeInferredColor,
        'target-arrow-color': edgeInferredColor,
        'line-style': 'dashed',
        'line-dash-pattern': [6, 4],
        'width': 2.4,
        'color': dark ? '#FCD34D' : '#92400E',
      }
    },
    {
      selector: 'node:selected',
      style: {
        'border-width': 3.6,
        'border-color': selectBorderColor
      }
    },
    { selector: '.dimmed', style: { 'opacity': 0.12 } },
    { selector: '.highlighted', style: { 'opacity': 1, 'z-index': 999 } },
    { selector: '.ancestor-highlight', style: { 'border-color': ancestorColor, 'border-width': 3.2, 'opacity': 1 } },
    { selector: '.descendant-highlight', style: { 'border-color': descendantColor, 'border-width': 3.2, 'opacity': 1 } },
  ];

  let cyInstance = null;
  try {
    cyInstance = cytoscape({
      container,
      elements,
      layout: layoutOpts,
      style: cyStyle,
      wheelSensitivity: 0.1,    // Smooth, gentle mousewheel zoom (prevents flying/spinning)
      minZoom: 0.35,
      maxZoom: 2.2,
      boxSelectionEnabled: false
    });
  } catch (cyErr) {
    console.warn('Primary Cytoscape layout failed, falling back:', cyErr);
    try {
      cyInstance = cytoscape({
        container,
        elements,
        layout: { name: 'breadthfirst', directed: true, padding: 35, animate: false },
        style: cyStyle,
        wheelSensitivity: 0.1,
        minZoom: 0.35,
        maxZoom: 2.2
      });
    } catch (fallbackErr) {
      console.warn('Breadthfirst fallback failed, using grid layout:', fallbackErr);
      cyInstance = cytoscape({
        container,
        elements,
        layout: { name: 'grid', padding: 35 },
        style: cyStyle,
        wheelSensitivity: 0.1
      });
    }
  }

  if (!cyInstance) return;
  state.cy = cyInstance;

  // Node Click -> Evidence DNA + Blast Radius Highlight (Stable viewport, no camera jerk)
  state.cy.on('tap', 'node', function(evt) {
    const node = evt.target;
    const logIds = node.data('log_ids') || [];
    const chosenId = logIds.find(id => id.startsWith('LOG-APT') || id.startsWith('UPLOAD')) || logIds[0];
    if (chosenId) fetchEvidence(chosenId);
    highlightBlastRadius(node);
  });

  // Edge Click -> Evidence DNA (Stable viewport)
  state.cy.on('tap', 'edge', function(evt) {
    const edge = evt.target;
    const logIds = edge.data('log_ids') || [];
    const firstId = logIds[0];
    if (firstId) fetchEvidence(firstId);

    state.cy.elements().addClass('dimmed').removeClass('highlighted ancestor-highlight descendant-highlight');
    edge.removeClass('dimmed').addClass('highlighted');
    edge.source().removeClass('dimmed').addClass('highlighted ancestor-highlight');
    edge.target().removeClass('dimmed').addClass('highlighted descendant-highlight');
  });

  // Hover Tooltip
  state.cy.on('mouseover', 'node', function(evt) {
    const node = evt.target;
    const pos = evt.renderedPosition;
    const bbox = container.getBoundingClientRect();
    showTooltip(
      node.data('label').replace('\n', ' — '),
      `Entity Class: ${node.data('entity_type')} | ${node.data('is_malicious') ? 'COMPROMISED' : 'Benign Asset'}`,
      `Betweenness Centrality: ${(node.data('centrality') * 100).toFixed(1)}% (Internal Pivot Metric)`,
      `Correlated Audit Logs: ${(node.data('log_ids') || []).length} events`,
      bbox.left + pos.x, bbox.top + pos.y
    );
  });

  state.cy.on('mouseout', 'node', hideTooltip);

  // Background Tap -> Reset Dimming & Close Drawer
  state.cy.on('tap', function(evt) {
    if (evt.target === state.cy) {
      resetGraphFocus();
      closeDrawer();
    }
  });

  setTimeout(() => {
    if (state.cy) {
      state.cy.resize();
      state.cy.fit(null, 35);
    }
  }, 100);
}

window.addEventListener('resize', () => {
  if (state.cy) {
    state.cy.resize();
  }
});

function highlightBlastRadius(node) {
  if (!state.cy) return;
  const cy = state.cy;
  cy.elements().addClass('dimmed');
  node.removeClass('dimmed').addClass('highlighted');

  // Upstream root cause path in Sky Blue
  node.predecessors().removeClass('dimmed').addClass('highlighted ancestor-highlight');

  // Downstream blast radius path in Crimson
  node.successors().removeClass('dimmed').addClass('highlighted descendant-highlight');

  node.connectedEdges().removeClass('dimmed').addClass('highlighted');
}

// ── USER-RESPONSIVE INTERACTIVE GRAPH CONTROLS ─────────────────────────────

function setGraphViewMode(mode) {
  state.graphViewMode = mode;
  const btnThreat = document.getElementById('btn-view-threat');
  const btnAll = document.getElementById('btn-view-all');
  if (btnThreat) btnThreat.classList.toggle('active', mode === 'threat');
  if (btnAll) btnAll.classList.toggle('active', mode === 'all');
  if (state.analysisResult) {
    renderGraph(state.analysisResult);
  }
}

function changeGraphLayout(name) {
  state.graphLayoutName = name;
  if (!state.cy) return;
  const cy = state.cy;
  let opts = { name: name, animate: true, animationDuration: 400 };

  if (name === 'breadthfirst') {
    const rootId = (state.analysisResult && state.analysisResult.initial_access && state.analysisResult.initial_access.entity) || '185.220.101.47';
    const rootNodes = cy.nodes(`[id = "${rootId}"]`);
    opts = {
      name: 'breadthfirst',
      directed: true,
      roots: rootNodes.length > 0 ? rootNodes : undefined,
      padding: 40,
      spacingFactor: 1.35,
      avoidOverlap: true,
      maximal: true,
      animate: true,
      animationDuration: 400
    };
  } else if (name === 'concentric') {
    opts = {
      name: 'concentric',
      concentric: function(node) {
        return (node.data('centrality') || 0) * 100 + (node.data('is_malicious') ? 50 : 0);
      },
      levelWidth: function() { return 25; },
      padding: 40,
      animate: true,
      animationDuration: 400
    };
  } else if (name === 'cose') {
    opts = {
      name: 'cose',
      animate: true,
      animationDuration: 500,
      padding: 40,
      componentSpacing: 60,
      nodeRepulsion: 6000,
      idealEdgeLength: 100
    };
  } else if (name === 'circle') {
    opts = {
      name: 'circle',
      padding: 40,
      animate: true,
      animationDuration: 400
    };
  }

  try {
    const layout = cy.layout(opts);
    layout.run();
  } catch (err) {
    console.warn('Layout execution failed, falling back:', err);
    try {
      cy.layout({ name: 'breadthfirst', directed: true, padding: 35 }).run();
    } catch (e) {
      console.error('All layouts failed:', e);
    }
  }
}

function onGraphSearch(query) {
  if (!state.cy) return;
  const cy = state.cy;
  const q = (query || '').trim().toLowerCase();
  if (!q) {
    resetGraphFocus();
    return;
  }

  const matchedNodes = cy.nodes().filter(n => {
    const label = (n.data('label') || '').toLowerCase();
    const id = n.data('id').toLowerCase();
    const type = (n.data('entity_type') || '').toLowerCase();
    return id.includes(q) || label.includes(q) || type.includes(q);
  });

  if (matchedNodes.length > 0) {
    cy.elements().addClass('dimmed').removeClass('highlighted ancestor-highlight descendant-highlight');
    matchedNodes.removeClass('dimmed').addClass('highlighted descendant-highlight');
    matchedNodes.connectedEdges().removeClass('dimmed').addClass('highlighted');
    cy.animate({
      center: { eles: matchedNodes[0] },
      zoom: 1.3
    }, { duration: 300 });
  }
}

function clearGraphSearch() {
  const input = document.getElementById('graph-search');
  if (input) input.value = '';
  resetGraphFocus();
}

function resetGraphFocus() {
  if (!state.cy) return;
  state.cy.elements().removeClass('dimmed highlighted ancestor-highlight descendant-highlight');
  state.cy.animate({
    fit: { padding: 40 }
  }, { duration: 350 });
}

function focusAttackStep(stepNum) {
  if (!state.cy) return;
  const stepMap = {
    1: { mitre: 'T1078', action: 'AUTH_ANOMALY', src: '185.220.101.47', tgt: 'emp_rohan' },
    2: { mitre: 'T1087', action: 'RECON_ENUM', src: 'emp_rohan', tgt: 'wkst-04-dev' },
    3: { mitre: 'T1558', action: 'PRIV_ESC', src: 'wkst-04-dev', tgt: 'svc_ci_deploy' },
    4: { mitre: 'T1021', action: 'LATERAL_MOVE', src: 'svc_ci_deploy', tgt: 'db-prod-01' },
    5: { mitre: 'T1048', action: 'DATA_EXFIL', src: 'db-prod-01', tgt: '185.220.101.47' },
    6: { mitre: 'T1048', action: 'C2_BEACON', src: 'db-prod-01', tgt: '185.220.101.47' },
  };

  const targetInfo = stepMap[stepNum];
  if (!targetInfo) return;

  const cy = state.cy;
  let matchEdge = cy.edges().filter(e => {
    const d = e.data();
    return (d.mitre_tag === targetInfo.mitre) || (d.action === targetInfo.action) ||
      (d.source === targetInfo.src && d.target === targetInfo.tgt);
  });

  if (matchEdge.length === 0 && stepNum === 3) {
    matchEdge = cy.edges().filter(e => e.data('is_inferred'));
  }

  if (matchEdge.length > 0) {
    cy.elements().addClass('dimmed').removeClass('highlighted ancestor-highlight descendant-highlight');
    const edge = matchEdge[0];
    edge.removeClass('dimmed').addClass('highlighted');
    edge.source().removeClass('dimmed').addClass('highlighted ancestor-highlight');
    edge.target().removeClass('dimmed').addClass('highlighted descendant-highlight');

    cy.animate({
      center: { eles: edge }
    }, { duration: 300, easing: 'ease-in-out-cubic' });

    const logIds = edge.data('log_ids') || [];
    if (logIds[0]) fetchEvidence(logIds[0]);
  }
}

// Canvas Toolbar Helpers
function zoomIn() { if (state.cy) state.cy.zoom(state.cy.zoom() * 1.25); }
function zoomOut() { if (state.cy) state.cy.zoom(state.cy.zoom() * 0.8); }
function fitGraph() { if (state.cy) state.cy.fit(null, 35); }
function reLayoutGraph() {
  if (!state.cy) return;
  changeGraphLayout(state.graphLayoutName || 'breadthfirst');
}

// ── 5. TIME-TRAVEL INVESTIGATION & SCRUBBER PLAYER ─────────────────────────

function initTimelineSlider(data) {
  state.timelineMin = data.timeline_min;
  state.timelineMax = data.timeline_max;
  if (!state.timelineMin || !state.timelineMax) return;

  const slider = document.getElementById('timeline-slider');
  slider.min = 0;
  slider.max = 100;
  slider.value = 100;
  document.getElementById('timeline-display').textContent = formatTimestamp(state.timelineMax);
}

function onSliderInput(val) {
  if (!state.timelineMin || !state.timelineMax) return;
  const minMs = new Date(state.timelineMin).getTime();
  const maxMs = new Date(state.timelineMax).getTime();
  const pct = parseInt(val, 10) / 100;
  const targetMs = minMs + (maxMs - minMs) * pct;
  const targetTs = new Date(targetMs).toISOString();

  document.getElementById('timeline-display').textContent = formatTimestamp(targetTs);

  clearTimeout(state.sliderTimeout);
  state.sliderTimeout = setTimeout(() => {
    fetchSnapshot(targetTs);
  }, 300);
}

function toggleTimelinePlay() {
  const btn = document.getElementById('btn-play-pause');
  if (state.isPlayingTimeline) {
    clearInterval(state.timelineInterval);
    state.isPlayingTimeline = false;
    btn.textContent = '▶';
  } else {
    state.isPlayingTimeline = true;
    btn.textContent = '⏸';
    const slider = document.getElementById('timeline-slider');
    if (parseInt(slider.value) >= 100) slider.value = 0;

    state.timelineInterval = setInterval(() => {
      let val = parseInt(slider.value, 10) + 10;
      if (val > 100) {
        val = 100;
        clearInterval(state.timelineInterval);
        state.isPlayingTimeline = false;
        btn.textContent = '▶';
      }
      slider.value = val;
      onSliderInput(val);
    }, 1200);
  }
}

function resetTimeline() {
  if (state.isPlayingTimeline) toggleTimelinePlay();
  const slider = document.getElementById('timeline-slider');
  slider.value = 0;
  onSliderInput(0);
}

function formatTimestamp(ts) {
  if (!ts) return '';
  try {
    return new Date(ts).toLocaleString('en-IN', {
      month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false, timeZoneName: 'short'
    });
  } catch {
    return ts;
  }
}

function formatTimeOnly(ts) {
  if (!ts) return '';
  try {
    return new Date(ts).toLocaleTimeString('en-IN', {
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    });
  } catch {
    return ts;
  }
}

// ── 6. ROOT CAUSE EXPLAINABLE AI REPORT ─────────────────────────────────────

function renderXAI(data) {
  const container = document.getElementById('xai-content');
  const steps = data.xai_report || [];
  if (!steps.length) {
    container.innerHTML = '<div style="color:var(--text-tertiary);font-size:11px;padding:20px;text-align:center;font-family:var(--font-mono)">No Explainable AI data available</div>';
    return;
  }

  container.innerHTML = steps.map(step => {
    const confPct = Math.round(step.confidence * 100);
    const confColor = step.is_inferred ? 'var(--color-warning)' : (confPct >= 90 ? 'var(--color-critical)' : 'var(--color-info-light)');
    const citations = (step.log_citations || []).map(lid =>
      `<span class="citation-badge ${lid === 'INFERRED' ? 'inferred' : ''}" onclick="fetchEvidence('${lid}')" title="Inspect raw forensic log">[LOG: ${lid}]</span>`
    ).join('');

    return `
      <div class="xai-step-card ${step.is_inferred ? 'inferred-step' : ''}" onclick="focusAttackStep(${step.step})" style="cursor:pointer" title="Click to isolate Stage ${step.step} on the attack graph">
        <div class="xai-card-top">
          <span class="step-pill">STAGE ${step.step}</span>
          <span class="step-heading">${step.title}</span>
          <span class="mitre-tag">${step.mitre}</span>
          ${step.is_inferred ? '<span class="inferred-tag">INFERRED BRIDGE</span>' : ''}
          <span style="margin-left:auto;font-size:9px;color:var(--accent-cyan);font-family:var(--font-mono);font-weight:600">🎯 Locate</span>
        </div>
        <div style="font-size:9.5px;color:var(--text-tertiary);margin-bottom:6px;font-family:var(--font-mono)">${step.mitre_name || ''}</div>
        <p class="xai-desc">${step.narrative}</p>
        <div class="citations-row">
          <span style="font-size:9px;color:var(--text-tertiary);font-family:var(--font-mono);margin-right:4px">Citations:</span>
          ${citations}
        </div>
        <div class="conf-wrap">
          <div class="conf-track">
            <div class="conf-fill" style="width:${confPct}%;background:${confColor}"></div>
          </div>
          <span class="conf-text" style="color:${confColor}">${confPct}% Certainty</span>
        </div>
      </div>
    `;
  }).join('');
}

// ── 7. CONTAINMENT PLAYBOOK & QUICK ACTIONS ─────────────────────────────────

function renderPlaybook(data) {
  const br = data.blast_radius || {};
  const list = br.containment_checklist || [];
  const container = document.getElementById('playbook-content');

  const affectedHtml = (br.affected_nodes || []).map(n =>
    `<span style="display:inline-block;background:var(--color-critical-bg);border:1px solid var(--color-critical-border);color:var(--color-critical);padding:2px 7px;border-radius:3px;font-size:9.5px;font-family:var(--font-mono);font-weight:600;margin:2px">${n}</span>`
  ).join('');

  container.innerHTML = `
    <div class="playbook-progress">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">
        <span style="font-size:9.5px;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;color:var(--text-tertiary);font-family:var(--font-sans)">Containment Readiness</span>
        <span id="containment-percent" style="font-size:11px;font-family:var(--font-mono);font-weight:700;color:var(--color-success)">0% COMPLETE</span>
      </div>
      <div class="conf-track" style="height:5px">
        <div id="containment-progress-bar" style="width:0%;height:100%;background:var(--color-success);border-radius:2px;transition:width 0.25s"></div>
      </div>
    </div>

    <div style="margin-bottom:12px">
      <div class="rail-title">Downstream Reachable Assets (${br.count || 0})</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:6px">${affectedHtml || '<span style="color:var(--text-tertiary);font-size:10px">None detected</span>'}</div>
    </div>

    <div class="rail-title" style="margin-bottom:7px">Prioritized Response Protocol</div>
    ${list.map((item, i) => `
      <div class="containment-item" id="ci-${i}">
        <input type="checkbox" class="check-box" onchange="onPlaybookCheckChange(this)">
        <span>${item}</span>
      </div>
    `).join('')}
  `;
}

function onPlaybookCheckChange(checkbox) {
  checkbox.closest('.containment-item').classList.toggle('containment-done', checkbox.checked);
  const all = document.querySelectorAll('.check-box');
  const checked = document.querySelectorAll('.check-box:checked');
  const pct = all.length > 0 ? Math.round((checked.length / all.length) * 100) : 0;

  const bar = document.getElementById('containment-progress-bar');
  const txt = document.getElementById('containment-percent');
  if (bar) bar.style.width = `${pct}%`;
  if (txt) txt.textContent = `${pct}% COMPLETE`;
}

function renderQuickActions(data) {
  const ia = data.initial_access || {};
  const el = document.getElementById('quick-actions');
  el.innerHTML = `
    <button class="rail-btn" style="border-color:var(--color-critical-border);color:var(--color-critical);background:var(--color-critical-bg)" onclick="alert('Dispatched: Account session revocation sent to Active Directory for ' + '${ia.patient_zero_account || 'Patient Zero'}')">
      <span style="font-family:var(--font-mono);font-weight:700;font-size:9.5px">[LOCK]</span> Lock ${ia.patient_zero_account || 'emp_rohan'}
    </button>
    <button class="rail-btn" style="border-color:var(--color-critical-border);color:var(--color-critical);background:var(--color-critical-bg)" onclick="alert('Dispatched: Egress firewall null-route rule pushed for IP 185.220.101.47')">
      <span style="font-family:var(--font-mono);font-weight:700;font-size:9.5px">[BLOCK]</span> Block 185.220.101.47
    </button>
    <button class="rail-btn" style="border-color:var(--color-warning-border);color:var(--color-warning);background:var(--color-warning-bg)" onclick="alert('Dispatched: Service credential rotation triggered for svc_ci_deploy')">
      <span style="font-family:var(--font-mono);font-weight:700;font-size:9.5px">[ROTATE]</span> Rotate svc_ci_deploy
    </button>
    <button class="rail-btn" style="border-color:var(--color-warning-border);color:var(--color-warning);background:var(--color-warning-bg)" onclick="alert('Dispatched: VLAN network quarantine triggered for host db-prod-01')">
      <span style="font-family:var(--font-mono);font-weight:700;font-size:9.5px">[ISOLATE]</span> Quarantine db-prod-01
    </button>
  `;
}

// ── 8. FORENSICS MATRIX & PIVOT ANALYTICS ───────────────────────────────────

function renderMatrix(data) {
  const container = document.getElementById('matrix-content');
  const nodes = data.nodes || [];
  const edges = data.edges || [];
  const malNodes = nodes.filter(n => n.is_malicious).length;
  const inferredEdges = edges.filter(e => e.is_inferred).length;
  const mitreSet = new Set(edges.filter(e => e.mitre_tag).map(e => e.mitre_tag));

  container.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:12px">
      ${[
        ['Total Entities', nodes.length, 'var(--color-info-light)'],
        ['Graph Edges', edges.length, 'var(--color-info-light)'],
        ['Compromised', malNodes, 'var(--color-critical)'],
        ['Inferred Bridges', inferredEdges, 'var(--color-warning)'],
      ].map(([label, val, color]) => `
        <div style="background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:4px;padding:9px;text-align:center;box-shadow:var(--shadow-sm)">
          <div style="font-size:17px;font-weight:700;color:${color};font-family:var(--font-sans)">${val}</div>
          <div style="font-size:9.5px;color:var(--text-tertiary);text-transform:uppercase;letter-spacing:0.5px;font-family:var(--font-sans);font-weight:600">${label}</div>
        </div>
      `).join('')}
    </div>

    <div class="rail-title" style="margin-bottom:7px">MITRE ATT&amp;CK Matrix Coverage</div>
    ${[...mitreSet].map(t => `
      <div style="display:flex;align-items:center;gap:7px;margin-bottom:5px;font-size:10.5px">
        <span class="mitre-tag">${t}</span>
        <span style="color:var(--text-secondary)">${mitreNames[t] || t}</span>
      </div>
    `).join('')}

    <div style="margin-top:14px">
      <div class="rail-title" style="margin-bottom:7px">Internal Pivot Nodes (Betweenness Centrality)</div>
      ${nodes.filter(n => n.centrality > 0).sort((a,b) => b.centrality - a.centrality).slice(0, 6).map(n => `
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:5px;font-size:10px">
          <div style="flex:1;font-family:var(--font-mono);color:${n.is_malicious ? 'var(--color-critical)' : 'var(--text-secondary)'};white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
            ${n.label}
          </div>
          <div style="width:70px;background:var(--bg-surface-elevated);border:1px solid var(--border-subtle);border-radius:2px;height:5px;overflow:hidden">
            <div style="width:${(n.centrality * 100).toFixed(0)}%;height:100%;background:${n.is_malicious ? 'var(--color-critical)' : 'var(--color-info-light)'};border-radius:2px"></div>
          </div>
          <span style="font-size:9.5px;color:var(--text-tertiary);font-family:var(--font-mono)">${(n.centrality * 100).toFixed(1)}%</span>
        </div>
      `).join('')}
    </div>
  `;
}

const mitreNames = {
  'T1078': 'Valid Accounts (Initial Access)',
  'T1087': 'Account Discovery (Reconnaissance)',
  'T1558': 'Steal/Forge Kerberos Tickets (Privilege Escalation)',
  'T1021': 'Remote Services / SMB (Lateral Movement)',
  'T1048': 'Exfiltration Over Alternative Protocol',
};

// ── 9. EVIDENCE DNA INSPECTOR (BOTTOM DRAWER) ───────────────────────────────

function renderEvidenceDNA(log) {
  const body = document.getElementById('evidence-body');
  const skew = log.skew_corrected_sec || 0;
  const skewStr = skew >= 0 ? `+${skew}s` : `${skew}s`;
  const severityColor = { CRITICAL: 'red', HIGH: 'amber', MEDIUM: 'cyan', LOW: 'green' }[log.severity] || 'cyan';

  let rawJson = '';
  try {
    rawJson = JSON.stringify(JSON.parse(log.raw_payload || '{}'), null, 2);
  } catch {
    rawJson = log.raw_payload || '{}';
  }
  state.currentEvidenceJson = rawJson;

  body.innerHTML = `
    <div style="display:flex;align-items:center;gap:7px;margin-bottom:7px;flex-wrap:wrap">
      <span style="font-family:var(--font-mono);font-size:12px;font-weight:700;color:${log.is_inferred ? 'var(--color-warning)' : 'var(--color-info-light)'}">${log.log_id}</span>
      <span style="font-size:10px;color:var(--text-tertiary)">|</span>
      <span style="font-size:11px;font-weight:600;color:var(--text-primary);font-family:var(--font-mono)">${log.action || ''}</span>
      ${log.mitre_tag ? `<span class="mitre-tag">${log.mitre_tag}</span>` : ''}
      <span class="chip-${severityColor === 'red' ? 'red' : (severityColor === 'amber' ? 'amber' : 'cyan')}" style="padding:1px 5px;border-radius:3px;font-size:9.5px;font-family:var(--font-mono);font-weight:600">${log.severity || 'LOW'}</span>
      ${log.is_inferred ? '<span class="inferred-tag">INFERRED LATERAL BRIDGE</span>' : ''}
      <span style="font-size:10px;color:${log.confidence >= 0.85 ? 'var(--color-critical)' : 'var(--color-warning)'};font-family:var(--font-mono);margin-left:auto;font-weight:600">${log.confidence ? Math.round(log.confidence * 100) + '% Confidence Corroboration' : ''}</span>
    </div>

    <div class="ev-split">
      <div class="ev-grid">
        <span class="ev-lbl">Source Host:</span>
        <span class="ev-val cyan">${log.source_host || 'N/A'}</span>
        
        <span class="ev-lbl">Raw Ingest Time:</span>
        <span class="ev-val">${log.raw_timestamp || 'N/A'} <span style="color:var(--color-warning)">(Clock Skew: ${log.host_skew_sec >= 0 ? '+' : ''}${log.host_skew_sec || 0}s)</span></span>
        
        <span class="ev-lbl">Normalized Master Time:</span>
        <span class="ev-val cyan">${log.normalized_timestamp || 'N/A'} <span style="color:var(--color-success)">(Correction: ${skewStr})</span></span>
        
        <span class="ev-lbl">Interaction:</span>
        <span class="ev-val">${log.source || '?'} <span style="color:var(--text-tertiary)">──[${log.action}]──&gt;</span> <span style="color:${log.is_malicious ? 'var(--color-critical)' : 'var(--text-primary)'}">${log.target || '?'}</span></span>
        
        <span class="ev-lbl">Protocol / Port:</span>
        <span class="ev-val">${log.protocol || 'TCP'} / ${log.port || '0'}</span>
        
        <span class="ev-lbl">MITRE Mapping:</span>
        <span class="ev-val amber">${log.mitre_technique || log.mitre_tag || 'N/A'}</span>
      </div>

      <div>
        <div style="font-size:9.5px;color:var(--text-tertiary);text-transform:uppercase;letter-spacing:0.5px;font-family:var(--font-sans);margin-bottom:3px;font-weight:600">Raw Telemetry Payload</div>
        <div class="json-box">${escapeHtml(rawJson)}</div>
      </div>
    </div>
  `;
}

function copyCurrentEvidence() {
  if (!state.currentEvidenceJson) return;
  navigator.clipboard.writeText(state.currentEvidenceJson).then(() => {
    alert('Forensic JSON copied to clipboard.');
  });
}

function escapeHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function openDrawer() { document.getElementById('evidence-drawer').classList.add('open'); }
function closeDrawer() { document.getElementById('evidence-drawer').classList.remove('open'); }

// ── 10. CHAOS CONTROLS & TAB SWITCHING ──────────────────────────────────────

function onToggleChange() {
  state.currentSettings = {
    shuffle:        document.getElementById('tog-shuffle').checked,
    inject_skew:    document.getElementById('tog-skew').checked,
    drop_telemetry: document.getElementById('tog-drop').checked,
    drop_rate:      0.15,
  };
  if (state.currentDataset === 'builtin') {
    runAnalysis(state.currentSettings);
  }
}

function selectDataset(type) {
  state.currentDataset = type;
  document.getElementById('btn-builtin').classList.toggle('active', type === 'builtin');
  document.querySelectorAll('.scenario-btn').forEach(b => b.classList.remove('active'));
  if (type === 'builtin') {
    runAnalysis(state.currentSettings);
  }
}

async function loadScenario(scenarioName) {
  showLoading(true);
  try {
    document.getElementById('btn-builtin').classList.remove('active');
    document.querySelectorAll('.scenario-btn').forEach(b => b.classList.remove('active'));
    const targetBtn = document.getElementById(`btn-scenario-${scenarioName}`);
    if (targetBtn) targetBtn.classList.add('active');

    let scenarioLogs = null;
    try {
      const res = await fetch(`/sample-data/${scenarioName}.json`);
      if (res.ok) {
        scenarioLogs = await res.json();
      }
    } catch (e) {
      console.warn('Direct sample-data fetch skipped:', e);
    }

    if (scenarioLogs) {
      const blob = new Blob([JSON.stringify(scenarioLogs)], { type: 'application/json' });
      const form = new FormData();
      form.append('file', blob, `${scenarioName}.json`);
      const res = await apiFetch('/api/upload', { method: 'POST', body: form });
      if (res.ok) {
        const data = await res.json();
        state.analysisResult = data;
        state.currentDataset = scenarioName;
        renderAll(data);
        return;
      }
    }

    if (scenarioName === 'dropped_telemetry_gap') {
      state.currentSettings.drop_telemetry = true;
      const tog = document.getElementById('tog-drop');
      if (tog) tog.checked = true;
    } else {
      state.currentSettings.drop_telemetry = false;
      const tog = document.getElementById('tog-drop');
      if (tog) tog.checked = false;
    }
    await runAnalysis(state.currentSettings);
  } catch (err) {
    console.error('Scenario load error:', err);
    alert('Failed to load scenario: ' + err.message);
  } finally {
    showLoading(false);
  }
}

function switchTab(name) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  const target = document.getElementById(`tab-${name}`);
  if (target) target.classList.add('active');
  if (window.event && window.event.target) {
    window.event.target.classList.add('active');
  }
}

// ── 11. TOOLTIP & LOADING OVERLAY ──────────────────────────────────────────

function showTooltip(title, type, centrality, logs, x, y) {
  const tt = document.getElementById('node-tooltip');
  document.getElementById('tt-title').textContent = title;
  document.getElementById('tt-type').textContent = type;
  document.getElementById('tt-centrality').textContent = centrality;
  document.getElementById('tt-logs').textContent = logs;
  tt.style.display = 'block';
  tt.style.left = `${Math.min(x + 14, window.innerWidth - 270)}px`;
  tt.style.top = `${Math.min(y + 14, window.innerHeight - 150)}px`;
}

function hideTooltip() {
  const tt = document.getElementById('node-tooltip');
  if (tt) tt.style.display = 'none';
}

function showLoading(show) {
  const overlay = document.getElementById('loading-overlay');
  if (overlay) overlay.classList.toggle('show', show);
}

// ── 12. SOC EXECUTIVE AUDIO BRIEFING (OFFLINE WEB SPEECH API) ──────────────

function toggleAudioBriefing() {
  if (!state.analysisResult) {
    alert('Please run log analysis first.');
    return;
  }
  if (!window.speechSynthesis) {
    alert('Web Speech API is not supported in this browser.');
    return;
  }

  const btn = document.getElementById('btn-audio');
  const btnText = document.getElementById('btn-audio-text');

  if (state.isSpeaking) {
    window.speechSynthesis.cancel();
    state.isSpeaking = false;
    if (btn) btn.classList.remove('speaking');
    if (btnText) btnText.textContent = 'Audio Briefing';
    return;
  }

  window.speechSynthesis.cancel();
  const data = state.analysisResult;
  const ia = data.initial_access || {};
  const br = data.blast_radius || {};
  const steps = (data.xai_report || []).filter(s => s.present !== false);

  let script = `OBSYRON Security Operations Briefing for HackInnovision 2026 Track C. `;
  script += `Enterprise telemetry reduction: ${data.raw_log_count} raw logs were ingested, isolating ${data.malicious_signal_count} high-priority attack signals. `;
  script += `Patient Zero initial access vector is confirmed at ${ia.entity || 'external IP'} targeting employee ${ia.patient_zero_account || 'emp_rohan'}. `;
  script += `Forward reachability calculates a blast radius of ${br.count || 0} downstream assets currently exposed or compromised. `;
  script += `Reconstructed attack graph certainty stands at ${Math.round((data.overall_confidence || 0) * 100)} percent. `;
  script += `Kill chain summary: `;

  steps.forEach(s => {
    script += `Stage ${s.step}: ${s.title}. ${s.narrative.substring(0, 115)}. `;
  });

  script += `Prioritized containment actions are active in the response playbook. End of briefing.`;

  const utter = new SpeechSynthesisUtterance(script);
  utter.rate = 0.95;
  utter.pitch = 1.0;
  utter.volume = 1.0;

  if (btn) btn.classList.add('speaking');
  if (btnText) btnText.textContent = 'Stop Briefing';
  state.isSpeaking = true;

  utter.onend = () => {
    if (btn) btn.classList.remove('speaking');
    if (btnText) btnText.textContent = 'Audio Briefing';
    state.isSpeaking = false;
  };
  utter.onerror = () => {
    if (btn) btn.classList.remove('speaking');
    if (btnText) btnText.textContent = 'Audio Briefing';
    state.isSpeaking = false;
  };

  window.speechSynthesis.speak(utter);
}

// ── 13. OPERATOR AUTHORIZATION & SESSION STATE ─────────────────────────────

function getActiveOperator() {
  try {
    const raw = localStorage.getItem('obsyron_operator');
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
}

function initAuth() {
  const op = getActiveOperator();
  updateAuthUI(op);

  // Wire navigation & header auth buttons to open modal instead of hard navigating
  const headerBtn = document.getElementById('btn-header-auth');
  if (headerBtn) {
    headerBtn.addEventListener('click', (e) => {
      e.preventDefault();
      openAuthModal();
    });
  }

  const navAuth = document.getElementById('nav-link-auth');
  if (navAuth) {
    navAuth.addEventListener('click', (e) => {
      const currentOp = localStorage.getItem('obsyron_operator');
      if (currentOp) {
        // If already authorized, show active operator clearance overview modal
        e.preventDefault();
        openAuthModal();
      }
      // If guest / not logged in, navigates directly to the full-screen /login portal!
    });
  }

  const mobileNavAuth = document.getElementById('mobile-nav-auth');
  if (mobileNavAuth) {
    mobileNavAuth.addEventListener('click', (e) => {
      const currentOp = localStorage.getItem('obsyron_operator');
      if (currentOp) {
        e.preventDefault();
        closeMobileMenu();
        openAuthModal();
      } else {
        closeMobileMenu();
        // Navigates directly to the full-screen /login portal!
      }
    });
  }

  // Check URL params for ?authorized=1 notification
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('authorized') === '1') {
    window.history.replaceState({}, document.title, window.location.pathname);
  }
}

function updateAuthUI(op) {
  const iconElem = document.getElementById('header-auth-icon');
  const labelElem = document.getElementById('header-auth-label');
  const badgeElem = document.getElementById('header-auth-badge');
  const navAuth = document.getElementById('nav-link-auth');

  const mobileStatus = document.getElementById('mobile-auth-status');
  const mobileLabel = document.getElementById('mobile-auth-label');
  const mobileIcon = document.getElementById('mobile-auth-icon');

  const modalActive = document.getElementById('modal-active-operator');
  const modalAvatar = document.getElementById('modal-op-avatar');
  const modalName = document.getElementById('modal-op-name');
  const modalRole = document.getElementById('modal-op-role');

  if (op) {
    if (iconElem) iconElem.textContent = op.avatar || '🛡️';
    if (labelElem) labelElem.textContent = op.name || op.username;
    if (badgeElem) {
      badgeElem.style.display = 'inline-block';
      badgeElem.textContent = op.clearance_code || 'L4';
      badgeElem.className = 'header-clearance-pill ' + (
        op.clearance_code === 'L4' ? 'clearance-l4' :
        op.clearance_code === 'L3' ? 'clearance-l3' : 'clearance-l2'
      );
    }
    if (mobileStatus) {
      mobileStatus.innerHTML = `OPERATOR: <strong style="color:var(--text-primary)">${op.name || op.username}</strong> <span class="header-clearance-pill ${op.clearance_code === 'L4' ? 'clearance-l4' : op.clearance_code === 'L3' ? 'clearance-l3' : 'clearance-l2'}">${op.clearance_code || 'L4'}</span>`;
    }
    if (mobileLabel) mobileLabel.textContent = `Operator: ${op.name || op.username}`;
    if (mobileIcon) mobileIcon.textContent = op.avatar || '🛡️';

    if (modalActive) modalActive.style.display = 'block';
    if (modalAvatar) modalAvatar.textContent = op.avatar || '🛡️';
    if (modalName) modalName.textContent = op.name || op.username;
    if (modalRole) modalRole.textContent = `${op.role || 'Forensic Operator'} · ${op.clearance || 'Level 4'}`;
  } else {
    if (iconElem) iconElem.textContent = '🔒';
    if (labelElem) labelElem.textContent = 'Log In / Sign Up';
    if (badgeElem) {
      badgeElem.style.display = 'none';
      badgeElem.className = 'header-clearance-pill';
    }
    if (mobileStatus) mobileStatus.textContent = 'OPERATOR STATUS: GUEST';
    if (mobileLabel) mobileLabel.textContent = 'Log In / Sign Up';
    if (mobileIcon) mobileIcon.textContent = '🔒';
    if (modalActive) modalActive.style.display = 'none';
  }
}

function switchModalAuthTab(tab) {
  const tabLogin = document.getElementById('modal-tab-login');
  const tabSignup = document.getElementById('modal-tab-signup');
  const panelLogin = document.getElementById('modal-panel-login');
  const panelSignup = document.getElementById('modal-panel-signup');
  const feedback = document.getElementById('modal-feedback');

  if (feedback) {
    feedback.style.display = 'none';
    feedback.className = '';
  }

  if (tab === 'signup') {
    tabLogin.classList.remove('active');
    tabSignup.classList.add('active');
    panelLogin.style.display = 'none';
    panelSignup.style.display = 'block';
  } else {
    tabSignup.classList.remove('active');
    tabLogin.classList.add('active');
    panelSignup.style.display = 'none';
    panelLogin.style.display = 'block';
  }
}

function openAuthModal() {
  const modal = document.getElementById('auth-modal');
  if (modal) modal.classList.add('show');
}

function closeAuthModal() {
  const modal = document.getElementById('auth-modal');
  if (modal) modal.classList.remove('show');
}

function handleAuthModalClick(e) {
  if (e.target.id === 'auth-modal') {
    closeAuthModal();
  }
}

async function quickSwitchRole(uname, pwd, lvl) {
  const uInput = document.getElementById('modal-input-username');
  const pInput = document.getElementById('modal-input-password');
  if (uInput) uInput.value = uname;
  if (pInput) pInput.value = pwd;
  await submitAuthLogin(uname, pwd, lvl);
}

async function handleModalLogin(e) {
  e.preventDefault();
  const uname = document.getElementById('modal-input-username').value.trim();
  const pwd = document.getElementById('modal-input-password').value.trim();
  await submitAuthLogin(uname, pwd, null);
}

async function submitAuthLogin(username, password, clearanceOverride) {
  const feedback = document.getElementById('modal-feedback');
  const btn = document.getElementById('btn-modal-auth');

  if (feedback) {
    feedback.style.display = 'none';
    feedback.className = '';
  }
  if (btn) btn.disabled = true;

  try {
    const res = await apiFetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: username,
        password: password,
        clearance_override: clearanceOverride
      })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || 'Authorization failed.');
    }

    localStorage.setItem('obsyron_auth_token', data.token);
    localStorage.setItem('obsyron_operator', JSON.stringify(data.operator));

    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.background = 'var(--color-success-bg)';
      feedback.style.color = 'var(--color-success)';
      feedback.style.border = '1px solid var(--color-success-border)';
      feedback.textContent = `✓ Clearance Granted: ${data.operator.clearance}`;
    }

    updateAuthUI(data.operator);

    setTimeout(() => {
      closeAuthModal();
      if (feedback) feedback.style.display = 'none';
    }, 700);

  } catch (err) {
    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.background = 'var(--color-critical-bg)';
      feedback.style.color = 'var(--color-critical)';
      feedback.style.border = '1px solid var(--color-critical-border)';
      feedback.textContent = `❌ ${err.message}`;
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function handleModalSignup(e) {
  e.preventDefault();
  const name = document.getElementById('modal-signup-name').value.trim();
  const username = document.getElementById('modal-signup-username').value.trim();
  const password = document.getElementById('modal-signup-password').value.trim();
  const clearance = document.getElementById('modal-signup-clearance').value;

  const feedback = document.getElementById('modal-feedback');
  const btn = document.getElementById('btn-modal-signup');

  if (feedback) {
    feedback.style.display = 'none';
    feedback.className = '';
  }
  if (btn) btn.disabled = true;

  try {
    const res = await apiFetch('/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name,
        username: username,
        password: password,
        clearance: clearance
      })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || 'Registration failed.');
    }

    localStorage.setItem('obsyron_auth_token', data.token);
    localStorage.setItem('obsyron_operator', JSON.stringify(data.operator));

    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.background = 'var(--color-success-bg)';
      feedback.style.color = 'var(--color-success)';
      feedback.style.border = '1px solid var(--color-success-border)';
      feedback.textContent = `✓ Account Created! Clearance Granted: ${data.operator.clearance}`;
    }

    updateAuthUI(data.operator);

    setTimeout(() => {
      closeAuthModal();
      if (feedback) feedback.style.display = 'none';
    }, 700);

  } catch (err) {
    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.background = 'var(--color-critical-bg)';
      feedback.style.color = 'var(--color-critical)';
      feedback.style.border = '1px solid var(--color-critical-border)';
      feedback.textContent = `❌ ${err.message}`;
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function logoutOperator() {
  const token = localStorage.getItem('obsyron_auth_token');
  try {
    if (token) {
      await apiFetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
    }
  } catch (e) {
    console.warn('Logout network notice:', e);
  } finally {
    localStorage.removeItem('obsyron_auth_token');
    localStorage.removeItem('obsyron_operator');
    updateAuthUI(null);
    closeAuthModal();
  }
}

// ── 13. SUPABASE POSTGRESQL DATABASE MANAGEMENT ───────────────────────────

async function initDatabaseStatus() {
  try {
    const res = await apiFetch('/api/database/status');
    if (!res.ok) return;
    const data = await res.json();
    updateDatabaseUI(data);
  } catch (err) {
    console.warn('Database status check notice:', err);
  }
}

function updateDatabaseUI(data) {
  const dot = document.getElementById('db-status-dot');
  const label = document.getElementById('db-status-label');
  const modalDot = document.getElementById('db-modal-dot');
  const modalText = document.getElementById('db-modal-status-text');

  if (data.authenticated) {
    if (dot) dot.style.background = '#10B981'; // Green
    if (label) label.textContent = 'Supabase: Connected';
    if (modalDot) modalDot.style.background = '#10B981';
    if (modalText) {
      modalText.textContent = '🟢 Connected & Authenticated (PostgreSQL Live)';
      modalText.style.color = 'var(--color-success)';
    }
  } else if (data.connected) {
    if (dot) dot.style.background = '#F59E0B'; // Amber
    if (label) label.textContent = 'Supabase: Key Needed';
    if (modalDot) modalDot.style.background = '#F59E0B';
    if (modalText) {
      modalText.textContent = '🟡 Host Reached (Key Required)';
      modalText.style.color = 'var(--color-warning)';
    }
  } else {
    if (dot) dot.style.background = '#64748B'; // Muted
    if (label) label.textContent = 'Supabase: Standby';
    if (modalDot) modalDot.style.background = '#64748B';
    if (modalText) {
      modalText.textContent = '⚪ Local-First Standby';
      modalText.style.color = 'var(--text-secondary)';
    }
  }
}

function openDatabaseModal() {
  const modal = document.getElementById('database-modal');
  if (modal) modal.style.display = 'flex';
  initDatabaseStatus();
}

function closeDatabaseModal() {
  const modal = document.getElementById('database-modal');
  if (modal) modal.style.display = 'none';
}

function handleDatabaseModalClick(event) {
  if (event.target.id === 'database-modal') {
    closeDatabaseModal();
  }
}

async function saveDatabaseKey() {
  const input = document.getElementById('input-supabase-key');
  const feedback = document.getElementById('db-modal-feedback');
  const key = (input ? input.value : '').trim();

  if (!key) {
    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.background = 'var(--color-critical-bg)';
      feedback.style.color = 'var(--color-critical)';
      feedback.textContent = 'Please paste your Supabase API key.';
    }
    return;
  }

  try {
    const res = await apiFetch('/api/database/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ supabase_key: key })
    });
    const data = await res.json();
    if (data.status) {
      updateDatabaseUI(data.status);
    }
    if (feedback) {
      feedback.style.display = 'block';
      if (data.status && data.status.authenticated) {
        feedback.style.background = 'var(--color-success-bg)';
        feedback.style.color = 'var(--color-success)';
        feedback.textContent = '✓ Connected to Supabase PostgreSQL successfully!';
      } else {
        feedback.style.background = 'var(--color-warning-bg)';
        feedback.style.color = 'var(--color-warning)';
        feedback.textContent = `Key saved. Status: ${data.status ? data.status.message : 'Configured'}`;
      }
    }
  } catch (err) {
    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.background = 'var(--color-critical-bg)';
      feedback.style.color = 'var(--color-critical)';
      feedback.textContent = `Error: ${err.message}`;
    }
  }
}

async function syncActiveInvestigationToSupabase() {
  const btn = document.getElementById('btn-sync-supabase');
  const feedback = document.getElementById('db-modal-feedback');
  if (btn) btn.disabled = true;

  try {
    const res = await apiFetch('/api/database/sync', { method: 'POST' });
    const data = await res.json();
    if (feedback) {
      feedback.style.display = 'block';
      if (data.success) {
        feedback.style.background = 'var(--color-success-bg)';
        feedback.style.color = 'var(--color-success)';
        feedback.textContent = '✓ Forensic case and audit logs synced to Supabase!';
      } else {
        feedback.style.background = 'var(--color-warning-bg)';
        feedback.style.color = 'var(--color-warning)';
        feedback.textContent = `Sync notice: ${data.error || data.message || 'Check API key permissions'}`;
      }
    }
  } catch (err) {
    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.background = 'var(--color-critical-bg)';
      feedback.style.color = 'var(--color-critical)';
      feedback.textContent = `Sync failed: ${err.message}`;
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── 14. BOOTSTRAP ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initAuth();
  initDatabaseStatus();
  runAnalysis(state.currentSettings);
});
