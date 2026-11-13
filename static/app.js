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
  sliderTimeout: null,
  isPlayingTimeline: false,
  timelineInterval: null,
  isSpeaking: false,
  currentEvidenceJson: ''
};

// ── 1. API INTEGRATION ─────────────────────────────────────────────────────

async function runAnalysis(settings) {
  showLoading(true);
  try {
    const res = await fetch('/api/analyze', {
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
    const res = await fetch(`/api/graph/snapshot?timestamp=${encodeURIComponent(timestamp)}`);
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
    const res = await fetch(`/api/evidence/${encodeURIComponent(logId)}`);
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
    const res = await fetch('/api/upload', {
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

// ── 2. UNIFIED RENDER DISPATCHER ───────────────────────────────────────────

function renderAll(data) {
  renderKPIs(data);
  renderGraph(data);
  renderXAI(data);
  renderPlaybook(data);
  renderMatrix(data);
  initTimelineSlider(data);
  renderQuickActions(data);
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

// ── 4. CYTOSCAPE ATTACK GRAPH ──────────────────────────────────────────────

function entityBadge(type) {
  const map = {
    USER: '[USER]',
    DEVICE: '[DEVICE]',
    SERVICE: '[SERVICE]',
    AUTH_ENDPOINT: '[EXT_IP]'
  };
  return map[type] || '[NODE]';
}

function entityFillColor(type, isMalicious) {
  if (isMalicious) {
    const mal = {
      USER: '#0C2338',
      DEVICE: '#251518',
      SERVICE: '#2B1D08',
      AUTH_ENDPOINT: '#2D1013'
    };
    return mal[type] || '#221518';
  }
  return '#111622';
}

function entityStrokeColor(type) {
  const map = {
    USER: '#38BDF8',
    DEVICE: '#64748B',
    SERVICE: '#F59E0B',
    AUTH_ENDPOINT: '#EF4444'
  };
  return map[type] || '#64748B';
}

function renderGraph(data) {
  const container = document.getElementById('cy');

  const elements = [];
  const nodeSet = new Set();

  (data.nodes || []).forEach(n => {
    nodeSet.add(n.id);
    elements.push({
      group: 'nodes',
      data: {
        id: n.id,
        label: `${entityBadge(n.entity_type)}\n${n.label}`,
        entity_type: n.entity_type,
        is_malicious: n.is_malicious,
        centrality: n.centrality,
        log_ids: n.log_ids || [],
        mitre_tags: n.mitre_tags || [],
        color: entityStrokeColor(n.entity_type),
        bg: entityFillColor(n.entity_type, n.is_malicious),
      }
    });
  });

  (data.edges || []).forEach((e, i) => {
    if (!nodeSet.has(e.source) || !nodeSet.has(e.target)) return;
    if (!e.mitre_tag && !e.is_inferred && e.severity !== 'CRITICAL' && e.severity !== 'HIGH') {
      return;
    }
    const confVal = Math.round((e.confidence || 0.75) * 100);
    elements.push({
      group: 'edges',
      data: {
        id: e.id || `edge-${i}`,
        source: e.source,
        target: e.target,
        label: `${e.action}\n${confVal}%`,
        is_inferred: Boolean(e.is_inferred),
        confidence: e.confidence,
        mitre_tag: e.mitre_tag,
        log_ids: e.log_ids || [],
        severity: e.severity,
        raw_payload: e.raw_payload,
        normalized_timestamp: e.normalized_timestamp,
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

  state.cy = cytoscape({
    container,
    elements,
    layout: {
      name: 'breadthfirst',
      directed: true,
      roots: elements.filter(e => e.group === 'nodes' && (e.data.id === '185.220.101.47' || e.data.entity_type === 'AUTH_ENDPOINT')).map(e => e.data.id),
      padding: 30,
      spacingFactor: 1.4,
      avoidOverlap: true,
      animate: false
    },
    style: [
      {
        selector: 'node',
        style: {
          'background-color': 'data(bg)',
          'border-color': 'data(color)',
          'border-width': 1.8,
          'label': 'data(label)',
          'text-valign': 'center',
          'text-halign': 'center',
          'color': '#F8FAFC',
          'font-size': 9.5,
          'font-weight': 600,
          'font-family': 'JetBrains Mono, monospace',
          'text-wrap': 'wrap',
          'width': 105,
          'height': 52,
          'shape': 'roundrectangle',
          'text-max-width': 98,
          'transition-property': 'background-color, border-color, opacity',
          'transition-duration': '0.15s'
        }
      },
      {
        selector: 'node[entity_type = "USER"]',
        style: { shape: 'roundrectangle', width: 95, height: 50 }
      },
      {
        selector: 'node[entity_type = "SERVICE"]',
        style: { shape: 'diamond', width: 108, height: 60 }
      },
      {
        selector: 'node[entity_type = "AUTH_ENDPOINT"]',
        style: { shape: 'hexagon', width: 100, height: 54 }
      },
      {
        selector: 'node[?is_malicious]',
        style: {
          'border-width': 2.4,
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 2.2,
          'line-color': '#475569',
          'target-arrow-color': '#475569',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'label': 'data(label)',
          'font-size': 8,
          'font-weight': 600,
          'font-family': 'JetBrains Mono, monospace',
          'color': '#CBD5E1',
          'text-background-color': '#0B0F17',
          'text-background-opacity': 0.95,
          'text-background-padding': 3,
          'text-wrap': 'wrap',
          'text-max-width': 85,
          'edge-text-rotation': 'autorotate',
          'arrow-scale': 1.15
        }
      },
      {
        selector: 'edge[severity = "CRITICAL"], edge[!is_inferred][confidence >= 0.85]',
        style: {
          'line-color': '#EF4444',
          'target-arrow-color': '#EF4444',
          'width': 2.5,
          'color': '#FCA5A5',
        }
      },
      {
        selector: 'edge[?is_inferred]',
        style: {
          'line-color': '#F59E0B',
          'target-arrow-color': '#F59E0B',
          'line-style': 'dashed',
          'line-dash-pattern': [6, 4],
          'width': 2.2,
          'color': '#FCD34D',
        }
      },
      { selector: 'node:selected', style: { 'border-width': 3, 'border-color': '#38BDF8' } },
      { selector: '.dimmed', style: { 'opacity': 0.16 } },
      { selector: '.highlighted', style: { 'opacity': 1, 'z-index': 999 } },
      { selector: '.ancestor-highlight', style: { 'border-color': '#38BDF8', 'border-width': 2.8, 'opacity': 1 } },
      { selector: '.descendant-highlight', style: { 'border-color': '#EF4444', 'border-width': 2.8, 'opacity': 1 } },
    ]
  });

  // Node Click -> Evidence DNA + Blast Radius Highlight
  state.cy.on('tap', 'node', function(evt) {
    const node = evt.target;
    const logIds = node.data('log_ids') || [];
    const chosenId = logIds.find(id => id.startsWith('LOG-APT') || id.startsWith('UPLOAD')) || logIds[0];
    if (chosenId) fetchEvidence(chosenId);
    highlightBlastRadius(node);
  });

  // Edge Click -> Evidence DNA
  state.cy.on('tap', 'edge', function(evt) {
    const edge = evt.target;
    const logIds = edge.data('log_ids') || [];
    const firstId = logIds[0];
    if (firstId) fetchEvidence(firstId);
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
      state.cy.elements().removeClass('dimmed highlighted ancestor-highlight descendant-highlight');
      closeDrawer();
    }
  });
}

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

// Canvas Toolbar Helpers
function zoomIn() { if (state.cy) state.cy.zoom(state.cy.zoom() * 1.25); }
function zoomOut() { if (state.cy) state.cy.zoom(state.cy.zoom() * 0.8); }
function fitGraph() { if (state.cy) state.cy.fit(null, 30); }
function reLayoutGraph() {
  if (!state.cy) return;
  state.cy.layout({
    name: 'breadthfirst',
    directed: true,
    padding: 30,
    spacingFactor: 1.4,
    avoidOverlap: true,
    animate: true,
    animationDuration: 300
  }).run();
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
      <div class="xai-step-card ${step.is_inferred ? 'inferred-step' : ''}">
        <div class="xai-card-top">
          <span class="step-pill">STAGE ${step.step}</span>
          <span class="step-heading">${step.title}</span>
          <span class="mitre-tag">${step.mitre}</span>
          ${step.is_inferred ? '<span class="inferred-tag">INFERRED BRIDGE</span>' : ''}
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
    `<span style="display:inline-block;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);color:var(--color-critical);padding:2px 7px;border-radius:3px;font-size:9.5px;font-family:var(--font-mono);font-weight:600;margin:2px">${n}</span>`
  ).join('');

  container.innerHTML = `
    <div class="playbook-progress">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">
        <span style="font-size:9.5px;font-weight:700;letter-spacing:0.5px;text-transform:uppercase;color:var(--text-tertiary);font-family:var(--font-sans)">Containment Readiness</span>
        <span id="containment-percent" style="font-size:11px;font-family:var(--font-mono);font-weight:700;color:var(--color-success)">0% COMPLETE</span>
      </div>
      <div class="conf-track" style="height:4px">
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
    <button class="rail-btn" style="border-color:var(--color-critical-border);color:var(--color-critical)" onclick="alert('Dispatched: Account session revocation sent to Active Directory for ' + '${ia.patient_zero_account || 'Patient Zero'}')">
      <span style="font-family:var(--font-mono);font-weight:700;font-size:9.5px">[LOCK]</span> Lock ${ia.patient_zero_account || 'emp_rohan'}
    </button>
    <button class="rail-btn" style="border-color:var(--color-critical-border);color:var(--color-critical)" onclick="alert('Dispatched: Egress firewall null-route rule pushed for IP 185.220.101.47')">
      <span style="font-family:var(--font-mono);font-weight:700;font-size:9.5px">[BLOCK]</span> Block 185.220.101.47
    </button>
    <button class="rail-btn" style="border-color:var(--color-warning-border);color:var(--color-warning)" onclick="alert('Dispatched: Service credential rotation triggered for svc_ci_deploy')">
      <span style="font-family:var(--font-mono);font-weight:700;font-size:9.5px">[ROTATE]</span> Rotate svc_ci_deploy
    </button>
    <button class="rail-btn" style="border-color:var(--color-warning-border);color:var(--color-warning)" onclick="alert('Dispatched: VLAN network quarantine triggered for host db-prod-01')">
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
        <div style="background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:4px;padding:9px;text-align:center">
          <div style="font-size:17px;font-weight:700;color:${color};font-family:var(--font-sans)">${val}</div>
          <div style="font-size:9.5px;color:var(--text-tertiary);text-transform:uppercase;letter-spacing:0.5px;font-family:var(--font-sans);font-weight:500">${label}</div>
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
          <div style="width:70px;background:var(--bg-surface-elevated);border-radius:2px;height:4px;overflow:hidden">
            <div style="width:${(n.centrality * 100).toFixed(0)}%;height:4px;background:${n.is_malicious ? 'var(--color-critical)' : 'var(--color-info-light)'};border-radius:2px"></div>
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
      <span style="font-size:11px;font-weight:600;color:#FFFFFF;font-family:var(--font-mono)">${log.action || ''}</span>
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
  if (type === 'builtin') {
    runAnalysis(state.currentSettings);
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
    btn.classList.remove('speaking');
    btnText.textContent = 'Executive Audio Briefing';
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

  btn.classList.add('speaking');
  btnText.textContent = 'Stop Audio Briefing';
  state.isSpeaking = true;

  utter.onend = () => {
    btn.classList.remove('speaking');
    btnText.textContent = 'Executive Audio Briefing';
    state.isSpeaking = false;
  };
  utter.onerror = () => {
    btn.classList.remove('speaking');
    btnText.textContent = 'Executive Audio Briefing';
    state.isSpeaking = false;
  };

  window.speechSynthesis.speak(utter);
}

// ── 13. BOOTSTRAP ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  runAnalysis(state.currentSettings);
});
