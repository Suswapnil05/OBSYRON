// ═══════════════════════════════════════════════════════════════════════════
// OBSYRON — Autonomous Forensic Investigation & Attack Graph Reconstruction
// HackInnovision 2026 (Track C) — Complete Dashboard Client Engine
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
  isSpeaking: false
};

// ── 1. API CLIENT METHODS ───────────────────────────────────────────────────

async function runAnalysis(settings) {
  showLoading(true);
  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings || state.currentSettings),
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Server returned ${res.status}: ${errText}`);
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
    console.error('Timeline snapshot fetch failed:', err);
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
    console.error('Evidence DNA fetch failed for ' + logId + ':', err);
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
    alert('Upload failed: ' + err.message);
  } finally {
    showLoading(false);
  }
}

// ── 2. UNIFIED RENDER PIPELINE ──────────────────────────────────────────────

function renderAll(data) {
  renderKPIs(data);
  renderGraph(data);
  renderXAI(data);
  renderContainment(data);
  renderStats(data);
  initTimelineSlider(data);
  renderQuickActions(data);
}

// ── 3. TOP KPI STRIP ────────────────────────────────────────────────────────

function renderKPIs(data) {
  const snrEl = document.getElementById('kpi-snr');
  const snrSub = document.getElementById('kpi-snr-sub');
  snrEl.textContent = `${data.raw_log_count} → ${data.malicious_signal_count}`;
  snrSub.textContent = 'Raw Enterprise Logs → Malicious Signals';

  const ia = data.initial_access || {};
  const pzEl = document.getElementById('kpi-pz');
  const pzSub = document.getElementById('kpi-pz-sub');
  pzEl.textContent = ia.entity || '—';
  pzSub.textContent = ia.timestamp
    ? `${ia.mitre_tactic} @ ${formatTimeOnly(ia.timestamp)}`
    : (ia.mitre_tactic || 'Patient Zero');

  const br = data.blast_radius || {};
  const brEl = document.getElementById('kpi-br');
  const brSub = document.getElementById('kpi-br-sub');
  brEl.textContent = `${br.count || 0} Assets`;
  brSub.textContent = `${br.affected_nodes ? br.affected_nodes.length : 0} Compromised / Reachable`;

  const conf = data.overall_confidence || 0;
  const confEl = document.getElementById('kpi-conf');
  const confSub = document.getElementById('kpi-conf-sub');
  const confPct = (conf * 100).toFixed(1);
  confEl.textContent = `${confPct}%`;
  if (conf < 0.75) {
    confEl.style.color = 'var(--amber)';
    confSub.textContent = '⚠️ Inferred Bridge Active (Confidence Penalized)';
  } else {
    confEl.style.color = 'var(--cyan)';
    confSub.textContent = 'Multi-Signal Corroborated';
  }
}

// ── 4. CYTOSCAPE ATTACK GRAPH ───────────────────────────────────────────────

function entityLabelBadge(type) {
  const map = {
    USER: '[USER]',
    DEVICE: '[DEVICE]',
    SERVICE: '[SERVICE]',
    AUTH_ENDPOINT: '[EXT_IP]'
  };
  return map[type] || '[NODE]';
}

function entityColor(type, isMalicious) {
  if (isMalicious) {
    const mal = {
      USER: '#0284C7',
      DEVICE: '#B91C1C',
      SERVICE: '#D97706',
      AUTH_ENDPOINT: '#DC2626'
    };
    return mal[type] || '#DC2626';
  }
  return '#1F2937';
}

function entityBorderColor(type) {
  const map = {
    USER: '#38BDF8',
    DEVICE: '#475569',
    SERVICE: '#F59E0B',
    AUTH_ENDPOINT: '#EF4444'
  };
  return map[type] || '#475569';
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
        label: `${entityLabelBadge(n.entity_type)}\n${n.label}`,
        entity_type: n.entity_type,
        is_malicious: n.is_malicious,
        centrality: n.centrality,
        log_ids: n.log_ids || [],
        mitre_tags: n.mitre_tags || [],
        color: entityBorderColor(n.entity_type),
        bg: entityColor(n.entity_type, n.is_malicious),
      }
    });
  });

  (data.edges || []).forEach((e, i) => {
    if (!nodeSet.has(e.source) || !nodeSet.has(e.target)) return;
    // Show malicious, inferred, or high-significance edges on main view
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
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">⬡</div><div>No attack graph nodes found</div></div>';
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
      spacingFactor: 1.35,
      avoidOverlap: true,
      animate: false
    },
    style: [
      {
        selector: 'node',
        style: {
          'background-color': 'data(bg)',
          'border-color': 'data(color)',
          'border-width': 2,
          'label': 'data(label)',
          'text-valign': 'center',
          'text-halign': 'center',
          'color': '#F3F4F6',
          'font-size': 9,
          'font-family': 'JetBrains Mono, monospace',
          'text-wrap': 'wrap',
          'width': 94,
          'height': 52,
          'shape': 'roundrectangle',
          'text-max-width': 88,
          'transition-property': 'background-color, border-color, shadow-blur',
          'transition-duration': '0.2s'
        }
      },
      {
        selector: 'node[entity_type = "USER"]',
        style: { shape: 'ellipse', width: 84, height: 56 }
      },
      {
        selector: 'node[entity_type = "SERVICE"]',
        style: { shape: 'diamond', width: 104, height: 62 }
      },
      {
        selector: 'node[entity_type = "AUTH_ENDPOINT"]',
        style: { shape: 'hexagon', width: 90, height: 56 }
      },
      {
        selector: 'node[?is_malicious]',
        style: {
          'shadow-blur': 18,
          'shadow-color': 'data(color)',
          'shadow-opacity': 0.7,
          'shadow-offset-x': 0,
          'shadow-offset-y': 0,
          'border-width': 2.5,
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
          'font-size': 7.5,
          'font-family': 'JetBrains Mono, monospace',
          'color': '#D1D5DB',
          'text-background-color': '#111827',
          'text-background-opacity': 0.9,
          'text-background-padding': 2,
          'text-wrap': 'wrap',
          'text-max-width': 75,
          'edge-text-rotation': 'autorotate',
          'arrow-scale': 1.1
        }
      },
      {
        selector: 'edge[severity = "CRITICAL"], edge[!is_inferred][confidence >= 0.85]',
        style: {
          'line-color': '#EF4444',
          'target-arrow-color': '#EF4444',
          'width': 2.8,
          'color': '#FCA5A5',
        }
      },
      {
        selector: 'edge[?is_inferred]',
        style: {
          'line-color': '#F59E0B',
          'target-arrow-color': '#F59E0B',
          'line-style': 'dashed',
          'line-dash-pattern': [8, 4],
          'width': 2.4,
          'color': '#FCD34D',
        }
      },
      { selector: 'node:selected', style: { 'border-width': 3.5, 'border-color': '#FFFFFF' } },
      { selector: '.dimmed', style: { 'opacity': 0.15 } },
      { selector: '.highlighted', style: { 'opacity': 1, 'z-index': 999 } },
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
      `Entity: ${node.data('entity_type')} | ${node.data('is_malicious') ? '🔴 COMPROMISED' : '✅ Benign'}`,
      `Centrality: ${(node.data('centrality') * 100).toFixed(1)}% (Pivot Score)`,
      `Correlated Logs: ${(node.data('log_ids') || []).length}`,
      bbox.left + pos.x, bbox.top + pos.y
    );
  });

  state.cy.on('mouseout', 'node', hideTooltip);

  // Background Tap -> Reset Dimming & Close Drawer
  state.cy.on('tap', function(evt) {
    if (evt.target === state.cy) {
      state.cy.elements().removeClass('dimmed highlighted');
      closeDrawer();
    }
  });
}

function highlightBlastRadius(node) {
  if (!state.cy) return;
  const cy = state.cy;
  cy.elements().addClass('dimmed');
  node.removeClass('dimmed').addClass('highlighted');
  node.successors().removeClass('dimmed').addClass('highlighted');
  node.predecessors().removeClass('dimmed').addClass('highlighted');
  node.connectedEdges().removeClass('dimmed').addClass('highlighted');
}

// ── 5. TIME-TRAVEL INVESTIGATION SLIDER ──────────────────────────────────────

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
  }, 350);
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

// ── 6. EXPLAINABLE AI & ROOT-CAUSE REPORT ───────────────────────────────────

function renderXAI(data) {
  const container = document.getElementById('xai-content');
  const steps = data.xai_report || [];
  if (!steps.length) {
    container.innerHTML = '<div class="empty-state"><div>No Explainable AI data</div></div>';
    return;
  }

  container.innerHTML = steps.map(step => {
    const confPct = Math.round(step.confidence * 100);
    const confColor = step.is_inferred ? '#F59E0B' : (confPct >= 90 ? '#EF4444' : '#38BDF8');
    const citations = (step.log_citations || []).map(lid =>
      `<span class="log-badge ${lid === 'INFERRED' ? 'inferred' : ''}" onclick="fetchEvidence('${lid}')" title="Click to inspect raw forensic evidence in Evidence DNA Ledger">[${lid}]</span>`
    ).join('');

    return `
      <div class="xai-step ${step.is_inferred ? 'inferred' : ''}">
        <div class="xai-step-header">
          <span class="step-num">STEP ${step.step}</span>
          <span class="step-title">${step.title}</span>
          <span class="mitre-badge">${step.mitre}</span>
          ${step.is_inferred ? '<span class="inferred-badge">INFERRED GAP BRIDGE</span>' : ''}
        </div>
        <div style="font-size:9px;color:var(--text3);margin-bottom:6px;font-family:var(--mono)">${step.mitre_name || ''}</div>
        <p class="xai-narrative">${step.narrative}</p>
        <div class="citations">${citations}</div>
        <div style="display:flex;align-items:center;gap:6px;margin-top:4px">
          <div class="conf-bar-wrap" style="flex:1">
            <div class="conf-bar" style="width:${confPct}%;background:${confColor}"></div>
          </div>
          <span style="font-size:9px;color:${confColor};font-family:var(--mono)">${confPct}% Confidence</span>
        </div>
      </div>
    `;
  }).join('');
}

// ── 7. CONTAINMENT PLAYBOOK & QUICK ACTIONS ─────────────────────────────────

function renderContainment(data) {
  const br = data.blast_radius || {};
  const list = br.containment_checklist || [];
  const container = document.getElementById('containment-content');

  const affectedHtml = (br.affected_nodes || []).map(n =>
    `<span style="display:inline-block;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.35);color:#EF4444;padding:2px 8px;border-radius:4px;font-size:9.5px;font-family:var(--mono);margin:2px">${n}</span>`
  ).join('');

  container.innerHTML = `
    <div style="margin-bottom:14px">
      <div class="rail-title" style="font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text3);margin-bottom:6px">
        Exposed Downstream Assets (${br.count || 0})
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px">${affectedHtml || '<span style="color:var(--text3);font-size:10px">None detected</span>'}</div>
    </div>
    <div class="rail-title" style="font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text3);margin-bottom:8px">
      Actionable Incident Response Playbook
    </div>
    ${list.map((item, i) => `
      <div class="containment-item" id="ci-${i}">
        <input type="checkbox" class="check-btn" onchange="this.closest('.containment-item').classList.toggle('containment-done', this.checked)">
        <span>${item}</span>
      </div>
    `).join('')}
  `;
}

function renderQuickActions(data) {
  const ia = data.initial_access || {};
  const el = document.getElementById('quick-actions');
  el.innerHTML = `
    <div style="font-size:9px;text-transform:uppercase;letter-spacing:1px;color:var(--text3);margin-bottom:6px">Priority Response:</div>
    <div class="rail-btn" style="font-size:10px;cursor:pointer;border-color:rgba(239,68,68,0.35);color:var(--red)" onclick="alert('Isolating account ${ia.entity || 'Patient Zero'} across Active Directory.')">
      🔴 Lock ${ia.entity || 'Patient Zero'}
    </div>
    <div class="rail-btn" style="font-size:10px;cursor:pointer;border-color:rgba(239,68,68,0.35);color:var(--red)" onclick="alert('Block rule dispatched to edge firewalls for 185.220.101.47')">
      🔴 Block 185.220.101.47
    </div>
    <div class="rail-btn" style="font-size:10px;cursor:pointer;border-color:rgba(245,158,11,0.35);color:var(--amber)" onclick="alert('Rotating Kerberos keys & secrets for svc_ci_deploy')">
      🟠 Rotate svc_ci_deploy
    </div>
    <div class="rail-btn" style="font-size:10px;cursor:pointer;border-color:rgba(245,158,11,0.35);color:var(--amber)" onclick="alert('db-prod-01 VLAN isolated. Standby database promoted.')">
      🟠 Quarantine db-prod-01
    </div>
  `;
}

// ── 8. GRAPH STATISTICS & PIVOT RANKING ─────────────────────────────────────

function renderStats(data) {
  const container = document.getElementById('stats-content');
  const nodes = data.nodes || [];
  const edges = data.edges || [];
  const malNodes = nodes.filter(n => n.is_malicious).length;
  const inferredEdges = edges.filter(e => e.is_inferred).length;
  const mitreSet = new Set(edges.filter(e => e.mitre_tag).map(e => e.mitre_tag));

  container.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px">
      ${[
        ['Total Entities', nodes.length, 'var(--cyan)'],
        ['Graph Edges', edges.length, 'var(--cyan)'],
        ['Compromised', malNodes, 'var(--red)'],
        ['Inferred Bridges', inferredEdges, 'var(--amber)'],
      ].map(([label, val, color]) => `
        <div style="background:var(--card2);border:1px solid var(--border2);border-radius:6px;padding:10px;text-align:center">
          <div style="font-size:18px;font-weight:700;color:${color}">${val}</div>
          <div style="font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px">${label}</div>
        </div>
      `).join('')}
    </div>
    <div class="rail-title" style="font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text3);margin-bottom:8px">MITRE ATT&CK Matrix Coverage</div>
    ${[...mitreSet].map(t => `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;font-size:10.5px">
        <span style="font-family:var(--mono);background:rgba(167,139,250,0.15);border:1px solid rgba(167,139,250,0.4);color:#A78BFA;padding:2px 6px;border-radius:3px;font-size:9px">${t}</span>
        <span style="color:var(--text2)">${mitreNames[t] || t}</span>
      </div>
    `).join('')}
    <div style="margin-top:14px">
      <div class="rail-title" style="font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text3);margin-bottom:8px">Top Compromised Pivot Hosts (Betweenness Centrality)</div>
      ${nodes.filter(n => n.centrality > 0).sort((a,b) => b.centrality - a.centrality).slice(0, 6).map(n => `
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;font-size:10px">
          <div style="flex:1;font-family:var(--mono);color:${n.is_malicious ? 'var(--red)' : 'var(--text2)'};white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
            ${n.label}
          </div>
          <div style="width:70px;background:var(--border);border-radius:2px;height:4px;overflow:hidden">
            <div style="width:${(n.centrality * 100).toFixed(0)}%;height:4px;background:${n.is_malicious ? 'var(--red)' : 'var(--cyan)'};border-radius:2px"></div>
          </div>
          <span style="font-size:9px;color:var(--text3);font-family:var(--mono)">${(n.centrality * 100).toFixed(1)}%</span>
        </div>
      `).join('')}
    </div>
  `;
}

const mitreNames = {
  'T1078': 'Valid Accounts (Initial Access)',
  'T1087': 'Account Discovery (Recon)',
  'T1558': 'Steal or Forge Kerberos Tickets (Priv Esc)',
  'T1021': 'Remote Services / SMB (Lateral Movement)',
  'T1048': 'Exfiltration Over Alternative Protocol',
};

// ── 9. EVIDENCE DNA INSPECTOR (BOTTOM DRAWER) ───────────────────────────────

function renderEvidenceDNA(log) {
  const body = document.getElementById('evidence-body');
  const skew = log.skew_corrected_sec || 0;
  const skewStr = skew >= 0 ? `+${skew}s` : `${skew}s`;
  const severityColor = { CRITICAL: 'red', HIGH: 'amber', MEDIUM: 'cyan', LOW: 'green' }[log.severity] || 'cyan';

  let payload = '';
  try {
    payload = JSON.stringify(JSON.parse(log.raw_payload || '{}'), null, 2);
  } catch {
    payload = log.raw_payload || '{}';
  }

  body.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap">
      <span style="font-family:var(--mono);font-size:13px;font-weight:700;color:${log.is_inferred ? 'var(--amber)' : 'var(--cyan)'}">${log.log_id}</span>
      <span style="font-size:10px;color:var(--text3)">|</span>
      <span style="font-size:11px;font-weight:600;color:var(--text)">${log.action || ''}</span>
      ${log.mitre_tag ? `<span style="font-size:9px;background:rgba(167,139,250,0.2);border:1px solid rgba(167,139,250,0.4);color:#A78BFA;padding:2px 7px;border-radius:3px;font-family:var(--mono)">${log.mitre_tag}</span>` : ''}
      <span style="font-size:9px;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.35);color:var(--${severityColor});padding:2px 7px;border-radius:3px">${log.severity || 'LOW'}</span>
      ${log.is_inferred ? '<span style="font-size:9px;background:rgba(245,158,11,0.2);border:1px solid var(--amber);color:var(--amber);padding:2px 7px;border-radius:3px">⚠️ INFERRED LATERAL BRIDGE</span>' : ''}
      <span style="font-size:10px;color:${log.confidence >= 0.85 ? 'var(--red)' : 'var(--amber)'};font-family:var(--mono);margin-left:auto">${log.confidence ? Math.round(log.confidence * 100) + '% Confidence Score' : ''}</span>
    </div>
    <div class="evidence-grid">
      <span class="ev-label">Source Host:</span>
      <span class="ev-value cyan">${log.source_host || 'N/A'}</span>
      <span class="ev-label">Raw Telemetry:</span>
      <span class="ev-value">${log.raw_timestamp || 'N/A'} <span style="color:var(--amber)">(Host Clock Skew Offset: ${log.host_skew_sec >= 0 ? '+' : ''}${log.host_skew_sec || 0}s)</span></span>
      <span class="ev-label">Normalized Master Time:</span>
      <span class="ev-value cyan">${log.normalized_timestamp || 'N/A'} <span style="color:var(--green)">(Correction Applied: t_norm = t_raw ${skewStr})</span></span>
      <span class="ev-label">Interaction Path:</span>
      <span class="ev-value">${log.source || '?'} <span style="color:var(--text3)">──[${log.action}]──&gt;</span> <span style="color:${log.is_malicious ? 'var(--red)' : 'var(--text)'}">${log.target || '?'}</span></span>
      <span class="ev-label">Protocol &amp; Port:</span>
      <span class="ev-value">${log.protocol || 'TCP'} / ${log.port || '0'}</span>
      <span class="ev-label">MITRE ATT&amp;CK Mapping:</span>
      <span class="ev-value amber">${log.mitre_technique || log.mitre_tag || 'N/A'}</span>
    </div>
    <div style="margin-top:8px">
      <div style="font-size:9px;color:var(--text3);margin-bottom:4px;text-transform:uppercase;letter-spacing:1px">Forensic Log Payload (Immutable JSON)</div>
      <div class="raw-payload">${escapeHtml(payload)}</div>
    </div>
  `;
}

function escapeHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function openDrawer() {
  document.getElementById('evidence-drawer').classList.add('open');
}
function closeDrawer() {
  document.getElementById('evidence-drawer').classList.remove('open');
}

// ── 10. CHAOS SIMULATOR CONTROLS ───────────────────────────────────────────

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

// ── 11. TAB NAVIGATION ──────────────────────────────────────────────────────

function switchTab(name) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  const targetPane = document.getElementById(`tab-${name}`);
  if (targetPane) targetPane.classList.add('active');
  if (window.event && window.event.target) {
    window.event.target.classList.add('active');
  }
}

// ── 12. HOVER TOOLTIP ───────────────────────────────────────────────────────

function showTooltip(title, type, centrality, logs, x, y) {
  const tt = document.getElementById('node-tooltip');
  document.getElementById('tt-title').textContent = title;
  document.getElementById('tt-type').textContent = type;
  document.getElementById('tt-centrality').textContent = centrality;
  document.getElementById('tt-logs').textContent = logs;
  tt.style.display = 'block';
  tt.style.left = `${Math.min(x + 12, window.innerWidth - 240)}px`;
  tt.style.top = `${Math.min(y + 12, window.innerHeight - 130)}px`;
}

function hideTooltip() {
  const tt = document.getElementById('node-tooltip');
  if (tt) tt.style.display = 'none';
}

function showLoading(show) {
  const overlay = document.getElementById('loading-overlay');
  if (overlay) overlay.classList.toggle('show', show);
}

// ── 13. SOC EXECUTIVE AUDIO BRIEFING (OFFLINE WEB SPEECH API) ──────────────

function playAudioBriefing() {
  if (!state.analysisResult) {
    alert('Run log analysis first to generate executive briefing.');
    return;
  }
  if (!window.speechSynthesis) {
    alert('Speech Synthesis API is not supported in this browser.');
    return;
  }

  if (state.isSpeaking) {
    window.speechSynthesis.cancel();
    state.isSpeaking = false;
    const btn = document.getElementById('btn-audio');
    btn.textContent = '▶ Play Audio Briefing';
    return;
  }

  window.speechSynthesis.cancel();
  const data = state.analysisResult;
  const ia = data.initial_access || {};
  const br = data.blast_radius || {};
  const steps = (data.xai_report || []).filter(s => s.present !== false);

  let script = `OBSYRON Security Operations Center Executive Briefing for HackInnovision 2026 Track C. `;
  script += `Signal reduction summary: ${data.raw_log_count} raw enterprise telemetry logs were ingested, isolating ${data.malicious_signal_count} high-priority malicious signals amidst background operational noise. `;
  script += `Initial access vector, Patient Zero, was identified as ${ia.entity || 'external identity'} operating under technique ${ia.mitre_tactic || 'T1078'}. `;
  script += `Forward reachability calculates a blast radius of ${br.count || 0} downstream enterprise assets currently exposed or compromised. `;
  script += `Overall reconstructed attack graph confidence stands at ${Math.round((data.overall_confidence || 0) * 100)} percent. `;
  script += `Chronological kill chain progression: `;

  steps.forEach(s => {
    script += `Step ${s.step}: ${s.title}. ${s.narrative.substring(0, 110)}. `;
  });

  script += `Prioritized containment actions have been populated in the response playbook. End of briefing.`;

  const utter = new SpeechSynthesisUtterance(script);
  utter.rate = 0.95;
  utter.pitch = 1.0;
  utter.volume = 1.0;

  const btn = document.getElementById('btn-audio');
  btn.textContent = '⏹ Stop Audio Briefing';
  state.isSpeaking = true;

  utter.onend = () => {
    btn.textContent = '▶ Play Audio Briefing';
    state.isSpeaking = false;
  };
  utter.onerror = () => {
    btn.textContent = '▶ Play Audio Briefing';
    state.isSpeaking = false;
  };

  window.speechSynthesis.speak(utter);
}

// ── 14. APPLICATION BOOTSTRAP ───────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  runAnalysis(state.currentSettings);
});

