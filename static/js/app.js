'use strict';

// ─── State ───────────────────────────────────────────────────────────────────
let currentEventSource = null;
let investigationActive = false;

// ─── DOM refs ────────────────────────────────────────────────────────────────
const targetInput     = document.getElementById('targetInput');
const investigateBtn  = document.getElementById('investigateBtn');
const stopBtn         = document.getElementById('stopBtn');
const progressPanel   = document.getElementById('progressPanel');
const progressFeed    = document.getElementById('progressFeed');
const reportPanel     = document.getElementById('reportPanel');
const typeDetector    = document.getElementById('typeDetector');
const typeIcon        = document.getElementById('typeIcon');
const typeLabel       = document.getElementById('typeLabel');
const statusDot       = document.getElementById('statusDot');
const statusText      = document.getElementById('statusText');
const historyList     = document.getElementById('historyList');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
const headerTime      = document.getElementById('headerTime');

// ─── Clock ───────────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  headerTime.textContent = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

// ─── Target type detection ───────────────────────────────────────────────────
const TYPE_RULES = [
  { pattern: /^CVE-\d{4}-\d+$/i,                                         type: 'CVE',    icon: '🛡️',  label: 'CVE Detected' },
  { pattern: /^(\d{1,3}\.){3}\d{1,3}$/,                                  type: 'IP',     icon: '📡',  label: 'IP Address Detected' },
  { pattern: /^https?:\/\//i,                                             type: 'URL',    icon: '🔗',  label: 'URL Detected' },
  { pattern: /^(From:|Received:|MIME-Version:|Return-Path:)/im,           type: 'Email',  icon: '📧',  label: 'Email Text Detected' },
  { pattern: /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/, type: 'Domain', icon: '🌐', label: 'Domain Detected' },
];

function detectType(value) {
  const trimmed = value.trim();
  if (!trimmed) return null;
  for (const rule of TYPE_RULES) {
    if (rule.pattern.test(trimmed)) return rule;
  }
  return { type: 'Unknown', icon: '?', label: 'Unknown type' };
}

targetInput.addEventListener('input', () => {
  const val = targetInput.value.trim();
  if (!val) {
    typeDetector.classList.add('hidden');
    return;
  }
  const detected = detectType(val);
  if (detected) {
    typeIcon.textContent  = detected.icon;
    typeLabel.textContent = detected.label;
    typeDetector.classList.remove('hidden');
  } else {
    typeDetector.classList.add('hidden');
  }
});

// ─── Quick example buttons ───────────────────────────────────────────────────
document.querySelectorAll('.quick-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    targetInput.value = btn.dataset.target;
    targetInput.dispatchEvent(new Event('input'));
    targetInput.focus();
  });
});

// ─── Status helpers ──────────────────────────────────────────────────────────
function setStatus(state, label) {
  statusDot.className = 'status-dot' + (state ? ' ' + state : '');
  statusText.textContent = label;
}

// ─── Feed helpers ────────────────────────────────────────────────────────────
function ts() {
  return new Date().toISOString().slice(11, 19);
}

function appendFeed(text, cssClass = '') {
  const line = document.createElement('div');
  line.className = 'feed-line' + (cssClass ? ' ' + cssClass : '');
  line.innerHTML = `<span class="feed-ts">${ts()}</span>${escapeHtml(text)}`;
  progressFeed.appendChild(line);
  progressFeed.scrollTop = progressFeed.scrollHeight;
}

function appendFeedRaw(html, cssClass = '') {
  const line = document.createElement('div');
  line.className = 'feed-line' + (cssClass ? ' ' + cssClass : '');
  line.innerHTML = `<span class="feed-ts">${ts()}</span>${html}`;
  progressFeed.appendChild(line);
  progressFeed.scrollTop = progressFeed.scrollHeight;
}

function clearFeed() {
  progressFeed.innerHTML = `
    <div class="feed-line boot">
      <span class="feed-prompt">CYBERSENTINEL v1.0</span> — Autonomous Threat Intelligence Agent
    </div>`;
}

function appendCursor() {
  const cursor = document.createElement('span');
  cursor.className = 'cursor-blink';
  cursor.id = 'feedCursor';
  progressFeed.appendChild(cursor);
  progressFeed.scrollTop = progressFeed.scrollHeight;
}

function removeCursor() {
  const c = document.getElementById('feedCursor');
  if (c) c.remove();
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─── Main investigation flow ─────────────────────────────────────────────────
investigateBtn.addEventListener('click', startInvestigation);
stopBtn.addEventListener('click', stopInvestigation);
targetInput.addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') startInvestigation();
});

async function startInvestigation() {
  const target = targetInput.value.trim();
  if (!target) {
    targetInput.focus();
    targetInput.style.borderColor = 'var(--danger)';
    setTimeout(() => { targetInput.style.borderColor = ''; }, 1500);
    return;
  }
  if (investigationActive) return;

  investigationActive = true;
  investigateBtn.disabled = true;
  stopBtn.classList.remove('hidden');
  setStatus('busy', 'INVESTIGATING');

  // Show progress panel, hide old report
  progressPanel.classList.remove('hidden');
  reportPanel.classList.add('hidden');
  reportPanel.innerHTML = '';
  clearFeed();
  appendFeed(`▶ Target: ${target}`, 'boot');
  appendCursor();

  // Step 1: POST to start the investigation
  let invId;
  try {
    const resp = await fetch('/api/investigate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target })
    });
    const data = await resp.json();
    if (!resp.ok || data.error) {
      throw new Error(data.error || 'Server error');
    }
    invId = data.id;
  } catch (err) {
    removeCursor();
    appendFeed(`✗ Failed to start: ${err.message}`, 'err');
    resetUI();
    return;
  }

  appendFeed(`◉ Investigation ID: ${invId}`, 'tool');

  // Step 2: SSE stream
  try {
    await streamInvestigation(invId, target);
  } catch (err) {
    removeCursor();
    appendFeed(`✗ Stream error: ${err.message}`, 'err');
    resetUI();
  }
}

function streamInvestigation(invId, target) {
  return new Promise((resolve, reject) => {
    const es = new EventSource(`/api/stream/${invId}`);
    currentEventSource = es;

    es.onmessage = (event) => {
      let msg;
      try { msg = JSON.parse(event.data); }
      catch { return; }

      handleStreamEvent(msg, target, resolve, reject, es);
    };

    es.onerror = () => {
      es.close();
      reject(new Error('Connection lost'));
    };
  });
}

function handleStreamEvent(msg, target, resolve, reject, es) {
  const { type, data } = msg;

  if (type === 'heartbeat') return;

  if (type === 'progress') {
    const ev = data;
    if (ev.type === 'start') {
      appendFeed(`◉ ${ev.message}`, 'tool');
    } else if (ev.type === 'thinking') {
      appendFeed(`🧠 ${ev.message}`, 'think');
    } else if (ev.type === 'tool_start') {
      appendFeed(ev.message, 'tool');
    } else if (ev.type === 'tool_end') {
      appendFeedRaw(
        `✓ <span style="color:var(--accent)">Done</span> — ${escapeHtml(ev.result_snippet || '')}`,
        'result'
      );
    } else if (ev.type === 'complete') {
      appendFeed(ev.message, 'done');
    }
    return;
  }

  if (type === 'done') {
    removeCursor();
    es.close();
    appendFeed('◼ Investigation complete. Rendering report...', 'done');
    renderReport(data.report, data.steps);
    loadHistory();
    resetUI();
    resolve();
    return;
  }

  if (type === 'error') {
    removeCursor();
    es.close();
    appendFeed(`✗ Agent error: ${data.message}`, 'err');
    resetUI();
    reject(new Error(data.message));
    return;
  }
}

function stopInvestigation() {
  if (currentEventSource) {
    currentEventSource.close();
    currentEventSource = null;
  }
  removeCursor();
  appendFeed('◼ Investigation stopped by user.', 'err');
  resetUI();
}

function resetUI() {
  investigationActive = false;
  investigateBtn.disabled = false;
  stopBtn.classList.add('hidden');
  setStatus('', 'READY');
}

// ─── Report rendering ─────────────────────────────────────────────────────────
function renderReport(report, steps) {
  const { threat_level, threat_colors, executive_summary, target, target_type,
          findings, risk_indicators, recommended_actions,
          confidence_level, confidence_note, generated_at } = report;

  const orbStyle = `background:${threat_colors.bg};color:${threat_colors.text};--orb-glow:${threat_colors.glow}`;
  const borderColor = threat_colors.bg;
  const genTime = new Date(generated_at).toLocaleString();
  const stepCount = steps ? steps.length : 0;

  const findingsList = (findings || []).map(f =>
    `<div class="finding-item"><span class="finding-bullet">▸</span><span>${escapeHtml(f)}</span></div>`
  ).join('') || '<div class="finding-item"><span class="finding-bullet">▸</span><span>No specific findings recorded.</span></div>';

  const riskList = (risk_indicators || []).map(r =>
    `<div class="risk-item"><span class="risk-bullet">⚠</span><span>${escapeHtml(r)}</span></div>`
  ).join('') || '<div class="risk-item"><span class="risk-bullet">✓</span><span>No significant risk indicators found.</span></div>';

  const actionList = (recommended_actions || []).map(a =>
    `<div class="action-item"><span class="action-bullet">→</span><span>${escapeHtml(a)}</span></div>`
  ).join('') || '<div class="action-item"><span class="action-bullet">→</span><span>No specific actions required.</span></div>';

  // Steps timeline
  const stepsHtml = steps && steps.length > 0
    ? steps.map((s, i) => `
        <div class="step-item">
          <div class="step-num">${String(i + 1).padStart(2, '0')}</div>
          <div>
            <div class="step-tool">${escapeHtml(s.tool)}</div>
            <div class="step-result">${escapeHtml(s.result_snippet || '')}</div>
          </div>
        </div>`).join('')
    : '<div style="color:var(--text-dim);font-size:.8rem">No steps recorded.</div>';

  reportPanel.innerHTML = `
    <div class="report-header-card">
      <div class="threat-level-display">
        <div class="threat-orb" style="${orbStyle}">${threat_level}</div>
        <div class="threat-info">
          <h2>Threat Level: ${threat_level}</h2>
          <div class="target-label">
            <span style="color:var(--accent2)">${escapeHtml(target_type)}</span>
            &nbsp;—&nbsp;
            <span style="color:var(--text-bright)">${escapeHtml(target)}</span>
          </div>
        </div>
      </div>
      <div class="report-meta">
        Generated: ${genTime}<br>
        Tools used: ${stepCount}<br>
        Confidence: <span style="color:var(--accent)">${confidence_level}</span>
      </div>
    </div>

    <div class="report-summary-card" style="border-top-color:${borderColor}">
      <div class="panel-title" style="margin-bottom:8px">◈ EXECUTIVE SUMMARY</div>
      <div class="summary-text">${escapeHtml(executive_summary)}</div>
    </div>

    <div class="report-sections">
      <div class="report-section">
        <div class="section-header">
          <span class="section-icon">📋</span>
          <span class="section-title">FINDINGS</span>
        </div>
        <div class="section-body">${findingsList}</div>
      </div>

      <div class="report-section" style="border-right:1px solid var(--border)">
        <div class="section-header">
          <span class="section-icon">⚠️</span>
          <span class="section-title">RISK INDICATORS</span>
        </div>
        <div class="section-body">${riskList}</div>
      </div>

      <div class="report-section" style="grid-column:1/-1;border-right:1px solid var(--border)">
        <div class="section-header">
          <span class="section-icon">🛡️</span>
          <span class="section-title">RECOMMENDED ACTIONS</span>
        </div>
        <div class="section-body">${actionList}</div>
      </div>
    </div>

    <div class="confidence-card">
      <span class="conf-label">CONFIDENCE:</span>
      <span class="conf-value">${confidence_level}</span>
      ${confidence_note ? `<span class="conf-note">— ${escapeHtml(confidence_note)}</span>` : ''}
    </div>

    <div class="steps-card">
      <button class="steps-toggle" onclick="toggleSteps(this)">
        ▶ INVESTIGATION TIMELINE (${stepCount} steps — click to expand)
      </button>
      <div class="steps-body" id="stepsBody">${stepsHtml}</div>
    </div>
  `;

  reportPanel.classList.remove('hidden');
  reportPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function toggleSteps(btn) {
  const body = document.getElementById('stepsBody');
  body.classList.toggle('open');
  btn.textContent = body.classList.contains('open')
    ? '▼ INVESTIGATION TIMELINE (click to collapse)'
    : `▶ INVESTIGATION TIMELINE (${body.querySelectorAll('.step-item').length} steps — click to expand)`;
}

// ─── History ─────────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const resp = await fetch('/api/history');
    const data = await resp.json();
    renderHistory(data.history || []);
  } catch { /* silently ignore */ }
}

function renderHistory(history) {
  if (!history.length) {
    historyList.innerHTML = '<div class="history-empty">No investigations yet</div>';
    return;
  }

  const COLORS = {
    CRITICAL: '#ff0033', HIGH: '#ff6600', MEDIUM: '#ffaa00',
    LOW: '#00cc44', INFORMATIONAL: '#0088ff', UNKNOWN: '#666'
  };

  historyList.innerHTML = history.map(h => {
    const color = COLORS[h.threat_level] || COLORS.UNKNOWN;
    const time = new Date(h.timestamp).toLocaleTimeString();
    return `
      <div class="history-item" onclick="loadHistoryEntry('${h.id}')">
        <div class="history-target">${escapeHtml(h.target)}</div>
        <div class="history-meta">
          <span class="history-time">${time}</span>
          <span class="threat-badge" style="background:${color}20;color:${color};border:1px solid ${color}40">
            ${h.threat_level}
          </span>
        </div>
      </div>`;
  }).join('');
}

function loadHistoryEntry(id) {
  // Just scroll to top to prompt re-investigation — history is lightweight entries
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

clearHistoryBtn.addEventListener('click', async () => {
  if (!confirm('Clear all investigation history?')) return;
  await fetch('/api/history', { method: 'DELETE' });
  loadHistory();
});

// ─── Init ─────────────────────────────────────────────────────────────────────
loadHistory();
targetInput.focus();
