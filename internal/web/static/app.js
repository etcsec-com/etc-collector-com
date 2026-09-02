/* ETC Collector — Standalone web GUI
 *
 * Single-file ESM module loaded by index.html. Exposes window.app() — the
 * Alpine.js data factory — and the rendering helpers for the audit view.
 *
 * Visual parity with the SaaS frontend (services/frontend/src/app/[locale]/
 * (dashboard)/audit/view + (public)/trial/TrialWizardClient). No build step,
 * no external assets beyond Alpine + Chart.js + Tailwind via CDN.
 *
 * Structure:
 *   1. Helpers (escape, format, score thresholds, severity palette)
 *   2. API client (fetch wrapper, GUI/API token handling)
 *   3. Compliance framework metadata
 *   4. Audit-view renderers (Executive / Findings / Infra / ANSSI / Frameworks)
 *   5. Score reveal (final wizard step)
 *   6. Alpine factory window.app()
 */

// ===========================================================================
// 1. HELPERS
// ===========================================================================

const $ = (sel, root = document) => root.querySelector(sel);

const fmt = (n) => (n == null ? '—' : Number(n).toLocaleString('en-US'));

const formatBytes = (n) => {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
};

const formatDate = (s) => {
  if (!s) return '—';
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString();
};

// Format a raw Go duration string (e.g. "1.2880605s", "84s", "1m30s", "500ms")
// to one decimal place in the largest sensible unit (→ "1.3s", "84.0s", "1.5m").
const formatDuration = (s) => {
  if (s == null || s === '' || s === '—') return '—';
  const str = String(s).trim();
  const m = str.match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h)?$/i); // simple single-unit case
  if (m) {
    const n = parseFloat(m[1]);
    const unit = (m[2] || 's').toLowerCase();
    return `${n.toFixed(1)}${unit}`;
  }
  return str; // compound (1m30s) or unknown — leave as-is rather than mangle
};

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

// ── Score thresholds (mirror ScoreHero.tsx) ────────────────────────────────

// Colours mirror the Etcsec Component Library reference (T_011).
function scoreColor(s) {
  if (s >= 90) return '#58cb43';
  if (s >= 70) return '#2f8f22';
  if (s >= 50) return '#eab308';
  if (s >= 30) return '#f2801f';
  return '#e5484d';
}
function scoreBg(s) {
  if (s >= 70) return '#ecfae8';
  if (s >= 50) return '#fbf3d6';
  if (s >= 30) return '#fdf0e3';
  return '#fdecec';
}
function scoreGrade(s) {
  if (s >= 85) return 'A';
  if (s >= 70) return 'B';
  if (s >= 50) return 'C';
  if (s >= 25) return 'D';
  return 'F';
}
function scoreRating(s) {
  if (s >= 90) return 'EXCELLENT';
  if (s >= 70) return 'GOOD';
  if (s >= 50) return 'FAIR';
  if (s >= 30) return 'POOR';
  return 'CRITICAL';
}

// ── Severity ordering & palette ────────────────────────────────────────────

// The palette resolves through the `--sev-*` aliases app.css declares for
// exactly this purpose ("JS-renderer aliases"), so app.css :root stays the one
// source of truth for the severity ramp — no hex duplicated in JS. These values
// land in inline `style` attributes (DOM), where var() resolves natively; for
// <canvas> (Chart.js) use cssToken() below, which reads the computed value.
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_PALETTE = {
  critical: 'var(--sev-critical)',
  high:     'var(--sev-high)',
  medium:   'var(--sev-medium)',
  low:      'var(--sev-low)',
  info:     'var(--sev-info)',
};

// ── Design tokens for canvas contexts ──────────────────────────────────────

// Chart.js paints to a <canvas>, which cannot resolve CSS custom properties.
// Read the token off :root at render time rather than hardcoding a second copy
// of the value here (the mistake the fidelity pass exists to avoid).
function cssToken(name, fallback = '') {
  try {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  } catch {
    return fallback;
  }
}

// #rrggbb → rgba(r,g,b,a) — lets a tinted fill derive from its token instead of
// carrying an independent literal.
function hexToRgba(hex, alpha) {
  const m = /^#?([0-9a-f]{6})$/i.exec((hex || '').trim());
  if (!m) return hex;
  const n = parseInt(m[1], 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha})`;
}

function severityRank(s) {
  const i = SEV_ORDER.indexOf((s || '').toLowerCase());
  return i < 0 ? 99 : i;
}

// ===========================================================================
// 2. API CLIENT
// ===========================================================================

const API = (() => {
  const guiHeader = () => {
    const t = localStorage.getItem('etc-gui-token') || '';
    return t ? { 'X-GUI-Token': t } : {};
  };
  const apiHeader = () => {
    const t = localStorage.getItem('etc-api-token') || '';
    return t ? { Authorization: 'Bearer ' + t } : {};
  };
  const json = (extra) => ({ 'Content-Type': 'application/json', ...extra });

  async function fetchJSON(url, opts = {}) {
    const headers = { ...json(), ...guiHeader(), ...apiHeader(), ...(opts.headers || {}) };
    const r = await fetch(url, { ...opts, headers });
    if (r.status === 401) {
      // Check error type — gui_token errors mean user must re-login.
      let payload = {};
      try { payload = await r.clone().json(); } catch {}
      if (payload.error === 'gui_token_required' || payload.error === 'gui_token_invalid') {
        localStorage.removeItem('etc-gui-token');
        localStorage.removeItem('etc-api-token');
        window.location.reload();
        return null;
      }
      // API token expired — drop it; caller can re-issue.
      localStorage.removeItem('etc-api-token');
    }
    if (!r.ok) {
      const msg = await r.text().catch(() => r.statusText);
      throw new Error(msg || `HTTP ${r.status}`);
    }
    if (r.status === 204) return null;
    return r.json();
  }

  return {
    fetchJSON,
    raw: (url, opts = {}) => {
      const headers = { ...guiHeader(), ...apiHeader(), ...(opts.headers || {}) };
      return fetch(url, { ...opts, headers });
    },

    health: () => fetch('/health').then((r) => (r.ok ? r.json() : { status: 'error' })),
    verifyGuiToken: async (token) => {
      try {
        const r = await fetch('/api/v1/auth/gui-token/verify', {
          method: 'POST',
          headers: json(),
          body: JSON.stringify({ token: token || 'check' }),
        });
        if (!r.ok) return false;
        const d = await r.json();
        if (d.required === false) return 'not_required';
        return d.valid === true;
      } catch { return false; }
    },
    issueAPIToken: async ({ service = 'web-gui', duration = '720h', maxUses = 0 } = {}) => {
      const r = await fetch('/api/v1/auth/token', {
        method: 'POST',
        headers: { ...json(), ...guiHeader() },
        body: JSON.stringify({ service, duration, maxUses }),
      });
      if (!r.ok) throw new Error('token issue failed');
      return r.json();
    },
    getConfig: () => fetch('/api/v1/admin/config', { headers: guiHeader() }).then((r) => (r.ok ? r.json() : {})),
    getCapabilities: () => fetchJSON('/api/v1/info/capabilities').catch(() => ({})),
    getJobs: () => fetchJSON('/api/v1/audit/jobs').catch(() => ({ jobs: [] })),
    getJob: (id) => fetchJSON(`/api/v1/audit/jobs/${encodeURIComponent(id)}`),
    startAdAudit: () => fetchJSON('/api/v1/audit/ad?async=true', { method: 'POST' }),

    testLDAP: (cfg) => fetch('/api/v1/admin/config/ldap/test', {
      method: 'POST',
      headers: { ...json(), ...guiHeader() },
      body: JSON.stringify(cfg),
    }).then((r) => r.json()),
    saveLDAP: (cfg) => fetch('/api/v1/admin/config/ldap', {
      method: 'PUT',
      headers: { ...json(), ...guiHeader() },
      body: JSON.stringify(cfg),
    }).then(async (r) => ({ ok: r.ok, body: await r.json() })),
    deleteLDAP: () => fetch('/api/v1/admin/config/ldap', { method: 'DELETE', headers: guiHeader() }),

    importPingCastle: async (xmlBlob) => {
      const r = await fetch('/api/v1/audit/import-pingcastle', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/xml',
          ...guiHeader(),
          ...apiHeader(),
        },
        body: xmlBlob,
      });
      if (!r.ok) {
        const msg = await r.text().catch(() => r.statusText);
        throw new Error(msg || `HTTP ${r.status}`);
      }
      return r.json();
    },

    enrichPingCastleHtml: async (auditId, htmlBlob) => {
      const r = await fetch(
        `/api/v1/audit/import-pingcastle/${encodeURIComponent(auditId)}/enrich-html`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'text/html',
            ...guiHeader(),
            ...apiHeader(),
          },
          body: htmlBlob,
        },
      );
      if (!r.ok) {
        const msg = await r.text().catch(() => r.statusText);
        throw new Error(msg || `HTTP ${r.status}`);
      }
      return r.json();
    },
  };
})();

// ===========================================================================
// 3. COMPLIANCE FRAMEWORKS METADATA
// ===========================================================================

const FRAMEWORK_LABELS = {
  ANSSI_PA099:         { short: 'ANSSI PA-099', abbr: 'ANSSI PA', long: 'ANSSI-PA-099 v1.0 — Active Directory Security',     description: 'ANSSI 2023 recommendations for secure AD administration. 5 maturity axes.' },
  ANSSI_BP039:         { short: 'ANSSI BP-039', abbr: 'ANSSI BP', long: 'ANSSI-BP-039 — Windows hardening',                  description: 'LSA Protection, Credential Guard, BitLocker (3 Windows controls).' },
  ANSSI_GUIDE_HYGIENE: { short: 'ANSSI Hygiène', abbr: 'Hygiène', long: 'ANSSI Guide d\'hygiène informatique',               description: 'ANSSI 42 essential measures for IT security.' },
  NIS2_FR:             { short: 'NIS2 (FR)', abbr: 'NIS2', long: 'NIS2 — French transposition',                       description: 'EU Directive 2022/2555. Articles 21(2)(a/b/c/e/h/i/j).' },
  HDS_v1_1:            { short: 'HDS v1.1', abbr: 'HDS', long: 'HDS v1.1 — Health',                                  description: 'French Health Data Hosting reference v1.1.' },
  RGPD:                { short: 'GDPR', abbr: 'RGPD', long: 'RGPD — Data protection',                             description: 'EU 2016/679 data protection regulation.' },
  CIS_v8:              { short: 'CIS v8', abbr: 'CIS', long: 'CIS Controls v8.1',                                  description: 'Center for Internet Security — 18 control families.' },
  NIST_800_53:         { short: 'NIST 800-53', abbr: 'NIST', long: 'NIST SP 800-53 Rev.5',                               description: 'Security controls for US federal information systems.' },
  DISA_STIG:           { short: 'DISA STIG', abbr: 'DISA', long: 'DISA STIG AD Domain V3R3',                           description: 'Security Technical Implementation Guide — AD domain.' },
};

// Country/region flag per framework (reference "Compliance readiness card").
const FRAMEWORK_FLAGS = {
  ANSSI_PA099: '🇫🇷', ANSSI_BP039: '🇫🇷', ANSSI_GUIDE_HYGIENE: '🇫🇷', HDS_v1_1: '🇫🇷',
  NIS2_FR: '🇪🇺', RGPD: '🇪🇺', CIS_v8: '🌐', NIST_800_53: '🇺🇸', DISA_STIG: '🇺🇸',
};
const SHIELD_SVG = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" stroke-width="2" style="flex-shrink:0"><path stroke-linecap="round" stroke-linejoin="round" d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/></svg>';

// Framework score → bar colour (reference vertical-bars: green high / amber mid
// / red low). Thresholds match the reference sample (70 green, 45-48 amber, <40 red).
function frameworkBarColor(s) {
  if (s >= 60) return '#2f8f22';   // green (--green-ink)
  if (s >= 40) return '#d9a406';   // amber
  return '#e5484d';                // red (--critical)
}

const ANSSI_FRAMEWORKS         = ['ANSSI_PA099', 'ANSSI_BP039', 'ANSSI_GUIDE_HYGIENE'];
const REGULATORY_FRAMEWORKS    = ['NIS2_FR', 'HDS_v1_1', 'RGPD'];
const INTERNATIONAL_FRAMEWORKS = ['CIS_v8', 'NIST_800_53', 'DISA_STIG'];
const ALL_FRAMEWORKS_ORDER     = [...ANSSI_FRAMEWORKS, ...REGULATORY_FRAMEWORKS, ...INTERNATIONAL_FRAMEWORKS];

function frameworkLabel(id) {
  return FRAMEWORK_LABELS[id] ?? { short: id, long: id, description: '' };
}

// ===========================================================================
// 4. AUDIT-VIEW RENDERERS — return HTML strings, attach charts after mount
// ===========================================================================
//
// Each renderXxx() function:
//   - returns the HTML string to inject into the tab pane host
//   - registers any Chart.js instances or interactivity in setupXxx() called
//     after innerHTML mount (we walk [data-chart-spec] elements in attachCharts)
//
// We track Chart.js instances on a global registry so tab switches can
// destroy them cleanly to free WebGL contexts.
const chartRegistry = new Map();
function destroyAllCharts() {
  chartRegistry.forEach((ch) => { try { ch.destroy(); } catch {} });
  chartRegistry.clear();
}
// Chart.js global theme — the reference handoff rules applied to every canvas
// chart at once (typography, hairline structure, mono for data, square
// tooltips). Restyling happens through Chart.js options only: same library,
// same CDN script, no build step. Runs once, on the first attach, so :root is
// guaranteed parsed by then.
let chartThemeApplied = false;
function applyChartTheme() {
  if (chartThemeApplied || !window.Chart) return;
  chartThemeApplied = true;
  const D = window.Chart.defaults;
  const panel = cssToken('--panel', '#ffffff');
  // Body copy = Geist; secondary text = --muted; structure = --line hairline.
  D.font.family = "'Geist', system-ui, -apple-system, sans-serif";
  D.font.size = 11;
  D.color = cssToken('--muted', '#5b6572');
  D.borderColor = cssToken('--line', '#e6e8ec');
  // Reference charts carry no legend — the card header names the series.
  D.plugins.legend.display = false;
  // Tooltip: square (radius 0), ink panel, Geist label over a Geist Mono value.
  Object.assign(D.plugins.tooltip, {
    backgroundColor: cssToken('--ink', '#0d0f13'),
    cornerRadius: 0,
    padding: 9,
    displayColors: false,
    titleColor: panel,
    bodyColor: panel,
    titleFont: { family: "'Geist', system-ui, sans-serif", size: 11, weight: '600' },
    bodyFont: { family: "'Geist Mono', 'SF Mono', Menlo, monospace", size: 11 },
  });
}

function attachCharts(root) {
  if (!window.Chart) return;
  applyChartTheme();
  root.querySelectorAll('canvas[data-chart-spec]').forEach((canvas) => {
    let spec;
    try { spec = JSON.parse(canvas.dataset.chartSpec); } catch { return; }
    const ctx = canvas.getContext('2d');
    const ch = new Chart(ctx, spec);
    chartRegistry.set(canvas.id || canvas.dataset.chartId, ch);
  });
}

// ── Severity helpers ───────────────────────────────────────────────────────

function severityCounts(audit) {
  const r = audit?.summary?.risk?.findings || {};
  return {
    critical: r.critical || 0,
    high:     r.high     || 0,
    medium:   r.medium   || 0,
    low:      r.low      || 0,
  };
}

// ── Score hero (mirror ScoreHero.tsx — SVG arc 270°) ───────────────────────

function renderScoreHero(audit) {
  const score = clamp(audit?.summary?.risk?.score ?? 0, 0, 100);
  const counts = severityCounts(audit);
  const totalCount = counts.critical + counts.high + counts.medium + counts.low;

  const col = scoreColor(score);
  const bg = scoreBg(score);
  const grade = scoreGrade(score);
  const rating = scoreRating(score);

  // SVG gauge constants (mirror SaaS — 270° arc starting at 135°)
  const CX = 85, CY = 85, R = 64, SW = 13;
  const ARC_DEG = 270;
  const CIRC = 2 * Math.PI * R;
  const ARC_LEN = (CIRC * ARC_DEG) / 360;
  const offset = ARC_LEN * (1 - score / 100);

  const objects = audit?.summary?.objects || {};
  const stats = [];
  if (totalCount > 0) stats.push({ label: 'Findings', value: totalCount });
  if (objects.users)     stats.push({ label: 'Users',     value: objects.users });
  if (objects.computers) stats.push({ label: 'Computers', value: objects.computers });
  if (objects.groups)    stats.push({ label: 'Groups',    value: objects.groups });
  if (objects.ous)       stats.push({ label: 'OUs',       value: objects.ous });

  const gridCols = stats.length > 0 ? `grid-template-columns: repeat(${stats.length}, minmax(0,1fr));` : '';

  return `
    <div class="card p-5 flex flex-col">
      <div class="flex gap-5 flex-1 items-center">
        <div class="shrink-0">
          <svg viewBox="0 0 170 170" class="w-36 h-36">
            <defs>
              <filter id="glow-hero" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur in="SourceGraphic" stdDeviation="5" result="blur"/>
                <feComponentTransfer in="blur" result="glow"><feFuncA type="linear" slope="0.55"/></feComponentTransfer>
                <feMerge><feMergeNode in="glow"/><feMergeNode in="SourceGraphic"/></feMerge>
              </filter>
            </defs>
            <circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="#eef0f3" stroke-width="${SW}"
              stroke-dasharray="${ARC_LEN} ${CIRC}" stroke-linecap="round"
              transform="rotate(135 ${CX} ${CY})"/>
            <g filter="url(#glow-hero)">
              <circle class="score-arc" cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="${col}" stroke-width="${SW}"
                stroke-dasharray="${ARC_LEN} ${CIRC}" stroke-dashoffset="${offset}" stroke-linecap="round"
                transform="rotate(135 ${CX} ${CY})"/>
            </g>
            <text x="${CX}" y="${CY - 4}" text-anchor="middle" dominant-baseline="central"
              font-size="30" font-weight="700" fill="${col}"
              style="font-family:'Space Grotesk',ui-sans-serif,sans-serif;letter-spacing:-0.02em;font-variant-numeric:tabular-nums">${score.toFixed(1)}</text>
            <text x="${CX}" y="${CY + 22}" text-anchor="middle" font-size="10" fill="#8a93a1"
              style="font-family:'Geist Mono',ui-monospace,monospace">/ 100</text>
          </svg>
        </div>

        <div class="flex-1 flex flex-col justify-between min-w-0 self-stretch py-1">
          <div class="flex items-start justify-between">
            <div class="flex flex-col gap-1.5">
              <div class="flex items-center gap-2">
                <span class="inline-flex items-center justify-center w-10 h-10 text-xl font-display font-bold" style="background:${bg};color:${col}">${grade}</span>
                <span class="inline-block px-3 py-1 text-xs font-bold uppercase" style="background:${bg};color:${col};letter-spacing:.06em">${rating}</span>
              </div>
              ${totalCount > 0 ? `<div class="text-xs text-muted font-mono tabular-nums">${fmt(totalCount)} findings</div>` : ''}
            </div>
          </div>
          ${stats.length > 0 ? `
            <div class="my-2" style="border-top:1px solid var(--line)"></div>
            <div class="grid gap-2" style="${gridCols}">
              ${stats.map((c) => `
                <div class="text-center">
                  <div class="text-lg font-display font-bold text-ink tabular-nums leading-tight">${fmt(c.value)}</div>
                  <div class="text-[11px] text-muted mt-0.5">${escapeHtml(c.label)}</div>
                </div>
              `).join('')}
            </div>` : ''}
        </div>
      </div>
    </div>
  `;
}

// ── Severity breakdown horizontal bar ──────────────────────────────────────

// Reference "Horizontal bars" card — reproduced to the letter: square card
// (1px var(--line), flat), header (Space Grotesk 13.5px title + mono caption,
// hairline divider), body padding 16px 18px gap 13px; each row = label(var--ink)
// + mono count(var--muted) above (mb 6px), then a 7px SQUARE rail on --track
// with a coloured fill (no border-radius).
function horizontalBars(title, caption, rows) {
  return `
    <div style="border:1px solid var(--line);background:var(--panel);overflow:hidden">
      <div style="padding:11px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between">
        <span style="font-family:'Space Grotesk',sans-serif;font-weight:600;font-size:13.5px;color:var(--ink)">${escapeHtml(title)}</span>
        <span style="font-family:'Geist Mono',monospace;font-size:10px;color:var(--faint)">${escapeHtml(caption)}</span>
      </div>
      <div style="padding:16px 18px;display:flex;flex-direction:column;gap:13px">
        ${rows.length ? rows.map((r) => `
          <div>
            <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:6px;gap:12px">
              <span style="color:var(--ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${escapeHtml(r.label)}">${escapeHtml(r.label)}</span>
              <span style="font-family:'Geist Mono',monospace;color:var(--muted);flex-shrink:0">${fmt(r.count)}</span>
            </div>
            <div style="height:7px;background:var(--track);overflow:hidden">
              <div style="height:100%;width:${r.pct}%;background:${r.color}"></div>
            </div>
          </div>
        `).join('') : '<div style="font-size:12px;color:var(--faint);padding:8px 0">No data.</div>'}
      </div>
    </div>`;
}

function renderSeverityBreakdown(audit) {
  const c = severityCounts(audit);
  const max = Math.max(c.critical, c.high, c.medium, c.low, 1);
  const rows = SEV_ORDER.slice(0, 4).map((k) => ({
    label: k.charAt(0).toUpperCase() + k.slice(1),
    count: c[k],
    pct: (c[k] / max) * 100,
    color: SEV_PALETTE[k],
  }));
  return horizontalBars('Severity breakdown', 'findings / severity', rows);
}

// ── Top categories — derive from category_breakdown or audit sections ─────

function categoryBreakdown(audit) {
  // Preferred: an explicit summary breakdown if the API ever provides one.
  const cb = audit?.summary?.categoryBreakdown || audit?.audit_ad_details?.category_breakdown;
  if (cb && Object.keys(cb).length) {
    return Object.entries(cb).map(([key, v]) => ({
      name: key,
      findings: v?.findings ?? v?.findingCount ?? 0,
      score: v?.score ?? null,
    })).filter((c) => c.findings > 0 || c.score != null).sort((a, b) => b.findings - a.findings);
  }
  // Real audits don't carry that — derive the breakdown from the actual audit
  // sections (each holds nested findings[] arrays). Count findings per section.
  const a = audit?.audit || audit;
  const SECTIONS = [
    ['Accounts', 'accounts'], ['Computers', 'computers'], ['Groups', 'groups'],
    ['Security', 'security'], ['Permissions', 'permissions'], ['ADCS', 'adcs'],
    ['GPO security', 'gpoSecurity'], ['Trusts', 'trustsAnalysis'],
    ['Temporal', 'temporal'], ['Configuration', 'extendedConfig'],
    ['Org units', 'organizationalUnits'],
  ];
  const countFindings = (node) => {
    let n = 0;
    (function walk(o) {
      if (!o || typeof o !== 'object') return;
      if (Array.isArray(o.findings)) n += o.findings.length;
      for (const k in o) { if (k !== 'findings' && o[k] && typeof o[k] === 'object') walk(o[k]); }
    })(node);
    return n;
  };
  return SECTIONS
    .map(([name, key]) => ({ name, findings: countFindings(a?.[key]), score: null }))
    .filter((c) => c.findings > 0)
    .sort((a, b) => b.findings - a.findings);
}

function renderTopCategories(audit) {
  const cats = categoryBreakdown(audit);
  const max = Math.max(...cats.map((c) => c.findings), 1);
  const rows = cats.slice(0, 8).map((c) => ({
    label: c.name,
    count: c.findings,
    pct: (c.findings / max) * 100,
    color: 'var(--blue)', // brand blue — no severity semantic on categories
  }));
  return horizontalBars('Top categories', 'findings / category', rows);
}

// ── Category radar (Chart.js) ──────────────────────────────────────────────

// Reference "Radar · coverage by category" — reproduced through Chart.js
// options: square card (1px var(--line), flat) + the same header as
// horizontalBars (Space Grotesk 13.5px title, Geist Mono 10px axis-count
// caption, hairline divider), body padding 16px, plot centred. Inside the
// canvas: POLYGONAL rings and angle lines in var(--line-strong) at 1px, no
// numeric ticks, axis labels in Geist Mono 9px var(--muted), shape stroked
// var(--blue) 2px over an 18% tint of the same token, 2.6px blue vertex dots.
//
// DATA GAP (flagged, T_014): this renderer plots a per-category *score*, which
// only reaches the UI via summary.categoryBreakdown. Real audits don't carry
// it — the collector emits a single summary.risk.score plus per-framework
// compliance scores, so categoryBreakdown() derives findings counts and leaves
// score null, and this card renders nothing. Producing a per-category posture
// score is a scoring-engine change (public/internal/audit/**), outside the ui
// jurisdiction; the UI deliberately does NOT invent one here.
function renderCategoryRadar(audit) {
  const cats = categoryBreakdown(audit).filter((c) => c.score != null).slice(0, 8);
  if (cats.length < 3) {
    return ''; // skip if not enough datapoints
  }
  const labels = cats.map((c) => c.name);
  const data = cats.map((c) => c.score);
  const id = 'radar-' + Math.random().toString(36).slice(2, 8);
  const grid = cssToken('--line-strong', '#d3d7dd');
  const muted = cssToken('--muted', '#5b6572');
  const blue = cssToken('--blue', '#3165be');
  const spec = {
    type: 'radar',
    data: {
      labels,
      datasets: [{
        label: 'Score',
        data,
        backgroundColor: hexToRgba(blue, 0.18),
        borderColor: blue,
        borderWidth: 2,
        borderJoinStyle: 'round',
        pointBackgroundColor: blue,
        pointBorderColor: blue,
        pointBorderWidth: 0,
        pointRadius: 2.6,
        pointHoverRadius: 4.5,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          min: 0,
          max: 100,
          // stepSize 25 keeps the reference's four rings even with ticks hidden.
          grid:        { color: grid, lineWidth: 1, circular: false },
          angleLines:  { color: grid, lineWidth: 1 },
          ticks:       { display: false, stepSize: 25 },
          pointLabels: { color: muted, font: { family: "'Geist Mono', 'SF Mono', Menlo, monospace", size: 9 } },
        },
      },
      // Legend + tooltip come from applyChartTheme() — nothing chart-specific.
      plugins: { legend: { display: false } },
    },
  };
  return `
    <div style="border:1px solid var(--line);background:var(--panel);overflow:hidden">
      <div style="padding:11px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between">
        <span style="font-family:'Space Grotesk',sans-serif;font-weight:600;font-size:13.5px;color:var(--ink)">Category coverage</span>
        <span style="font-family:'Geist Mono',monospace;font-size:10px;color:var(--faint)">${labels.length} axes</span>
      </div>
      <div style="padding:16px;display:flex;justify-content:center">
        <div style="width:100%;max-width:560px;height:280px">
          <canvas id="${id}" data-chart-spec='${escapeHtml(JSON.stringify(spec))}'></canvas>
        </div>
      </div>
    </div>
  `;
}

// ── Audit info row (domain / forest / scan duration / connection) ──────────

function renderAuditInfo(audit) {
  const d = audit?.domainConfig || audit?.summary?.domainConfig || {};
  const m = audit?.metadata || audit?.summary?.metadata || {};
  const cell = (label, value, sub, mono) => `
    <div>
      <div class="s-label">${escapeHtml(label)}</div>
      <div class="text-sm font-bold text-ink truncate ${mono ? 'font-mono' : ''}" title="${escapeHtml(value)}">${escapeHtml(value)}</div>
      ${sub ? `<div class="text-[11px] text-muted-light truncate mt-0.5">${escapeHtml(sub)}</div>` : ''}
    </div>`;
  return `
    <div class="card p-0 overflow-hidden">
      <div class="stat-strip">
        ${cell('Domain', m?.domain?.name || '—', d?.domainInfo?.forestName || '', true)}
        ${cell('Functional level', `Server ${d?.domainInfo?.functionalLevel || '—'}`, `${d?.domainInfo?.domainControllers?.length || 0} domain controllers`, false)}
        ${cell('Scan duration', formatDuration(m?.execution?.duration), m?.execution?.timestamp ? formatDate(m.execution.timestamp) : '', true)}
        ${cell('Connection', m?.domain?.ldapUrl || '—', m?.domain?.baseDN || '', true)}
      </div>
    </div>
  `;
}

// ── Risk stat strip — headline severity counts as KPI tiles (not a chart) ──
function renderRiskStrip(audit) {
  const r = audit?.summary?.risk?.findings || {};
  const total = r.total ?? ((r.critical || 0) + (r.high || 0) + (r.medium || 0) + (r.low || 0));
  const instances = r.totalInstances;
  const tiles = [
    { label: 'Critical', value: r.critical || 0, color: SEV_PALETTE.critical },
    { label: 'High',     value: r.high || 0,     color: SEV_PALETTE.high },
    { label: 'Medium',   value: r.medium || 0,   color: SEV_PALETTE.medium },
    { label: 'Low',      value: r.low || 0,      color: SEV_PALETTE.low },
    { label: 'Findings', value: total,           color: '#1b2230' },
  ];
  if (instances != null) tiles.push({ label: 'Instances', value: instances, color: '#1b2230' });
  return `
    <div class="card p-0 overflow-hidden">
      <div class="stat-strip">
        ${tiles.map((t) => `
          <div>
            <div class="s-val" style="color:${t.color}">${fmt(t.value)}</div>
            <div class="s-label">${escapeHtml(t.label)}</div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

// ── Executive tab assembly ─────────────────────────────────────────────────

function renderExecutiveTab(audit) {
  // NOTE: renderSeverityBreakdown / renderTopCategories / renderCategoryRadar
  // are chart renderers owned by T_014 — only their card framing is touched
  // here, not their internals.
  return [
    renderScoreHero(audit),
    renderRiskStrip(audit),
    renderAuditInfo(audit),
    `<div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
      ${renderSeverityBreakdown(audit)}
      ${renderTopCategories(audit)}
    </div>`,
    renderCategoryRadar(audit),
  ].join('');
}

// ───────────────────────────────────────────────────────────────────────────
// FINDINGS TAB
// ───────────────────────────────────────────────────────────────────────────
//
// Source: audit.audit (the deep tree). We walk its sections and emit
// findings grouped by category. Severity chips toggle filter. Search
// filters by title/type substring.

function flattenFindings(audit) {
  const a = audit?.audit || audit;
  const sections = [
    { name: 'Accounts',       paths: ['accounts.status', 'accounts.privileged', 'accounts.dangerous', 'accounts.service'] },
    { name: 'Security',       paths: ['security.passwords', 'security.kerberos', 'security.advanced'] },
    { name: 'Infrastructure', paths: ['computers', 'groups', 'gpoSecurity', 'organizationalUnits'] },
    { name: 'Configuration',  paths: ['permissions', 'adcs', 'extendedConfig', 'trustsAnalysis'] },
  ];
  const all = [];
  for (const sec of sections) {
    for (const p of sec.paths) {
      const node = p.split('.').reduce((o, k) => (o ? o[k] : null), a);
      const findings = node?.findings;
      if (Array.isArray(findings)) {
        for (const f of findings) {
          all.push({
            section: sec.name,
            type: f.type || f.code || '',
            title: f.title || (f.type ? f.type.replace(/_/g, ' ') : '(unnamed)'),
            description: f.description || f.message || '',
            severity: (f.severity || 'medium').toLowerCase(),
            category: f.category || '',
            count: f.count ?? 0,
            compliance: Array.isArray(f.compliance) ? f.compliance : [],
            evidence: f.evidence ?? f.affectedObjects ?? f.affectedEntities ?? null,
          });
        }
      }
    }
  }
  return all;
}

function renderFindingsTab(audit) {
  const all = flattenFindings(audit);
  const counts = SEV_ORDER.reduce((acc, k) => ({ ...acc, [k]: all.filter((f) => f.severity === k).length }), {});
  const categories = [...new Set(all.map((f) => f.category).filter(Boolean))].sort();

  // Group by section
  const groups = {};
  for (const f of all) {
    if (!groups[f.section]) groups[f.section] = [];
    groups[f.section].push(f);
  }
  Object.values(groups).forEach((arr) => arr.sort((a, b) => severityRank(a.severity) - severityRank(b.severity)));

  const complianceTags = (f) => (f.compliance || [])
    .slice(0, 4)
    .map((c) => `<span class="tag">${escapeHtml(frameworkLabel(c.framework).short)}${c.control ? ` · ${escapeHtml(c.control)}` : ''}</span>`)
    .join('');

  const allMeta = all.map((f) => [f.severity, f.category, (f.title + ' ' + f.type + ' ' + f.category).toLowerCase()]);
  return `
    <div x-data="findingsTab(${JSON.stringify(allMeta).replace(/"/g, '&quot;')})" class="space-y-4">
      <!-- Filter bar: severity toggle chips + category select + search.
           Square controls (no rounded-* utility): index.html's tailwind.config
           collapses every radius to 0 anyway, so a rounded-* class here only
           states an intent the reference forbids. border-slate-200 IS the
           hairline — the config remaps the slate ramp onto --line #e6e8ec. -->
      <div class="card p-3 flex flex-wrap items-center gap-3">
        <div class="flex flex-wrap items-center gap-2">
          ${SEV_ORDER.slice(0, 4).map((k) => `
            <button type="button" @click="toggleSev('${k}')" :class="sev['${k}'] ? 'opacity-100 ring-2 ring-offset-1' : 'opacity-40'"
              class="chip-sev ${k}" style="--tw-ring-color:${SEV_PALETTE[k]}">
              ${k} <span class="ml-1 font-mono tabular-nums opacity-80">${counts[k]}</span>
            </button>
          `).join('')}
        </div>
        ${categories.length > 1 ? `
          <select x-model="cat" class="h-8 border border-slate-200 bg-white px-2 text-xs font-semibold text-muted focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none">
            <option value="">All categories</option>
            ${categories.map((c) => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('')}
          </select>` : ''}
        <div class="ml-auto flex items-center gap-2">
          <span class="text-[11px] text-muted-light font-mono tabular-nums" x-text="matchLabel()"></span>
          <input x-model="q" placeholder="Search findings…"
            class="h-8 w-48 border border-slate-200 px-3 text-sm focus:ring-2 focus:ring-primary/30 focus:border-primary outline-none" />
        </div>
      </div>

      ${Object.entries(groups).map(([section, items]) => `
        <div class="acc-section" x-data="{open: true}" x-show="sectionVisible(${JSON.stringify(items.map((f) => [f.severity, f.category, (f.title + ' ' + f.type + ' ' + f.category).toLowerCase()])).replace(/"/g, '&quot;')})">
          <button type="button" class="acc-header" @click="open = !open">
            <span class="flex items-center gap-2">
              <svg class="w-3 h-3 transition-transform" :class="open ? 'rotate-90' : ''" fill="none" viewBox="0 0 12 12" stroke="currentColor" stroke-width="2"><path d="M4 2l4 4-4 4"/></svg>
              <span>${escapeHtml(section)}</span>
            </span>
            <span class="text-xs font-bold font-mono tabular-nums text-muted">${items.length}</span>
          </button>
          <div x-show="open">
            ${items.map((f) => {
              const hay = (f.title + ' ' + f.type + ' ' + f.category).toLowerCase().replace(/'/g, '');
              const tags = complianceTags(f);
              return `
              <div x-data="{open: false}" x-show="passFilter('${escapeHtml(f.severity)}', '${escapeHtml(f.category)}', '${escapeHtml(hay)}')">
                <button type="button" class="acc-row w-full text-left" @click="open = !open">
                  <span class="chip-sev ${f.severity} shrink-0">${escapeHtml(f.severity)}</span>
                  <span class="title">${escapeHtml(f.title)}</span>
                  <span class="hidden lg:flex items-center gap-1 shrink-0">${tags}</span>
                  <span class="text-[11px] text-muted-light font-mono shrink-0 hidden md:inline">${escapeHtml(f.type)}</span>
                  <span class="count">${fmt(f.count)}</span>
                </button>
                <div x-show="open" class="acc-detail" x-collapse>
                  <div>${escapeHtml(f.description) || '<span class="italic text-muted-light">No description.</span>'}</div>
                  ${(f.category || tags) ? `<div class="meta">
                    ${f.category ? `<span class="tag">${escapeHtml(f.category)}</span>` : ''}
                    ${tags}
                  </div>` : ''}
                </div>
              </div>
            `;
            }).join('')}
          </div>
        </div>
      `).join('')}

      ${all.length === 0 ? `<div class="card"><div class="empty-state"><div class="empty-title">No findings reported</div><div>This audit returned a clean result for the scanned scope.</div></div></div>` : ''}
    </div>
  `;
}

// Alpine component for the findings filter bar (severity + category + search).
// `meta` is [[severity, category, searchHaystack], …] for every finding, so
// the bar can report a live match count and hide sections with zero matches.
window.findingsTab = function (meta) {
  return {
    meta: Array.isArray(meta) ? meta : [],
    total: Array.isArray(meta) ? meta.length : 0,
    sev: { critical: true, high: true, medium: true, low: true, info: true },
    cat: '',
    q: '',
    toggleSev(k) { this.sev[k] = !this.sev[k]; },
    passFilter(sev, cat, hay) {
      if (!this.sev[sev]) return false;
      if (this.cat && cat !== this.cat) return false;
      if (!this.q) return true;
      return hay.includes(this.q.toLowerCase());
    },
    sectionVisible(rows) {
      return rows.some((r) => this.passFilter(r[0], r[1], r[2]));
    },
    matchLabel() {
      const n = this.meta.filter((r) => this.passFilter(r[0], r[1], r[2])).length;
      return n === this.total ? `${this.total} findings` : `${n} / ${this.total}`;
    },
  };
};

// ───────────────────────────────────────────────────────────────────────────
// INFRASTRUCTURE TAB
// ───────────────────────────────────────────────────────────────────────────

function renderInfrastructureTab(audit) {
  const a = audit?.audit || audit;
  const d = audit?.domainConfig || a?.domainConfig || {};
  const pol = d?.passwordPolicy || {};
  const krb = d?.kerberosPolicy || {};
  const dom = d?.domainInfo || {};
  const trusts = d?.trusts || [];
  const dcs = dom.domainControllers || [];

  const objects = audit?.summary?.objects || {};

  return `
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">
      <div class="card p-5">
        <h3 class="section-title mb-3">Password policy</h3>
        <dl>
          ${infraRow('Min length', pol.minLength != null ? `${pol.minLength} chars` : '—', (pol.minLength || 0) < 12 ? 'critical' : 'ok')}
          ${infraRow('Max age', pol.maxAge != null ? `${pol.maxAge} days` : '—')}
          ${infraRow('History', pol.historyCount != null ? `${pol.historyCount} remembered` : '—')}
          ${infraRow('Lockout', (pol.lockoutThreshold || 0) === 0 ? 'Disabled' : `${pol.lockoutThreshold} / ${pol.lockoutDuration ?? '—'}min`, (pol.lockoutThreshold || 0) === 0 ? 'critical' : 'ok')}
          ${infraRow('Complexity', pol.complexityEnabled ? 'Required' : 'Disabled', pol.complexityEnabled ? 'ok' : 'critical')}
        </dl>
      </div>

      <div class="card p-5">
        <h3 class="section-title mb-3">Kerberos &amp; security</h3>
        <dl>
          ${infraRow('TGT lifetime', krb.maxTicketAge != null ? `${krb.maxTicketAge}h` : '—')}
          ${infraRow('Max renew', krb.maxRenewAge != null ? `${krb.maxRenewAge}h` : '—')}
          ${infraRow('Machine quota', dom.machineAccountQuota != null ? `${dom.machineAccountQuota}` : '—', (dom.machineAccountQuota || 0) > 0 ? 'critical' : 'ok')}
          ${infraRow('Anonymous LDAP', dom.anonymousLdapAllowed ? 'Allowed' : 'Blocked', dom.anonymousLdapAllowed ? 'critical' : 'ok')}
          ${infraRow('Schema version', `v${dom.schemaVersion || '—'}`)}
        </dl>
      </div>

      <div class="card p-0 overflow-hidden lg:col-span-2">
        <h3 class="section-title px-5 pt-4 pb-2">Object inventory</h3>
        <div class="stat-strip">
          ${[
            ['Users', objects.users],
            ['Computers', objects.computers],
            ['Groups', objects.groups],
            ['OUs', objects.ous],
            ['Trusts', trusts.length],
            ['DCs', dcs.length],
          ].map(([l, v]) => `
            <div>
              <div class="s-val">${fmt(v || 0)}</div>
              <div class="s-label">${escapeHtml(l)}</div>
            </div>
          `).join('')}
        </div>
      </div>

      ${dcs.length > 0 ? `
      <div class="card p-0 overflow-hidden lg:col-span-2">
        <h3 class="section-title px-5 pt-4 pb-2">Domain controllers <span class="font-mono">(${dcs.length})</span></h3>
        <div class="overflow-x-auto">
          <table class="data-table">
            <thead>
              <tr><th>Name</th><th>OS</th><th>Site</th><th>Roles</th></tr>
            </thead>
            <tbody>
              ${dcs.map((dc) => `
                <tr>
                  <td class="mono">${escapeHtml(dc.name || dc.dnsHostName || '—')}</td>
                  <td>${escapeHtml(dc.operatingSystem || '—')}</td>
                  <td>${escapeHtml(dc.site || '—')}</td>
                  <td>${(dc.fsmoRoles || []).map((r) => `<span class="tag tag-mitre mr-1 mb-0.5">${escapeHtml(r)}</span>`).join('') || '—'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>` : ''}

      ${trusts.length > 0 ? `
      <div class="card p-0 overflow-hidden lg:col-span-2">
        <h3 class="section-title px-5 pt-4 pb-2">Trust relationships <span class="font-mono">(${trusts.length})</span></h3>
        <div class="overflow-x-auto">
          <table class="data-table">
            <thead>
              <tr><th>Target</th><th>Direction</th><th>Type</th><th>Transitive</th></tr>
            </thead>
            <tbody>
              ${trusts.map((t) => `
                <tr>
                  <td class="mono">${escapeHtml(t.targetName || t.target || '—')}</td>
                  <td>${escapeHtml(t.direction || '—')}</td>
                  <td>${escapeHtml(t.type || '—')}</td>
                  <td>${t.transitive ? '<span class="text-success font-semibold">yes</span>' : '<span class="text-muted-light">no</span>'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>` : ''}
    </div>
  `;
}

function infraRow(label, value, tone) {
  const cls = tone === 'critical' ? 'bad' : tone === 'ok' ? 'ok' : '';
  return `
    <div class="def-row">
      <dt>${escapeHtml(label)}</dt>
      <dd class="${cls}">${escapeHtml(value)}</dd>
    </div>
  `;
}

// ───────────────────────────────────────────────────────────────────────────
// COMPLIANCE — ANSSI + Frameworks
// ───────────────────────────────────────────────────────────────────────────

function complianceScores(audit) {
  return audit?.summary?.complianceScores || [];
}

// Compliance readiness card — reproduces the reference KPI card + progress-bar
// KPI vocabulary (no invented shield/layout): title + verdict micro-label, a
// Space Grotesk score, a square meter, a mono passed/failed/manual line, and a
// collapsible controls data-table. Hairlines are var(--line) throughout.
function frameworkScoreFields(score) {
  const passed = score.controlsPassed || score.passedControls || 0;
  const failed = score.controlsFailed || score.failedControls || 0;
  const manual = score.controlsManual || 0;
  const total = score.controlsTotal || score.totalControls || (passed + failed + manual);
  return { passed, failed, manual, total, pct: clamp(score.score || 0, 0, 100) };
}

// Optional drill-down: a collapsible row per framework that expands to its
// per-control data-table. Currently unrendered — see the note above
// renderComplianceTab.
function renderFrameworkDetail(score) {
  const meta = frameworkLabel(score.framework);
  const { passed, failed, manual, total, pct } = frameworkScoreFields(score);
  const col = frameworkBarColor(pct);
  const controls = score.evaluatedControls || score.controls || [];
  return `
    <div class="acc-section" x-data="{open: false}">
      <button type="button" class="acc-row w-full text-left" @click="open = !open">
        <span class="font-mono text-xs tabular-nums shrink-0 text-right" style="color:${col};width:30px">${Math.round(pct)}</span>
        <span class="title" title="${escapeHtml(meta.long)}">${escapeHtml(meta.short)}</span>
        <span class="text-[11px] text-muted-light font-mono tabular-nums shrink-0 hidden md:inline">${fmt(passed)} passed · ${fmt(failed)} failed · ${fmt(manual)} manual</span>
        <span class="count">${fmt(passed)}/${fmt(total)}</span>
      </button>
      ${controls.length > 0 ? `
        <div x-show="open" x-collapse>
          <div class="overflow-x-auto max-h-80">
            <table class="data-table">
              <thead><tr><th>Code</th><th>Control</th><th>Status</th></tr></thead>
              <tbody>
                ${controls.map((c) => {
                  const st = (c.status || 'unknown').toLowerCase();
                  const cls = st === 'passed' || st === 'pass' ? 'passed' : st === 'failed' || st === 'fail' ? 'failed' : st === 'manual' ? 'manual' : 'na';
                  return `
                    <tr>
                      <td class="mono whitespace-nowrap">${escapeHtml(c.code || '—')}</td>
                      <td class="text-xs">${escapeHtml(c.title || '')}</td>
                      <td><span class="chip-status ${cls}">${escapeHtml(c.status || 'n/a')}</span></td>
                    </tr>
                  `;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      ` : ''}
    </div>
  `;
}

// Reference "Compliance readiness card" (SEGMENTED PIPS) — reproduced to the
// letter: square card (padding 16px 18px), header = shield + flag + name
// (Space Grotesk 14px) + a bordered verdict micro-badge (✕/✓ + label, in the
// verdict colour at 30% border), a pip row (one pip per control, flex:1
// height:14px gap:2px, passed pips in the verdict colour, rest --track), and a
// footer = "N/M controls passing" (faint) + big % (Space Grotesk 18px).
function complianceReadinessCard(score) {
  const id = score.framework;
  const meta = FRAMEWORK_LABELS[id] || { short: id };
  const passed = score.controlsPassed ?? score.passedControls ?? 0;
  const failed = score.controlsFailed ?? score.failedControls ?? 0;
  const manual = score.controlsManual ?? 0;
  const total = (score.controlsTotal ?? score.totalControls ?? (passed + failed + manual)) || 1;
  const pct = Math.round(clamp(score.score ?? 0, 0, 100));
  const v = pct >= 80 ? { label: 'Compliant', color: '#2f8f22', mark: '✓' }
    : pct >= 50 ? { label: 'At risk', color: '#eab308', mark: '!' }
    : { label: 'Non-compliant', color: '#e5484d', mark: '✕' };
  const flag = FRAMEWORK_FLAGS[id] || '🌐';
  const pipTotal = Math.min(total, 42);
  const filled = Math.round((passed / total) * pipTotal);
  let pips = '';
  for (let i = 0; i < pipTotal; i++) {
    pips += `<span style="flex:1 1 0%;height:14px;min-width:2px;background:${i < filled ? v.color : 'var(--track)'}"></span>`;
  }
  return `
    <div style="border:1px solid var(--line);background:var(--panel);padding:16px 18px">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:12px">
        <div style="display:flex;align-items:center;gap:8px;min-width:0">
          ${SHIELD_SVG}
          <span style="font-size:10px">${flag}</span>
          <span style="font-family:'Space Grotesk',sans-serif;font-weight:600;font-size:14px;color:var(--ink);white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${escapeHtml(meta.long || meta.short)}">${escapeHtml(meta.short)}</span>
        </div>
        <span style="display:inline-flex;align-items:center;gap:4px;font-size:9px;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;color:${v.color};border:1px solid ${v.color}4d;padding:3px 7px;flex-shrink:0">${v.mark} ${v.label}</span>
      </div>
      <div style="display:flex;gap:2px;margin-bottom:10px;flex-wrap:nowrap;overflow:hidden">${pips}</div>
      <div style="display:flex;align-items:baseline;justify-content:space-between">
        <span style="font-size:9px;color:var(--faint)">${passed}/${total} controls passing</span>
        <span style="font-family:'Space Grotesk',sans-serif;font-weight:700;font-size:18px;color:var(--ink)">${pct}<span style="font-family:inherit;font-size:10px;color:var(--muted);font-weight:400"> %</span></span>
      </div>
    </div>`;
}

// T_029 note — the compliance tabs render ONLY complianceReadinessCard. The
// per-control drill-down (renderFrameworkDetail, with frameworkScoreFields /
// frameworkBarColor) has had no caller since T_016 replaced the bar chart with
// the pips cards. It is kept rather than deleted because it is the only
// per-control view of `evaluatedControls` — the pips card shows counts, not the
// control list — so removing it would drop a feature, not just dead code.
// Rewire it under the cards or drop it: lead's call, flagged in T_029.
function renderComplianceTab(audit, allowedFrameworks, emptyCopy) {
  const all = complianceScores(audit);
  const filtered = allowedFrameworks
    .map((id) => all.find((s) => s.framework === id))
    .filter(Boolean);

  if (filtered.length === 0) {
    return `<div class="card"><div class="empty-state"><div class="empty-title">No compliance data</div><div>${escapeHtml(emptyCopy)}</div></div></div>`;
  }

  // Reference vocabulary = the "Compliance readiness card" (segmented pips),
  // one per framework, in a responsive grid.
  return `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px">${filtered.map(complianceReadinessCard).join('')}</div>`;
}

function renderAnssiTab(audit) {
  return renderComplianceTab(
    audit,
    ANSSI_FRAMEWORKS,
    'No ANSSI compliance data — re-run an audit to populate PA-099, BP-039, and Hygiène scores.',
  );
}

function renderFrameworksTab(audit) {
  return renderComplianceTab(
    audit,
    [...REGULATORY_FRAMEWORKS, ...INTERNATIONAL_FRAMEWORKS],
    'No framework compliance data — re-run an audit to populate NIS2, HDS, GDPR, CIS, NIST, and DISA STIG scores.',
  );
}

// ===========================================================================
// 5. SCORE REVEAL — wizard `done` step
// ===========================================================================

function renderScoreReveal(host, finalScore, onView) {
  finalScore = clamp(finalScore, 0, 100);
  const grade = scoreGrade(finalScore);
  const rating = scoreRating(finalScore);
  const col = scoreColor(finalScore);
  const bg = scoreBg(finalScore);

  const R = 108;
  const CIRC = 2 * Math.PI * R;

  host.innerHTML = `
    <div class="relative">
      <svg width="260" height="260" viewBox="0 0 260 260">
        <defs>
          <linearGradient id="srGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="${col}"/>
            <stop offset="100%" stop-color="${col}" stop-opacity="0.5"/>
          </linearGradient>
          <filter id="srGlow">
            <feGaussianBlur stdDeviation="6" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>
        <circle cx="130" cy="130" r="${R}" stroke="rgba(148,163,184,0.2)" stroke-width="12" fill="none"/>
        <circle id="srArc" cx="130" cy="130" r="${R}"
          stroke="url(#srGrad)" stroke-width="12" fill="none" stroke-linecap="round" filter="url(#srGlow)"
          style="transform:rotate(-90deg);transform-origin:center;stroke-dasharray:0 ${CIRC};transition:stroke-dasharray 2.4s cubic-bezier(.25,.46,.45,.94)"/>
      </svg>
      <div class="absolute inset-0 flex flex-col items-center justify-center">
        <div id="srNum" class="font-display font-bold tabular-nums" style="color:${col};font-size:64px;line-height:1;letter-spacing:-0.02em">0.00</div>
        <div class="text-xs uppercase tracking-widest text-muted mt-1 font-mono">/ 100</div>
      </div>
    </div>
    <div class="flex items-center gap-3">
      <span class="h-10 w-10 grid place-items-center text-xl font-display font-bold text-white" style="background:${col}">${grade}</span>
      <div>
        <div class="text-lg font-bold">${rating} posture</div>
        <div class="text-xs text-muted">Across 340 Active Directory detectors</div>
      </div>
    </div>
    <button type="button" id="srViewBtn"
      class="inline-flex items-center gap-2 px-8 py-3 bg-gradient-to-r from-primary to-primary-dark text-white font-semibold hover:-translate-y-0.5 transition-all">
      View full findings
    </button>
    <p class="max-w-md text-center text-xs text-muted">
      Continuous monitoring, multi-site fleet management and NIS2 / GDPR / HDS compliance:
      <a href="https://etcsec.com/?utm_source=collector&utm_medium=score_reveal" target="_blank" rel="noopener" class="text-primary font-semibold hover:underline ml-1">etcsec.com →</a>
    </p>
  `;

  // Animate stroke + number
  const arc = $('#srArc', host);
  const num = $('#srNum', host);
  requestAnimationFrame(() => {
    if (arc) {
      const dash = CIRC * (finalScore / 100);
      arc.style.strokeDasharray = `${dash} ${CIRC - dash}`;
    }
  });
  const t0 = performance.now();
  const dur = 2400;
  const startVal = finalScore < 50 ? 100 : 0;
  function tick(t) {
    const p = Math.min(1, (t - t0) / dur);
    const ease = 1 - Math.pow(1 - p, 3);
    const v = startVal + (finalScore - startVal) * ease;
    if (num) num.textContent = v.toFixed(2);
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);

  $('#srViewBtn', host)?.addEventListener('click', onView);
}

// ===========================================================================
// 6. ALPINE FACTORY — window.app()
// ===========================================================================

window.app = function () {
  return {
    // ──── auth + bootstrapping ────────────────────────────────────────────
    authenticated: false,
    loginToken: '',
    loginError: '',
    loginLoading: false,
    health: {},
    config: {},
    capabilities: {},

    // ──── nav ──────────────────────────────────────────────────────────────
    NAV: [
      { id: 'home',        label: 'Home' },
      { id: 'launch',      label: 'Run audit' },
      { id: 'import',      label: 'Import PC' },
      { id: 'audits',      label: 'Audits' },
      { id: 'settings',    label: 'Settings' },
    ],
    AUDIT_TABS: [
      { id: 'executive',  label: 'Executive' },
      { id: 'findings',   label: 'Findings' },
      { id: 'infra',      label: 'Infrastructure' },
      { id: 'anssi',      label: 'ANSSI' },
      { id: 'frameworks', label: 'Frameworks' },
    ],
    WIZARD_STEPS: [
      { id: 'provider', label: 'Provider' },
      { id: 'config',   label: 'Credentials' },
      { id: 'audit',    label: 'Audit' },
      { id: 'done',     label: 'Results' },
    ],

    view: 'home',
    auditTab: 'executive',
    currentAuditId: null,
    auditData: null,
    pollHandle: null,

    // ──── wizard state ────────────────────────────────────────────────────
    wizardStep: 'provider',
    wizardError: '',
    wizardJobId: null,
    wizardJobStatus: 'pending',
    wizardProgress: 5,
    wizardElapsed: 0,
    wizardElapsedLabel: '0s',
    wizardTimer: null,
    auditStarting: false,
    adCfg: {
      url: '',
      baseDN: '',
      bindDN: '',
      bindPassword: '',
      tlsVerify: true,
    },
    connTesting: false,
    connTestResult: null,

    // ──── PingCastle import ───────────────────────────────────────────────
    pcCapabilityChecked: false,
    pcSupported: false,
    pcXmlFile: null,
    pcHtmlFile: null,
    pcImporting: false,
    pcImportingLabel: '',
    lastPcEvent: '',

    // ──── jobs ────────────────────────────────────────────────────────────
    jobs: [],

    // ──── settings ────────────────────────────────────────────────────────
    ldapForm: { url: '', bindDN: '', bindPassword: '', baseDN: '', tlsVerify: 'true' },
    ldapLoading: false,
    ldapMsg: '',
    ldapMsgOk: false,
    tokenForm: { service: '', duration: '720h', maxUses: 0 },
    generatedToken: '',
    tokenExpiry: '',

    // helpers exposed to template
    formatDate,
    formatBytes,

    // ════════ INIT ════════════════════════════════════════════════════════
    async init() {
      this.health = await API.health();

      // GUI token gate
      const stored = localStorage.getItem('etc-gui-token') || '';
      if (stored) {
        const ok = await API.verifyGuiToken(stored);
        if (ok === true) {
          this.authenticated = true;
          await this.postLogin();
          return;
        }
        localStorage.removeItem('etc-gui-token');
      }
      const probe = await API.verifyGuiToken('check');
      if (probe === 'not_required') {
        this.authenticated = true;
        await this.postLogin();
      }
    },

    async login() {
      this.loginError = '';
      this.loginLoading = true;
      const ok = await API.verifyGuiToken(this.loginToken);
      this.loginLoading = false;
      if (ok === true) {
        localStorage.setItem('etc-gui-token', this.loginToken);
        this.authenticated = true;
        await this.postLogin();
      } else {
        this.loginError = 'Invalid access token';
      }
    },

    logout() {
      localStorage.removeItem('etc-gui-token');
      localStorage.removeItem('etc-api-token');
      this.authenticated = false;
      this.loginToken = '';
    },

    async postLogin() {
      // Ensure API token exists for subsequent calls
      if (!localStorage.getItem('etc-api-token')) {
        try {
          const tok = await API.issueAPIToken();
          if (tok?.token) localStorage.setItem('etc-api-token', tok.token);
        } catch {}
      }
      await Promise.all([this.loadConfig(), this.loadCapabilities(), this.loadJobs()]);
      // Pre-fill LDAP form from current config
      if (this.config.ldap?.configured) {
        this.ldapForm = {
          url: this.config.ldap.url || '',
          baseDN: this.config.ldap.baseDN || '',
          bindDN: this.config.ldap.bindDN || '',
          bindPassword: '',
          tlsVerify: this.config.ldap.tlsVerify ? 'true' : 'false',
        };
        this.adCfg = {
          url: this.config.ldap.url || '',
          baseDN: this.config.ldap.baseDN || '',
          bindDN: this.config.ldap.bindDN || '',
          bindPassword: '',
          tlsVerify: !!this.config.ldap.tlsVerify,
        };
      }
      // Refresh job list every 5s
      setInterval(() => this.loadJobs(), 5000);
      // Deeplink: ?view=audit&id=...
      const params = new URLSearchParams(window.location.search);
      const v = params.get('view'); const id = params.get('id');
      if (v === 'audit' && id) {
        this.openAudit(id);
      }
      // Capability check for PingCastle import
      this.pcSupported = !!this.capabilities?.features?.import_pingcastle
        || !!this.capabilities?.import_pingcastle
        || (this.health?.version && this.compareVersion(this.health.version, '3.1.22') >= 0);
      this.pcCapabilityChecked = true;
    },

    compareVersion(a, b) {
      const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
      const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
      for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        const x = pa[i] || 0, y = pb[i] || 0;
        if (x !== y) return x - y;
      }
      return 0;
    },

    // ════════ NAV ═════════════════════════════════════════════════════════
    setView(v) {
      destroyAllCharts();
      this.view = v;
      if (v === 'launch' && this.wizardStep === 'done') this.resetWizard();
      // Update URL for shareable links
      const params = new URLSearchParams();
      params.set('view', v);
      if (v === 'audit' || v === 'view-audit') {
        if (this.currentAuditId) params.set('id', this.currentAuditId);
      }
      history.replaceState(null, '', `?${params.toString()}`);
    },

    // Job status → shared primitives (app.css .dot / .chip-status). Returning
    // class NAMES rather than colours keeps app.css the single source of truth
    // for the palette — no hex ever crosses into JS.
    jobDot(status) {
      return ({
        completed: 'ok',
        failed:    'bad',
        running:   'run',
        pending:   'wait',
      })[status] || 'idle';
    },
    jobBadge(status) {
      return ({
        completed: 'completed',
        failed:    'failed',
        running:   'running',
        pending:   'pending',
      })[status] || 'na';
    },
    // The collector creates exactly two job types (api/handlers.go:
    // jobStore.Create("ad_audit") and jobStore.Create("pingcastle_import")).
    jobTypeLabel(type) {
      return ({
        ad_audit:           'AD audit',
        pingcastle_import:  'PingCastle',
      })[type] || (type || '').replace(/_/g, ' ');
    },
    jobDuration(j) {
      if (!j.completedAt || !j.createdAt) return '—';
      const ms = new Date(j.completedAt) - new Date(j.createdAt);
      const s = Math.round(ms / 1000);
      if (s < 60) return s + 's';
      return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
    },

    // ════════ DATA LOADERS ════════════════════════════════════════════════
    async loadConfig() {
      try { this.config = await API.getConfig(); } catch {}
    },
    async loadCapabilities() {
      try { this.capabilities = await API.getCapabilities(); } catch {}
    },
    async loadJobs() {
      try {
        const d = await API.getJobs();
        this.jobs = (d.jobs || []).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      } catch {}
    },

    // ════════ AUDIT VIEW ══════════════════════════════════════════════════
    async openAudit(id) {
      this.currentAuditId = id;
      this.auditData = null;
      this.setView('view-audit');
      try {
        const d = await API.getJob(id);
        this.auditData = d.result || null;
      } catch (e) {
        console.error('load audit failed', e);
        this.auditData = null;
        return;
      }
      this.auditTab = 'executive';
      this.$nextTick(() => this.renderAuditTabs());
      // Register the tab-switch watcher exactly once (subsequent openAudit
      // calls reuse the same watcher — would otherwise leak listeners).
      if (!this._auditTabWatchSetup) {
        this._auditTabWatchSetup = true;
        this.$watch('auditTab', () => this.renderAuditTabs());
      }
    },

    renderAuditTabs() {
      destroyAllCharts();
      if (!this.auditData) return;
      // The collector returns `{result: AuditResponse}` where AuditResponse
      // is `{success, provider, audit: {summary, accounts, ...}}`. All renderers
      // below expect the inner `audit` shape (with summary at the top level).
      const inner = this.auditData?.audit || this.auditData;
      const tab = this.auditTab;
      const host = document.getElementById(`audit-tab-${tab}`);
      if (!host) return;
      let html = '';
      if (tab === 'executive')       html = renderExecutiveTab(inner);
      else if (tab === 'findings')   html = renderFindingsTab(inner);
      else if (tab === 'infra')      html = renderInfrastructureTab(inner);
      else if (tab === 'anssi')      html = renderAnssiTab(inner);
      else if (tab === 'frameworks') html = renderFrameworksTab(inner);
      host.innerHTML = html;
      attachCharts(host);
      // Re-init Alpine on the freshly injected DOM so x-data inside renderers works
      if (window.Alpine?.initTree) window.Alpine.initTree(host);
    },

    auditMetaLine() {
      const a = this.auditData;
      if (!a) return '';
      const m = a.audit?.metadata || a.metadata || {};
      const ts = m?.execution?.timestamp;
      const dom = m?.domain?.name || '';
      const status = this.jobs.find((j) => j.id === this.currentAuditId)?.status || '';
      return [dom, ts ? formatDate(ts) : null, status].filter(Boolean).join(' · ');
    },

    downloadAuditJSON() {
      if (!this.auditData) return;
      const blob = new Blob([JSON.stringify(this.auditData, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `audit-${(this.currentAuditId || 'export').slice(0, 8)}.json`;
      a.click();
    },

    // ════════ WIZARD ══════════════════════════════════════════════════════
    setStep(s) { this.wizardStep = s; },
    wizardStepIdx() {
      const idx = this.WIZARD_STEPS.findIndex((s) => s.id === this.wizardStep);
      return idx < 0 ? 0 : idx;
    },
    pickProvider(p) {
      if (p !== 'ad') return;
      this.connTestResult = null;
      this.wizardError = '';
      this.setStep('config');
    },
    resetWizard() {
      this.wizardStep = 'provider';
      this.wizardError = '';
      this.wizardJobId = null;
      this.wizardProgress = 5;
      this.wizardElapsedLabel = '0s';
      this.connTestResult = null;
      this.auditStarting = false;
      this.stopWizardTimer();
      if (this.pollHandle) { clearTimeout(this.pollHandle); this.pollHandle = null; }
    },
    async testConnection() {
      this.wizardError = '';
      this.connTestResult = null;
      this.connTesting = true;
      try {
        const cfg = {
          url: this.adCfg.url,
          bindDN: this.adCfg.bindDN,
          bindPassword: this.adCfg.bindPassword,
          baseDN: this.adCfg.baseDN,
          tlsVerify: !!this.adCfg.tlsVerify,
        };
        const r = await API.testLDAP(cfg);
        this.connTestResult = r;
      } catch (e) {
        this.connTestResult = { success: false, message: e.message };
      } finally {
        this.connTesting = false;
      }
    },
    async saveConfigAndAudit() {
      this.wizardError = '';
      this.auditStarting = true;
      try {
        // Save credentials so the audit can run with them
        const cfg = {
          url: this.adCfg.url,
          bindDN: this.adCfg.bindDN,
          bindPassword: this.adCfg.bindPassword,
          baseDN: this.adCfg.baseDN,
          tlsVerify: !!this.adCfg.tlsVerify,
        };
        const save = await API.saveLDAP(cfg);
        if (!save.ok) {
          this.wizardError = save.body?.message || 'Failed to save credentials';
          this.auditStarting = false;
          return;
        }
        await this.loadConfig();
        // Kick off the async audit
        const r = await API.startAdAudit();
        if (!r?.jobId && !r?.id) {
          this.wizardError = 'Could not start audit job';
          this.auditStarting = false;
          return;
        }
        this.wizardJobId = r.jobId || r.id;
        this.setStep('audit');
        this.startWizardTimer();
        this.pollWizardJob();
      } catch (e) {
        this.wizardError = e.message;
      } finally {
        this.auditStarting = false;
      }
    },
    startWizardTimer() {
      this.wizardElapsed = 0;
      this.wizardElapsedLabel = '0s';
      this.wizardProgress = 5;
      this.wizardTimer = setInterval(() => {
        this.wizardElapsed++;
        const m = Math.floor(this.wizardElapsed / 60);
        const s = this.wizardElapsed % 60;
        this.wizardElapsedLabel = m > 0 ? `${m}m ${s}s` : `${s}s`;
        // Fake progress curve up to 90% — settles when status flips to completed
        const target = 90;
        this.wizardProgress = Math.min(target, this.wizardProgress + (target - this.wizardProgress) * 0.04);
      }, 1000);
    },
    stopWizardTimer() {
      if (this.wizardTimer) { clearInterval(this.wizardTimer); this.wizardTimer = null; }
    },
    async pollWizardJob() {
      if (!this.wizardJobId) return;
      try {
        const d = await API.getJob(this.wizardJobId);
        this.wizardJobStatus = d.status;
        if (d.status === 'completed') {
          this.stopWizardTimer();
          this.wizardProgress = 100;
          this.auditData = d.result || null;
          this.currentAuditId = d.id || this.wizardJobId;
          this.setStep('done');
          this.$nextTick(() => {
            const host = document.getElementById('score-reveal-host');
            const score = clamp(this.auditData?.audit?.summary?.risk?.score
              ?? this.auditData?.summary?.risk?.score ?? 50, 0, 100);
            if (host) renderScoreReveal(host, score, () => this.openAudit(this.currentAuditId));
          });
          await this.loadJobs();
          return;
        }
        if (d.status === 'failed') {
          this.stopWizardTimer();
          this.wizardError = d.error || 'Audit failed';
          this.setStep('error');
          await this.loadJobs();
          return;
        }
      } catch (e) {
        // transient — keep polling
      }
      this.pollHandle = setTimeout(() => this.pollWizardJob(), 3000);
    },

    // ════════ PINGCASTLE IMPORT ══════════════════════════════════════════
    _stampPcEvent(label) {
      this.lastPcEvent = `${new Date().toISOString().slice(11, 19)} ${label}`;
    },
    onPcXmlPick(ev) {
      const f = ev.target.files?.[0] || null;
      this._stampPcEvent(`onPcXmlPick file=${f?.name || 'null'} size=${f?.size ?? '-'}`);
      console.log('[PC import] xml picked:', f?.name, f?.size, 'bytes');
      this.pcXmlFile = f;
      this.wizardError = '';
    },
    onPcHtmlPick(ev) {
      const f = ev.target.files?.[0] || null;
      this._stampPcEvent(`onPcHtmlPick file=${f?.name || 'null'} size=${f?.size ?? '-'}`);
      console.log('[PC import] html picked:', f?.name, f?.size, 'bytes');
      this.pcHtmlFile = f;
      this.wizardError = '';
    },
    onPcDrop(ev, kind) {
      kind = kind || 'xml';
      const f = ev.dataTransfer?.files?.[0];
      this._stampPcEvent(`onPcDrop kind=${kind} file=${f?.name || 'null'} size=${f?.size ?? '-'}`);
      console.log('[PC import] drop:', kind, f?.name, f?.size, 'bytes');
      if (!f) return;
      if (kind === 'xml') {
        if (/\.xml$/i.test(f.name)) {
          this.pcXmlFile = f;
          this.wizardError = '';
        } else {
          this.wizardError = 'Drop a .xml PingCastle report.';
        }
      } else if (kind === 'html') {
        if (/\.html?$/i.test(f.name)) {
          this.pcHtmlFile = f;
          this.wizardError = '';
        } else {
          this.wizardError = 'Drop a .html PingCastle report.';
        }
      }
    },
    async importPingCastle() {
      this._stampPcEvent(`importPingCastle click xml=${!!this.pcXmlFile} html=${!!this.pcHtmlFile}`);
      console.log('[PC import] click — xml:', this.pcXmlFile?.name, 'html:', this.pcHtmlFile?.name);
      if (!this.pcXmlFile) {
        this.wizardError = 'Pick an XML file first (click the dropzone).';
        return;
      }
      if (this.pcXmlFile.size > 50 * 1024 * 1024) {
        this.wizardError = 'XML file is larger than 50 MB.';
        return;
      }
      if (this.pcXmlFile.size === 0) {
        this.wizardError = 'Selected XML file is empty (0 bytes). Re-select it.';
        return;
      }
      if (this.pcHtmlFile && this.pcHtmlFile.size > 50 * 1024 * 1024) {
        this.wizardError = 'HTML file is larger than 50 MB.';
        return;
      }

      this.pcImporting = true;
      this.pcImportingLabel = 'Uploading and parsing the XML…';
      this.wizardError = '';

      let auditId = null;
      try {
        // Step 1 — XML import is the source of truth. If it fails we abort.
        console.log('[PC import] POST /api/v1/audit/import-pingcastle');
        const r = await API.importPingCastle(this.pcXmlFile);
        console.log('[PC import] xml response:', r);
        auditId = r.jobId || r.id || r.auditId;
        if (!auditId) throw new Error('Import succeeded but no audit ID returned.');

        // Step 2 — HTML enrichment is optional; failure is non-fatal so the
        // user can still view the XML-only report (matches /trial behaviour).
        if (this.pcHtmlFile) {
          this.pcImportingLabel = 'Enriching with HTML report…';
          try {
            console.log('[PC import] POST enrich-html for', auditId);
            await API.enrichPingCastleHtml(auditId, this.pcHtmlFile);
            console.log('[PC import] html enrichment OK');
          } catch (htmlErr) {
            console.warn('[PC import] html enrichment failed (non-fatal):', htmlErr);
            // Surface as a soft warning but keep going to the report.
            this.wizardError = `HTML enrichment failed: ${htmlErr.message}. Report is still available.`;
          }
        }

        this.pcImportingLabel = 'Opening report…';
        await this.loadJobs();
        this.openAudit(auditId);
      } catch (e) {
        console.error('[PC import] failed:', e);
        this.wizardError = e.message || 'Import failed';
      } finally {
        this.pcImporting = false;
        this.pcImportingLabel = '';
      }
    },

    // ════════ SETTINGS ═══════════════════════════════════════════════════
    async testLDAP() {
      this.ldapLoading = true; this.ldapMsg = '';
      try {
        const r = await API.testLDAP({
          url: this.ldapForm.url,
          bindDN: this.ldapForm.bindDN,
          bindPassword: this.ldapForm.bindPassword,
          baseDN: this.ldapForm.baseDN,
          tlsVerify: this.ldapForm.tlsVerify === 'true',
        });
        this.ldapMsg = r.message || (r.success ? 'Connection OK' : 'Connection failed');
        this.ldapMsgOk = !!r.success;
      } catch (e) {
        this.ldapMsg = e.message || 'Test failed'; this.ldapMsgOk = false;
      } finally { this.ldapLoading = false; }
    },
    async saveLDAP() {
      this.ldapLoading = true; this.ldapMsg = '';
      try {
        const r = await API.saveLDAP({
          url: this.ldapForm.url,
          bindDN: this.ldapForm.bindDN,
          bindPassword: this.ldapForm.bindPassword,
          baseDN: this.ldapForm.baseDN,
          tlsVerify: this.ldapForm.tlsVerify === 'true',
        });
        if (r.ok) {
          this.ldapMsg = 'Saved'; this.ldapMsgOk = true;
          await this.loadConfig();
          await this.loadCapabilities();
        } else {
          this.ldapMsg = r.body?.message || 'Save failed'; this.ldapMsgOk = false;
        }
      } catch (e) {
        this.ldapMsg = e.message || 'Save failed'; this.ldapMsgOk = false;
      } finally { this.ldapLoading = false; }
    },
    async deleteLDAP() {
      if (!confirm('Remove LDAP configuration?')) return;
      try {
        await API.deleteLDAP();
        this.ldapForm = { url: '', bindDN: '', bindPassword: '', baseDN: '', tlsVerify: 'true' };
        this.ldapMsg = ''; this.ldapMsgOk = false;
        await this.loadConfig();
      } catch {}
    },
    async generateToken() {
      try {
        const r = await API.issueAPIToken({
          service: this.tokenForm.service,
          duration: this.tokenForm.duration,
          maxUses: this.tokenForm.maxUses,
        });
        this.generatedToken = r.token;
        this.tokenExpiry = r.expiresAt ? new Date(r.expiresAt).toLocaleString() : '—';
      } catch {}
    },
  };
};
