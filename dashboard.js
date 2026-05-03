let cfg = JSON.parse(localStorage.getItem('ads-cfg') || '{}');
let allEvents = [];
let allBlacklist = [];
let allRules = [];
let rulesFilter = 'all'; // all | pending | approved | rejected
let evPage = 1;
const EV_PER_PAGE = 20;
let sortKey = 'created_at', sortDir = -1;
let autoRefresh = true;
let refreshTimer = null;
let refreshInterval = 5000;
let prevPage = 'dashboard';

window.onload = () => {
  loadSettings();
  checkConfig();
  updateClock();
  setInterval(updateClock, 1000);
  refreshAll();
  scheduleRefresh();
  const today = new Date().toISOString().split('T')[0];
  const week = new Date(Date.now()-7*86400000).toISOString().split('T')[0];
  document.getElementById('rep-from').value = week;
  document.getElementById('rep-to').value = today;
  const savedTheme = localStorage.getItem('ads-theme') || 'light';
  setTheme(savedTheme);
};

function updateClock() {
  const now = new Date();
  document.getElementById('topbar-time').textContent = now.toUTCString().replace('GMT','UTC');
}

function checkConfig() {
  document.getElementById('config-banner').classList.toggle('hidden', !!(cfg.baseUrl));
}

function getHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (cfg.apiKey) h['X-Api-Key'] = cfg.apiKey;
  return h;
}

function apiUrl(path) {
  return ((cfg.baseUrl || 'http://localhost:8000').replace(/\/$/, '')) + path;
}

function nav(el) {
  if (!el) return;
  const page = el.dataset.page;
  prevPage = document.querySelector('.nav-item.active')?.dataset.page || 'dashboard';
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('page-' + page).classList.add('active');
  const titles = { dashboard:'Dashboard', events:'Live Events', incident:'Incident Detail',
    response:'Response / Blacklist', pipeline:'Agent Pipeline', rules:'Adaptive Rules',
    reports:'Reports & Export', settings:'Settings' };
  document.getElementById('topbar-title').textContent = titles[page] || page;
  if (page === 'events') loadEvents();
  if (page === 'response') loadBlacklist();
  if (page === 'pipeline') renderPipeline();
  if (page === 'rules') loadRules();
  if (page === 'reports') loadReportSummary();
}

function goBack() {
  const el = document.querySelector(`[data-page="${prevPage}"]`);
  if (el) nav(el); else nav(document.querySelector('[data-page=dashboard]'));
}

function scheduleRefresh() {
  clearInterval(refreshTimer);
  if (autoRefresh) refreshTimer = setInterval(autoRefreshTick, refreshInterval);
}

function autoRefreshTick() {
  const active = document.querySelector('.page.active')?.id;
  if (active === 'page-dashboard') loadDashboard();
  if (active === 'page-events') loadEvents();
  if (active === 'page-rules') loadRules();
}

function toggleAutoRefresh() {
  autoRefresh = !autoRefresh;
  document.getElementById('ar-toggle').classList.toggle('on', autoRefresh);
  document.getElementById('ar-dot').style.display = autoRefresh ? 'block' : 'none';
  document.getElementById('ar-label').textContent = autoRefresh ? 'Auto-refresh' : 'Manual';
  scheduleRefresh();
}

function updateRefreshInterval() {
  refreshInterval = parseInt(document.getElementById('s-interval').value);
  scheduleRefresh();
}

function refreshAll() { loadDashboard(); checkHealth(); }

async function checkHealth() {
  try {
    const res = await fetch(apiUrl('/health'), { headers: getHeaders() });
    const ok = res.ok;
    document.getElementById('sys-dot').style.background = ok ? 'var(--accent)' : 'var(--red)';
    document.getElementById('sys-status').textContent = ok ? 'Online' : 'Offline';
  } catch {
    document.getElementById('sys-dot').style.background = 'var(--red)';
    document.getElementById('sys-status').textContent = 'Offline';
  }
}

async function loadDashboard() {
  try {
    const [logsRes, blRes, rulesRes] = await Promise.all([
      fetch(apiUrl('/logs'), { headers: getHeaders() }),
      fetch(apiUrl('/blacklist'), { headers: getHeaders() }),
      fetch(apiUrl('/rules/suggested'), { headers: getHeaders() })
    ]);
    const logs = logsRes.ok ? (await logsRes.json()) : [];
    const bl = blRes.ok ? (await blRes.json()) : [];
    const rules = rulesRes.ok ? (await rulesRes.json()) : { rules: [] };
    const rows = logs.logs || logs || [];
    const blacklistRows = bl.blacklist || bl || [];
    const pendingRules = (rules.rules || []).length;
    allEvents = rows;
    updateDashboard({
      total: rows.length,
      blocked: rows.filter(r => r.action === 'block').length,
      alerts: rows.filter(r => r.action === 'alert').length,
      blacklist_count: blacklistRows.length,
      recent: rows,
      pending_rules: pendingRules
    });
  } catch { /* offline */ }
}

function updateDashboard(data) {
  const rows = data.recent || [];
  document.getElementById('c-total').textContent = data.total ?? rows.length;
  document.getElementById('c-blocked').textContent = data.blocked ?? 0;
  document.getElementById('c-alerts').textContent = data.alerts ?? 0;
  document.getElementById('c-blacklist').textContent = data.blacklist_count ?? 0;
  document.getElementById('c-total-d').textContent = (data.total || 0) + ' events logged';
  document.getElementById('c-blocked-d').textContent = (data.blocked || 0) + ' IPs blocked';
  document.getElementById('c-alerts-d').textContent = (data.alerts || 0) + ' alerts fired';
  document.getElementById('c-blacklist-d').textContent = (data.blacklist_count || 0) + ' in blacklist';
  if (data.pending_rules > 0) {
    document.getElementById('nav-badge-rules').textContent = data.pending_rules;
    document.getElementById('nav-badge-rules').style.display = '';
  } else {
    document.getElementById('nav-badge-rules').style.display = 'none';
  }
  document.getElementById('nav-badge-events').textContent = data.total || 0;
  renderDashTable(rows);
  renderTimeline(rows);
  renderDistChart(rows);
}

function renderDashTable(rows) {
  const tbody = document.getElementById('dash-table');
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">🛡</div>No incidents yet</div></td></tr>`;
    return;
  }
  tbody.innerHTML = rows.slice(0, 10).map(r => `
    <tr>
      <td class="mono">${formatTime(r.created_at)}</td>
      <td class="mono">${r.ip || '—'}</td>
      <td>${threatBadge(r.threat)}</td>
      <td>${riskBar(r.risk_score)}</td>
      <td>${actionBadge(r.action)}</td>
      <td><button class="btn" onclick='showIncident(${JSON.stringify(r).replace(/'/g,"&#39;")})'>View</button></td>
    </tr>
  `).join('');
}

async function loadEvents() {
  try {
    const res = await fetch(apiUrl('/logs'), { headers: getHeaders() });
    if (!res.ok) throw new Error();
    const data = await res.json();
    allEvents = data.logs || data || [];
    filterEvents();
  } catch {
    document.getElementById('events-table').innerHTML =
      `<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">⚡</div>Cannot connect to backend</div></td></tr>`;
  }
}

function filterEvents() {
  const search = document.getElementById('ev-search').value.toLowerCase();
  const threat = document.getElementById('ev-threat').value;
  const action = document.getElementById('ev-action').value;
  const riskMin = document.getElementById('ev-risk').value;
  let filtered = allEvents.filter(r => {
    if (search && !r.ip?.toLowerCase().includes(search) && !r.threat?.toLowerCase().includes(search)) return false;
    if (threat && r.threat !== threat) return false;
    if (action && r.action !== action) return false;
    if (riskMin !== '' && r.risk_score < parseInt(riskMin)) return false;
    return true;
  });
  filtered.sort((a,b) => {
    let av = a[sortKey], bv = b[sortKey];
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    return av < bv ? sortDir : av > bv ? -sortDir : 0;
  });
  evPage = 1;
  renderEventsTable(filtered);
  renderPagination(filtered.length);
}

function sortTable(key) {
  if (sortKey === key) sortDir *= -1; else { sortKey = key; sortDir = -1; }
  filterEvents();
}

function renderEventsTable(rows) {
  const start = (evPage-1)*EV_PER_PAGE;
  const page = rows.slice(start, start+EV_PER_PAGE);
  const tbody = document.getElementById('events-table');
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">⚡</div>No events match filters</div></td></tr>`;
    return;
  }
  tbody.innerHTML = page.map(r => `
    <tr>
      <td class="mono">${formatTime(r.created_at)}</td>
      <td class="mono">${r.ip||'—'}</td>
      <td>${threatBadge(r.threat)}</td>
      <td>${riskBar(r.risk_score)}</td>
      <td>${actionBadge(r.action)}</td>
      <td class="mono" style="max-width:140px;overflow:hidden;text-overflow:ellipsis;font-size:10px">${truncate(r.reason,36)}</td>
      <td><button class="btn" onclick='showIncident(${JSON.stringify(r).replace(/'/g,"&#39;")})'>View</button></td>
    </tr>
  `).join('');
}

function renderPagination(total) {
  const pages = Math.ceil(total/EV_PER_PAGE);
  const el = document.getElementById('ev-pagination');
  if (pages <= 1) { el.innerHTML = ''; return; }
  let html = `<button class="pg-btn" onclick="evPage=Math.max(1,evPage-1);filterEvents()">←</button>`;
  for (let i=1;i<=Math.min(pages,7);i++)
    html += `<button class="pg-btn ${i===evPage?'active':''}" onclick="evPage=${i};filterEvents()">${i}</button>`;
  html += `<button class="pg-btn" onclick="evPage=Math.min(${pages},evPage+1);filterEvents()">→</button>`;
  el.innerHTML = html;
}

function showIncident(row) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-incident').classList.add('active');
  document.getElementById('topbar-title').textContent = 'Incident Detail';
  document.getElementById('inc-heading').textContent = `Incident — ${row.ip}`;
  document.getElementById('inc-basicinfo').innerHTML = [
    ['IP Address', `<span class="mono">${row.ip}</span>`],
    ['Threat Type', threatBadge(row.threat)],
    ['Risk Score', riskBar(row.risk_score)],
    ['Action Taken', actionBadge(row.action)],
    ['Logged At', `<span class="mono">${formatTime(row.created_at)}</span>`],
    ['Log ID', `<span class="mono">#${row.id}</span>`]
  ].map(([k,v])=>`<div class="kv"><span class="kv-key">${k}</span><span class="kv-val">${v}</span></div>`).join('');
  const reasons = (row.reason||'').split(',').filter(Boolean);
  document.getElementById('inc-analysis').innerHTML = [
    ['Reasons', reasons.map(r=>`<span class="badge gray">${r.trim()}</span>`).join(' ')||'—'],
    ['Risk Score', `<span class="mono">${row.risk_score||0}/100</span>`],
    ['Agent', `<span class="badge blue">decision</span>`],
    ['Pipeline', `<span class="badge green">completed</span>`]
  ].map(([k,v])=>`<div class="kv"><span class="kv-key">${k}</span><span class="kv-val">${v}</span></div>`).join('');
  const chainMap = {
    port_scan:'Port scanning detected', brute_force_low:'Brute force started (low)',
    brute_force_medium:'Brute force escalated', brute_force_high:'Brute force — high confidence',
    ddos:'DDoS flood detected', flood_attack:'Flood attack (50+ req/60s)',
    multi_stage_attack:'Multi-stage attack chain', data_exfiltration:'Data exfiltration detected',
    lateral_movement:'Lateral movement observed', privilege_escalation:'Privilege escalation attempt',
  };
  const tlItems = [];
  if (row.threat) tlItems.push({ time: row.created_at, label: chainMap[row.threat]||row.threat, badge: threatBadge(row.threat) });
  if (row.action==='block') tlItems.push({ time: row.created_at, label: 'IP added to blacklist', badge: `<span class="badge red">Blocked</span>` });
  if (row.action==='alert') tlItems.push({ time: row.created_at, label: 'Alert triggered — monitoring', badge: `<span class="badge yellow">Alert</span>` });
  document.getElementById('inc-timeline').innerHTML = tlItems.map(t=>`
    <div class="timeline-item"><span class="tl-time">${formatTime(t.time)}</span><span class="tl-desc">${t.badge} ${t.label}</span></div>
  `).join('') || '<div class="empty-state">No timeline data</div>';
  const playbook = (row.playbook||'').split('\n').filter(Boolean);
  document.getElementById('inc-playbook').innerHTML = playbook.length
    ? playbook.map((s,i)=>`<li><span class="playbook-num">${i+1}</span><span>${s}</span></li>`).join('')
    : '<li><span class="playbook-num">1</span><span>No playbook stored for this incident.</span></li>';
  document.getElementById('inc-json-pre').textContent = JSON.stringify(
    {id:row.id,ip:row.ip,threat:row.threat,action:row.action,risk_score:row.risk_score,reason:row.reason,playbook:row.playbook,created_at:row.created_at}, null, 2);
}

function copyJson() {
  navigator.clipboard.writeText(document.getElementById('inc-json-pre').textContent);
  document.querySelector('.copy-btn').textContent = '✓';
  setTimeout(()=>document.querySelector('.copy-btn').textContent='copy', 2000);
}

async function loadBlacklist() {
  try {
    const res = await fetch(apiUrl('/blacklist'), { headers: getHeaders() });
    if (!res.ok) throw new Error();
    const data = await res.json();
    allBlacklist = data.blacklist || data || [];
    filterBlacklist();
  } catch {
    document.getElementById('bl-table').innerHTML =
      `<tr><td colspan="4"><div class="empty-state"><div class="empty-icon">🛡</div>Cannot load blacklist</div></td></tr>`;
  }
}

function filterBlacklist() {
  const search = document.getElementById('bl-search').value.toLowerCase();
  const filtered = allBlacklist.filter(r => !search || r.ip?.toLowerCase().includes(search));
  const tbody = document.getElementById('bl-table');
  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state"><div class="empty-icon">🛡</div>No blocked IPs</div></td></tr>`;
    return;
  }
  console.log(filtered)
  tbody.innerHTML = filtered.map(r => `
    <tr>
      <td class="mono">${r.ip}</td>
      <td class="mono">${formatTime(r.created_at)}</td>
      <td><span class="badge red">Auto-blocked</span></td>
      <td><button class="btn danger" onclick="unblockIP('${r.ip}')">Unblock</button></td>
    </tr>
  `).join('');
  
}

async function addToBlacklist() {
  const ip = document.getElementById('bl-add-ip').value.trim();
  if (!ip || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) { toast('Invalid IP format', 'error'); return; }
  try {
    const res = await fetch(apiUrl('/blacklist'), { method:'POST', headers: getHeaders(), body: JSON.stringify({ip}) });
    if (!res.ok) throw new Error(await res.text());
    document.getElementById('bl-add-ip').value = '';
    toast(`${ip} blocked`, 'success');
    loadBlacklist();
  } catch(e) { toast('Failed: '+e.message, 'error'); }
}

async function unblockIP(ip) {
  if (!confirm(`Unblock ${ip}? This action will be logged.`)) return;
  try {
    const res = await fetch(apiUrl(`/blacklist/${encodeURIComponent(ip)}`), { method:'DELETE', headers: getHeaders() });
    if (!res.ok) throw new Error(await res.text());
    toast(`${ip} unblocked`, 'success');
    loadBlacklist();
  } catch(e) { toast('Failed: '+e.message, 'error'); }
}

const AGENTS = [
  {name:'Filter',desc:'Drops irrelevant events',file:'agents/filter.py'},
  {name:'Normalizer',desc:'Normalizes event schema',file:'agents/normalizer.py'},
  {name:'Detection',desc:'Multi-rule threat engine',file:'agents/detection.py'},
  {name:'Coordinator',desc:'Routes agent messages',file:'agents/coordinator.py'},
  {name:'Decision',desc:'Risk scoring + action',file:'agents/decision.py'},
  {name:'Response',desc:'Executes block/alert/ignore',file:'agents/response.py'},
];

async function renderPipeline() {
  let stats = {};
  try {
    const res = await fetch(apiUrl('/pipeline/status'), { headers: getHeaders() });
    if (res.ok) stats = await res.json();
  } catch {}
  document.getElementById('pipeline-nodes').innerHTML = AGENTS.map((a,i) => {
    const st = stats[a.name.toLowerCase()]||{};
    const active = st.status === 'active';
    return `
      <div style="display:flex;align-items:center;gap:0">
        <div style="background:var(--bg2);border:1px solid ${active?'var(--accent-border)':'var(--border)'};border-radius:8px;padding:10px 14px;min-width:100px;cursor:pointer;transition:all .15s" onclick="highlightAgent(${i})" id="pipeline-node-${i}">
          <div style="font-size:12px;font-weight:600;color:var(--text)">${a.name}</div>
          <div style="font-size:10px;margin-top:3px;color:${active?'var(--accent)':'var(--text3)'}">${active?'● Active':'○ Idle'}</div>
          <div style="font-size:10px;color:var(--text3);margin-top:2px;font-family:var(--mono)">${st.events||0} events</div>
        </div>
        ${i<AGENTS.length-1?`<div style="color:var(--border2);font-size:18px;padding:0 4px">→</div>`:''}
      </div>`;
  }).join('');
  document.getElementById('pipeline-detail').innerHTML = AGENTS.map((a,i) => {
    const st = stats[a.name.toLowerCase()]||{};
    return `
      <div class="detail-box" id="pipeline-detail-${i}">
        <div class="detail-box-title">${a.name}</div>
        <div class="kv"><span class="kv-key">Status</span><span class="kv-val">${st.status||'idle'}</span></div>
        <div class="kv"><span class="kv-key">Events processed</span><span class="kv-val">${st.events||0}</span></div>
        <div class="kv"><span class="kv-key">Avg latency</span><span class="kv-val">${st.latency||'—'}</span></div>
        <div class="kv"><span class="kv-key">Last active</span><span class="kv-val">${st.last_active||'—'}</span></div>
        <div style="margin-top:8px;font-size:11px;color:var(--text3)">${a.desc}</div>
        <div style="margin-top:4px;font-size:10px;color:var(--text3);font-family:var(--mono)">${a.file}</div>
      </div>`;
  }).join('');
}

function highlightAgent(i) {
  document.querySelectorAll('[id^=pipeline-detail-]').forEach((el,j) =>
    el.style.borderColor = i===j ? 'var(--accent)' : 'var(--border)');
}

// ── Rules ────────────────────────────────────────────────────────────────────

async function loadRules() {
  try {
    const res = await fetch(apiUrl('/rules/all'), { headers: getHeaders() });
    if (!res.ok) throw new Error();
    const data = await res.json();
    allRules = data.rules || [];
    renderRules();
    updateRulesCounts();
  } catch {
    document.getElementById('rules-table').innerHTML =
      `<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">⊞</div>Cannot load rules</div></td></tr>`;
  }
}

function updateRulesCounts() {
  const pending  = allRules.filter(r => r.status === 'pending').length;
  const approved = allRules.filter(r => r.status === 'approved').length;
  const rejected = allRules.filter(r => r.status === 'rejected').length;
  const tabEl = document.getElementById('rules-tab-counts');
  if (tabEl) tabEl.innerHTML = `
    <span class="rules-tab ${rulesFilter==='all'?'active':''}" onclick="setRulesFilter('all')">All (${allRules.length})</span>
    <span class="rules-tab ${rulesFilter==='pending'?'active':''}" onclick="setRulesFilter('pending')">Pending <span class="badge yellow">${pending}</span></span>
    <span class="rules-tab ${rulesFilter==='approved'?'active':''}" onclick="setRulesFilter('approved')">Approved <span class="badge green">${approved}</span></span>
    <span class="rules-tab ${rulesFilter==='rejected'?'active':''}" onclick="setRulesFilter('rejected')">Rejected <span class="badge gray">${rejected}</span></span>
  `;
  // Update nav badge
  const badge = document.getElementById('nav-badge-rules');
  if (badge) { badge.textContent = pending; badge.style.display = pending > 0 ? '' : 'none'; }
}

function setRulesFilter(f) {
  rulesFilter = f;
  renderRules();
  updateRulesCounts();
}

function renderRules() {
  const filtered = rulesFilter === 'all' ? allRules : allRules.filter(r => r.status === rulesFilter);
  const tbody = document.getElementById('rules-table');
  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">⊞</div>No rules in this category</div></td></tr>`;
    return;
  }
  tbody.innerHTML = filtered.map(r => {
    const isPending  = r.status === 'pending';
    const isApproved = r.status === 'approved';
    const isRejected = r.status === 'rejected';
    const statusBadge = isApproved
      ? `<span class="badge green">✓ Approved</span>`
      : isRejected
      ? `<span class="badge gray">✗ Rejected</span>`
      : `<span class="badge yellow">⏳ Pending</span>`;
    const actions = isPending
      ? `<button class="btn primary" onclick="approveRule(${r.id})">Approve</button>
         <button class="btn danger"  onclick="rejectRule(${r.id})">Reject</button>`
      : isApproved
      ? `<button class="btn danger"  onclick="rejectRule(${r.id})">Revoke</button>`
      : `<button class="btn primary" onclick="approveRule(${r.id})">Re-approve</button>
         <button class="btn"         onclick="deleteRule(${r.id})">Delete</button>`;
    return `<tr>
      <td class="mono" style="font-size:11px">${r.event_label || r.event_type}</td>
      <td>${threatBadge(r.suggested_threat)}</td>
      <td class="mono">${r.occurrences}</td>
      <td class="mono">${Math.round((r.suggested_confidence||0)*100)}%</td>
      <td>${statusBadge}</td>
      <td style="display:flex;gap:6px;flex-wrap:wrap">${actions}</td>
    </tr>`;
  }).join('');
}

async function approveRule(id) {
  try {
    const res = await fetch(apiUrl(`/rules/${id}/approve`), {method:'POST', headers:getHeaders()});
    if (!res.ok) throw new Error();
    toast('Rule approved — now active in detection pipeline', 'success');
    loadRules();
  } catch { toast('Failed to approve rule', 'error'); }
}

async function rejectRule(id) {
  try {
    const res = await fetch(apiUrl(`/rules/${id}/reject`), {method:'POST', headers:getHeaders()});
    if (!res.ok) throw new Error();
    toast('Rule rejected', 'warn');
    loadRules();
  } catch { toast('Failed to reject rule', 'error'); }
}

async function deleteRule(id) {
  if (!confirm('Permanently delete this rule?')) return;
  try {
    const res = await fetch(apiUrl(`/rules/${id}`), {method:'DELETE', headers:getHeaders()});
    if (!res.ok) throw new Error();
    toast('Rule deleted', 'warn');
    loadRules();
  } catch { toast('Failed to delete rule', 'error'); }
}

// ── Reports ──────────────────────────────────────────────────────────────────

async function loadReportSummary() {
  try {
    const res = await fetch(apiUrl('/logs'), { headers: getHeaders() });
    if (!res.ok) throw new Error();
    const data = await res.json();
    const rows = data.logs || data || [];
    document.getElementById('rep-total').textContent = rows.length;
    const threats = {}, ips = {};
    rows.forEach(r => {
      if (r.threat) threats[r.threat] = (threats[r.threat]||0)+1;
      if (r.ip) ips[r.ip] = (ips[r.ip]||0)+1;
    });
    document.getElementById('rep-top-threat').textContent = Object.entries(threats).sort((a,b)=>b[1]-a[1])[0]?.[0]||'—';
    document.getElementById('rep-top-ip').textContent = Object.entries(ips).sort((a,b)=>b[1]-a[1])[0]?.[0]||'—';
  } catch {}
}

function exportCSV() {
  if (!allEvents.length) { toast('No data to export', 'warn'); return; }
  const headers = ['id','ip','threat','action','risk_score','reason','created_at'];
  const rows = [headers.join(','), ...allEvents.map(r => headers.map(h=>JSON.stringify(r[h]||'')).join(','))];
  download('threat_logs.csv', rows.join('\n'), 'text/csv');
  toast('CSV exported', 'success');
}

function exportSTIX() {
  if (!allEvents.length) { toast('No data to export', 'warn'); return; }
  const bundle = {
    type:'bundle', id:'bundle--'+uuid(), spec_version:'2.1',
    objects: allEvents.filter(r=>r.action==='block').map(r => ({
      type:'indicator', id:'indicator--'+uuid(), spec_version:'2.1',
      created: r.created_at||new Date().toISOString(),
      modified: r.created_at||new Date().toISOString(),
      name:`Blocked IP: ${r.ip}`,
      description: r.reason||r.threat,
      pattern:`[ipv4-addr:value = '${r.ip}']`,
      pattern_type:'stix', valid_from:r.created_at||new Date().toISOString(),
      labels:['malicious-activity'], confidence:r.risk_score
    }))
  };
  download('threats.stix.json', JSON.stringify(bundle,null,2), 'application/json');
  toast('STIX JSON exported', 'success');
}

function download(filename, content, mime) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content],{type:mime}));
  a.download = filename; a.click();
}

function uuid() { return crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2); }

function loadSettings() {
  document.getElementById('s-baseurl').value = cfg.baseUrl||'';
  document.getElementById('s-apikey').value = cfg.apiKey||'';
  document.getElementById('s-webhook').value = cfg.webhook||'';
}

function saveSettings() {
  cfg.baseUrl = document.getElementById('s-baseurl').value.trim();
  cfg.apiKey = document.getElementById('s-apikey').value.trim();
  cfg.webhook = document.getElementById('s-webhook').value.trim();
  localStorage.setItem('ads-cfg', JSON.stringify(cfg));
  toast('Settings saved', 'success');
  checkConfig(); refreshAll();
}

async function testConnection() {
  try {
    const res = await fetch(apiUrl('/health'), { headers: getHeaders() });
    if (res.ok) { toast('Connection successful ✓', 'success'); checkHealth(); }
    else toast('Server responded with ' + res.status, 'error');
  } catch { toast('Connection failed — check URL', 'error'); }
}

function toggleMask() {
  const el = document.getElementById('s-apikey');
  el.classList.toggle('masked');
  document.querySelector('[onclick="toggleMask()"]').textContent = el.classList.contains('masked') ? 'show' : 'hide';
}

function toggleTheme() { setTheme(document.body.dataset.theme==='dark'?'light':'dark'); }

function setTheme(t) {
  document.body.dataset.theme = t;
  localStorage.setItem('ads-theme', t);
  document.querySelector('.theme-btn').textContent = t==='dark' ? '☀' : '☾';
}

function renderTimeline(rows) {
  const svg = document.getElementById('chart-timeline');
  if (!rows.length) return;
  const W=560,H=80,PAD=8;
  const scores = rows.slice(-20).map(r=>r.risk_score||0);
  const max = Math.max(...scores,1);
  const pts = scores.map((s,i)=>{
    const x=PAD+i*(W-2*PAD)/(scores.length-1||1);
    const y=H-PAD-(s/max)*(H-2*PAD);
    return `${x},${y}`;
  }).join(' ');
  svg.innerHTML = `
    <defs><linearGradient id="lg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#16a34a" stop-opacity="0.3"/>
      <stop offset="100%" stop-color="#16a34a" stop-opacity="0"/>
    </linearGradient></defs>
    <polyline points="${pts}" fill="none" stroke="#16a34a" stroke-width="1.5" stroke-linejoin="round"/>
    <polyline points="${PAD},${H-PAD} ${pts} ${W-PAD},${H-PAD}" fill="url(#lg)" stroke="none"/>
    <line x1="${PAD}" y1="${H/2}" x2="${W-PAD}" y2="${H/2}" stroke="var(--border)" stroke-width="0.5" stroke-dasharray="4 4"/>
  `;
}

function renderDistChart(rows) {
  const counts={};
  rows.forEach(r=>{if(r.threat)counts[r.threat]=(counts[r.threat]||0)+1;});
  const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,5);
  if(!sorted.length)return;
  const svg=document.getElementById('chart-dist');
  const max=Math.max(...sorted.map(s=>s[1]),1);
  const colors=['#dc2626','#d97706','#2563eb','#16a34a','#7c3aed'];
  const BW=28,GAP=10,H=80,PB=20;
  const totalW=sorted.length*(BW+GAP);
  const startX=(200-totalW)/2;
  svg.innerHTML=sorted.map(([t,c],i)=>{
    const h=Math.max(4,((c/max)*(H-PB-8)));
    const x=startX+i*(BW+GAP);
    const y=H-PB-h;
    const label=t.replace(/_/g,' ').slice(0,5);
    return `
      <rect x="${x}" y="${y}" width="${BW}" height="${h}" rx="3" fill="${colors[i]}" opacity="0.85"/>
      <text x="${x+BW/2}" y="${H-4}" font-size="7" text-anchor="middle" fill="var(--text3)" font-family="JetBrains Mono,monospace">${label}</text>
      <text x="${x+BW/2}" y="${y-3}" font-size="8" text-anchor="middle" fill="${colors[i]}" font-family="JetBrains Mono,monospace">${c}</text>
    `;
  }).join('');
}

function threatBadge(t) {
  if(!t)return`<span class="badge gray">—</span>`;
  const cls=t.includes('brute')||t.includes('multi_stage')||t.includes('flood')||t.includes('malware')||t.includes('exfil')?'red'
    :t.includes('ddos')?'red'
    :t.includes('scan')||t.includes('travel')||t.includes('lateral')||t.includes('privilege')?'yellow'
    :t.includes('anomaly')?'blue':'gray';
  return`<span class="badge ${cls}">${t.replace(/_/g,' ')}</span>`;
}

function actionBadge(a) {
  const m={block:'red',alert:'yellow',ignore:'gray'};
  return`<span class="badge ${m[a]||'gray'}">${a||'—'}</span>`;
}

function riskBar(score) {
  const s=Math.min(100,Math.max(0,score||0));
  const color=s>80?'var(--red)':s>50?'var(--yellow)':'var(--accent)';
  return`<div class="risk-bar"><div class="risk-track"><div class="risk-fill" style="width:${s}%;background:${color}"></div></div><span style="font-size:10px;font-family:var(--mono);color:${color};min-width:28px">${s}</span></div>`;
}

function formatTime(ts) {
  if(!ts)return'—';
  try{return new Date(ts).toLocaleString('en-GB',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});}
  catch{return ts;}
}

function truncate(s,n){return s&&s.length>n?s.slice(0,n)+'…':(s||'—');}

function toast(msg,type='success'){
  const el=document.createElement('div');
  el.className=`toast ${type}`;
  el.innerHTML=`<span>${type==='success'?'✓':type==='error'?'✗':'!'}</span>${msg}`;
  document.getElementById('toasts').appendChild(el);
  setTimeout(()=>el.remove(),3500);
}

function closeModal(){document.getElementById('modal').classList.remove('open');}
