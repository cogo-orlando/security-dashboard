// ══════════════════════════════════════════
//  SECURITY DASHBOARD — JS v2
// ══════════════════════════════════════════

// ── Horloge live ──
function updateClock() {
    const el = document.getElementById('liveTime');
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
setInterval(updateClock, 1000);
updateClock();

// ── Navigation sidebar ──
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        const section = item.dataset.section;
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        item.classList.add('active');
        document.querySelectorAll('.section').forEach(s => s.classList.add('hidden'));
        const target = document.getElementById(`section-${section}`);
        if (target) {
            target.classList.remove('hidden');
            loadSectionData(section);
            // Ré-observe les éléments reveal de la section
            target.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));
        }
    });
});

// ── Reveal observer ──
const revealObserver = new IntersectionObserver(entries => {
    entries.forEach(e => {
        if (e.isIntersecting) {
            e.target.classList.add('visible');
            revealObserver.unobserve(e.target);
        }
    });
}, { threshold: 0.05 });

document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));

// ══════════════════════════════════════════
//  CHARGEMENT DES DONNÉES
// ══════════════════════════════════════════

async function loadStats() {
    try {
        const [statsRes, trendsRes] = await Promise.all([
            fetch('/api/stats'),
            fetch('/api/trends')
        ]);
        if (!statsRes.ok) throw new Error(`stats HTTP ${statsRes.status}`);
        const stats = await statsRes.json();
        const trends = trendsRes.ok ? await trendsRes.json() : null;
        renderStats(stats, trends);
    } catch (err) {
        console.error('loadStats error:', err);
    }
}

async function loadEvents(type = '', search = '') {
    try {
        let url = '/api/events?limit=100';
        if (type) url += `&type=${encodeURIComponent(type)}`;
        if (search) url += `&q=${encodeURIComponent(search)}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        renderEvents(data || []);
    } catch (err) {
        console.error('loadEvents error:', err);
    }
}

async function loadBlacklist() {
    try {
        const res = await fetch('/api/blacklist');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        renderBlacklist(data || []);
    } catch (err) {
        console.error('loadBlacklist error:', err);
    }
}

async function loadAgents() {
    try {
        const res = await fetch('/api/agents');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        renderAgents(data || []);
    } catch (err) {
        console.error('loadAgents error:', err);
    }
}

async function loadErrors() {
    try {
        const res = await fetch('/api/errors');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        renderErrors(data || []);
    } catch (err) {
        console.error('loadErrors error:', err);
    }
}

// ══════════════════════════════════════════
//  RENDU STATS + TENDANCES
// ══════════════════════════════════════════

function renderStats(data, trends) {
    setText('kpi-total-events', fmtNum(data.total_events ?? 0));
    setText('kpi-events-24h', fmtNum(data.events_24h ?? 0));
    setText('kpi-honeypots', fmtNum(data.honeypots_24h ?? 0));
    setText('kpi-blacklist-count', fmtNum(data.total_blacklist ?? 0));
    setText('kpi-errors-24h', fmtNum(data.errors_24h ?? 0));

    // Tendances
    if (trends) {
        renderTrend('trend-req', trends.delta_req);
        renderTrend('trend-hp', trends.delta_hp);
        renderTrend('trend-err', trends.delta_err);
    }

    // Top IPs
    const ipsEl = document.getElementById('table-ips');
    const badgeIps = document.getElementById('badge-ips');
    if (data.top_ips && data.top_ips.length > 0) {
        badgeIps.textContent = data.top_ips.length;
        const max = data.top_ips[0].count;
        ipsEl.innerHTML = data.top_ips.map(ip => `
            <div class="table-row">
                <span class="tr-key">${escHtml(ip.ip)}</span>
                <div class="tr-bar-wrap">
                    <div class="tr-bar" style="width:${Math.round(ip.count/max*100)}%"></div>
                    <span class="tr-val">${fmtNum(ip.count)}</span>
                </div>
            </div>
        `).join('');
    } else {
        ipsEl.innerHTML = '<div class="table-loading">Aucune donnée</div>';
    }

    // Top paths
    const pathsEl = document.getElementById('table-paths');
    const badgePaths = document.getElementById('badge-paths');
    if (data.top_paths && data.top_paths.length > 0) {
        badgePaths.textContent = data.top_paths.length;
        const max = data.top_paths[0].count;
        pathsEl.innerHTML = data.top_paths.map(p => `
            <div class="table-row">
                <span class="tr-key">${escHtml(p.path)}</span>
                <div class="tr-bar-wrap">
                    <div class="tr-bar" style="width:${Math.round(p.count/max*100)}%"></div>
                    <span class="tr-val">${fmtNum(p.count)}</span>
                </div>
            </div>
        `).join('');
    } else {
        pathsEl.innerHTML = '<div class="table-loading">Aucune donnée</div>';
    }

    renderChart(data.events_by_hour || []);

    // Recent events
    const reList = document.getElementById('re-list');
    if (data.recent_events && data.recent_events.length > 0) {
        reList.innerHTML = data.recent_events.map(e => `
            <div class="re-item">
                <span class="re-time">${formatTime(e.created_at)}</span>
                <span class="re-ip">${escHtml(e.ip)}</span>
                <span class="re-method">${escHtml(e.method)}</span>
                <span class="re-path">${escHtml(e.path)}</span>
                <span class="re-status ${statusClass(e.status)}">${e.status}</span>
                <span class="ev-type ev-type--${e.event_type}">${e.event_type}</span>
            </div>
        `).join('');
    } else {
        reList.innerHTML = '<div class="table-loading">Aucun événement récent</div>';
    }
}

function renderTrend(id, delta) {
    const el = document.getElementById(id);
    if (!el || delta === undefined) return;
    if (delta === 0) {
        el.textContent = '→ stable';
        el.className = 'kpi-trend trend-neutral';
    } else if (delta > 0) {
        el.textContent = `↑ +${delta.toFixed(1)}%`;
        el.className = 'kpi-trend trend-up';
    } else {
        el.textContent = `↓ ${delta.toFixed(1)}%`;
        el.className = 'kpi-trend trend-down';
    }
}

// ══════════════════════════════════════════
//  GRAPHIQUE TRAFIC
// ══════════════════════════════════════════

let chartInstance = null;

function renderChart(hourData) {
    const canvas = document.getElementById('trafficChart');
    if (!canvas) return;

    const hours = Array.from({ length: 24 }, (_, i) => i);
    const counts = hours.map(h => {
        const found = hourData.find(d => d.hour === h);
        return found ? found.count : 0;
    });

    const total = counts.reduce((a, b) => a + b, 0);
    const chartTotalEl = document.getElementById('chart-total');
    if (chartTotalEl) chartTotalEl.textContent = `${fmtNum(total)} requêtes`;

    if (chartInstance) chartInstance.destroy();
    chartInstance = new BarChart(canvas.getContext('2d'), hours, counts, {
        color: 'rgba(0,245,160,',
        labelEvery: 4,
        labelFormat: h => `${String(h).padStart(2,'0')}h`
    });
}

// ══════════════════════════════════════════
//  GRAPHIQUE USER AGENTS (donut)
// ══════════════════════════════════════════

let agentChartInstance = null;

function renderAgentChart(agents) {
    const canvas = document.getElementById('agentsChart');
    if (!canvas || !agents.length) return;

    const colors = [
        'rgba(0,245,160,', 'rgba(0,200,245,', 'rgba(245,160,0,',
        'rgba(168,85,247,', 'rgba(245,80,80,', 'rgba(122,144,160,'
    ];

    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);

    const W = rect.width;
    const H = rect.height;
    const cx = W * 0.28;
    const cy = H / 2;
    const r = Math.min(cx - 10, cy - 20);
    const total = agents.reduce((s, a) => s + a.count, 0);

    ctx.clearRect(0, 0, W, H);

    let startAngle = -Math.PI / 2;
    agents.forEach((a, i) => {
        const slice = (a.count / total) * Math.PI * 2;
        const color = colors[i % colors.length];

        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, r, startAngle, startAngle + slice);
        ctx.closePath();
        ctx.fillStyle = color + '0.8)';
        ctx.fill();
        ctx.strokeStyle = 'rgba(8,11,15,0.6)';
        ctx.lineWidth = 2;
        ctx.stroke();

        startAngle += slice;
    });

    // Donut hole
    ctx.beginPath();
    ctx.arc(cx, cy, r * 0.55, 0, Math.PI * 2);
    ctx.fillStyle = '#080b0f';
    ctx.fill();

    // Total au centre
    ctx.fillStyle = 'rgba(232,240,248,0.9)';
    ctx.font = `bold 18px "Syne", sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(fmtNum(total), cx, cy - 8);
    ctx.fillStyle = 'rgba(122,144,160,0.8)';
    ctx.font = `10px "DM Mono", monospace`;
    ctx.fillText('requêtes', cx, cy + 10);

    // Légende
    const legendX = W * 0.58;
    const legendStartY = H / 2 - (agents.length * 26) / 2;
    agents.forEach((a, i) => {
        const color = colors[i % colors.length];
        const y = legendStartY + i * 28;

        ctx.fillStyle = color + '0.8)';
        ctx.fillRect(legendX, y, 12, 12);

        ctx.fillStyle = 'rgba(232,240,248,0.9)';
        ctx.font = `bold 12px "Syne", sans-serif`;
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        ctx.fillText(a.agent, legendX + 18, y + 6);

        ctx.fillStyle = 'rgba(0,245,160,0.8)';
        ctx.font = `10px "DM Mono", monospace`;
        ctx.fillText(`${fmtNum(a.count)} (${Math.round(a.count/total*100)}%)`, legendX + 18, y + 18);
    });
}

// ══════════════════════════════════════════
//  RENDU ÉVÉNEMENTS
// ══════════════════════════════════════════

function renderEvents(events) {
    const tbody = document.getElementById('events-tbody');
    if (!events || events.length === 0) {
        tbody.innerHTML = '<div class="table-loading">Aucun événement trouvé</div>';
        return;
    }
    tbody.innerHTML = events.map(e => `
        <div class="event-row">
            <span>${formatTime(e.created_at)}</span>
            <span>${escHtml(e.ip)}</span>
            <span>${escHtml(e.method)}</span>
            <span class="ev-path">${escHtml(e.path)}</span>
            <span class="${statusClass(e.status)}">${e.status}</span>
            <span><span class="ev-type ev-type--${e.event_type}">${e.event_type}</span></span>
        </div>
    `).join('');
}

// ══════════════════════════════════════════
//  RENDU BLACKLIST
// ══════════════════════════════════════════

function renderBlacklist(list) {
    const tbody = document.getElementById('blacklist-tbody');
    if (!list || list.length === 0) {
        tbody.innerHTML = '<div class="bl-empty"><span>✓</span> Aucune IP blacklistée actuellement</div>';
        return;
    }
    tbody.innerHTML = list.map(b => `
        <div class="blacklist-row">
            <span class="bl-ip">${escHtml(b.ip)}</span>
            <span class="bl-reason">${escHtml(b.reason)}</span>
            <span>${formatDate(b.created_at)}</span>
            <span>${formatDate(b.expires_at)}</span>
        </div>
    `).join('');
}

// ══════════════════════════════════════════
//  RENDU USER AGENTS
// ══════════════════════════════════════════

function renderAgents(agents) {
    const grid = document.getElementById('agents-grid');
    if (!agents || agents.length === 0) {
        grid.innerHTML = '<div class="table-loading">Aucune donnée</div>';
        return;
    }

    const total = agents.reduce((s, a) => s + a.count, 0);
    const colors = ['#00f5a0', '#00c8f5', '#f5a000', '#a855f7', '#f55050', '#7a90a0'];

    grid.innerHTML = agents.map((a, i) => `
        <div class="agent-card">
            <div class="agent-top">
                <span class="agent-dot" style="background:${colors[i % colors.length]}"></span>
                <span class="agent-name">${escHtml(a.agent)}</span>
                <span class="agent-count">${fmtNum(a.count)}</span>
            </div>
            <div class="agent-bar-wrap">
                <div class="agent-bar">
                    <div class="agent-fill" style="width:${Math.round(a.count/total*100)}%; background:${colors[i % colors.length]}"></div>
                </div>
                <span class="agent-pct">${Math.round(a.count/total*100)}%</span>
            </div>
        </div>
    `).join('');

    renderAgentChart(agents);
}

// ══════════════════════════════════════════
//  RENDU ERREURS
// ══════════════════════════════════════════

function renderErrors(errors) {
    const tbody = document.getElementById('errors-tbody');
    if (!errors || errors.length === 0) {
        tbody.innerHTML = '<div class="table-loading">Aucune erreur — tout va bien ✓</div>';
        return;
    }

    const max = errors[0].count;
    tbody.innerHTML = errors.map(e => {
        const level = e.status >= 500 ? 'danger' : e.status >= 400 ? 'warn' : 'ok';
        return `
            <div class="error-row">
                <span class="er-path">${escHtml(e.path)}</span>
                <span class="er-status ev-status-${level === 'danger' ? 'err' : level === 'warn' ? 'warn' : 'ok'}">${e.status}</span>
                <div class="tr-bar-wrap">
                    <div class="tr-bar tr-bar--${level}" style="width:${Math.round(e.count/max*100)}%"></div>
                    <span class="tr-val">${fmtNum(e.count)}x</span>
                </div>
                <span class="er-level er-level--${level}">${level === 'danger' ? 'Critique' : level === 'warn' ? 'Attention' : 'OK'}</span>
            </div>
        `;
    }).join('');
}

// ══════════════════════════════════════════
//  CHART CLASS
// ══════════════════════════════════════════

class BarChart {
    constructor(ctx, labels, data, opts = {}) {
        this.ctx = ctx;
        this.labels = labels;
        this.data = data;
        this.opts = opts;
        this.canvas = ctx.canvas;
        this._destroyed = false;
        this.draw();
        this._resizeHandler = () => this.draw();
        window.addEventListener('resize', this._resizeHandler);
    }

    destroy() {
        this._destroyed = true;
        window.removeEventListener('resize', this._resizeHandler);
    }

    draw() {
        if (this._destroyed) return;
        const { ctx, labels, data, canvas, opts } = this;
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);

        const W = rect.width;
        const H = rect.height;
        const pad = { top: 10, right: 10, bottom: 24, left: 32 };
        const chartW = W - pad.left - pad.right;
        const chartH = H - pad.top - pad.bottom;
        const max = Math.max(...data, 1);
        const barW = chartW / data.length;
        const color = opts.color || 'rgba(0,245,160,';

        ctx.clearRect(0, 0, W, H);

        // Grille + valeurs axe Y
        ctx.strokeStyle = 'rgba(255,255,255,0.05)';
        ctx.lineWidth = 1;
        ctx.fillStyle = 'rgba(122,144,160,0.6)';
        ctx.font = `9px "DM Mono", monospace`;
        ctx.textAlign = 'right';
        for (let i = 0; i <= 4; i++) {
            const y = pad.top + (chartH / 4) * i;
            ctx.beginPath();
            ctx.moveTo(pad.left, y);
            ctx.lineTo(pad.left + chartW, y);
            ctx.stroke();
            if (i < 4) {
                ctx.fillText(fmtNum(Math.round(max * (1 - i/4))), pad.left - 3, y + 4);
            }
        }

        // Barres
        data.forEach((val, i) => {
            const x = pad.left + i * barW;
            const barH = val === 0 ? 0 : Math.max(2, (val / max) * chartH);
            const y = pad.top + chartH - barH;
            const grad = ctx.createLinearGradient(0, y, 0, y + barH);
            grad.addColorStop(0, color + '0.9)');
            grad.addColorStop(1, color + '0.2)');
            ctx.fillStyle = grad;
            ctx.fillRect(x + 1, y, barW - 2, barH);
        });

        // Labels
        ctx.fillStyle = 'rgba(122,144,160,0.8)';
        ctx.font = `9px "DM Mono", monospace`;
        ctx.textAlign = 'center';
        const every = opts.labelEvery || 4;
        const fmt = opts.labelFormat || (v => v);
        labels.forEach((h, i) => {
            if (h % every === 0) {
                ctx.fillText(fmt(h), pad.left + i * barW + barW / 2, H - 4);
            }
        });
    }
}

// ══════════════════════════════════════════
//  RECHERCHE ÉVÉNEMENTS
// ══════════════════════════════════════════

let searchTimeout = null;
let currentFilter = '';

document.getElementById('eventSearch')?.addEventListener('input', (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
        loadEvents(currentFilter, e.target.value);
    }, 300);
});

// ── Filtres événements ──
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.type;
        const search = document.getElementById('eventSearch')?.value || '';
        loadEvents(currentFilter, search);
    });
});

// ══════════════════════════════════════════
//  NAVIGATION SECTIONS
// ══════════════════════════════════════════

function loadSectionData(section) {
    switch (section) {
        case 'overview':  loadStats(); break;
        case 'events':    loadEvents(); break;
        case 'blacklist': loadBlacklist(); break;
        case 'traffic':   loadStats(); break;
        case 'agents':    loadAgents(); break;
        case 'errors':    loadErrors(); break;
        case 'metrics': loadMetrics(); break;
        case 'score':   break;
    }
}

async function loadMetrics() {
    try {
        const res = await fetch('/api/metrics');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        renderMetrics(data);
    } catch (err) {
        console.error('loadMetrics error:', err);
    }
}

function renderMetrics(data) {
    setText('met-goroutines', data.goroutines ?? '—');
    setText('met-alloc', `${(data.alloc_mb ?? 0).toFixed(2)} MB`);
    setText('met-uptime', data.uptime ?? '—');
    setText('met-gc', data.gc_cycles ?? '—');
    setText('met-goversion', data.go_version ?? '—');
    setText('met-goos', data.goos ?? '—');
    setText('met-goarch', data.goarch ?? '—');
    setText('met-sys', `${(data.sys_mb ?? 0).toFixed(2)} MB`);
    setText('met-total', `${(data.total_alloc_mb ?? 0).toFixed(2)} MB`);
}

// ── Bouton refresh ──
document.getElementById('refreshBtn')?.addEventListener('click', () => {
    const btn = document.getElementById('refreshBtn');
    btn.classList.add('loading');
    const activeSection = document.querySelector('.nav-item.active')?.dataset.section || 'overview';
    Promise.resolve(loadSectionData(activeSection)).finally(() => {
        setTimeout(() => btn.classList.remove('loading'), 500);
    });
});

// ── Auto-refresh toutes les 15 secondes ──
setInterval(() => {
    const activeSection = document.querySelector('.nav-item.active')?.dataset.section;
    if (activeSection) loadSectionData(activeSection);
}, 15000);

// ══════════════════════════════════════════
//  UTILS
// ══════════════════════════════════════════

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function fmtNum(n) {
    if (n === undefined || n === null) return '0';
    return Number(n).toLocaleString('fr-FR');
}

function escHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function formatTime(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDate(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function statusClass(status) {
    if (status >= 200 && status < 300) return 'ev-status-ok';
    if (status >= 400 && status < 500) return 'ev-status-warn';
    return 'ev-status-err';
}

// ── Init ──
loadStats();