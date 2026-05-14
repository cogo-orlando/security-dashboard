// ══════════════════════════════════════════
//  SECURITY DASHBOARD — JS
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
}, { threshold: 0.1 });

document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));

// ── Chargement des données ──
async function loadStats() {
    try {
        const res = await fetch('/api/stats');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        renderStats(data);
    } catch (err) {
        console.error('loadStats error:', err);
    }
}

async function loadEvents(type = '') {
    try {
        const url = type ? `/api/events?type=${type}` : '/api/events';
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

// ── Rendu stats ──
function renderStats(data) {
    setText('kpi-total-events', data.total_events ?? 0);
    setText('kpi-events-24h', data.events_24h ?? 0);
    setText('kpi-honeypots', data.honeypots_24h ?? 0);
    setText('kpi-blacklist-count', data.total_blacklist ?? 0);

    // Top IPs
    const ipsEl = document.getElementById('table-ips');
    const badgeIps = document.getElementById('badge-ips');
    if (data.top_ips && data.top_ips.length > 0) {
        badgeIps.textContent = data.top_ips.length;
        ipsEl.innerHTML = data.top_ips.map(ip => `
            <div class="table-row">
                <span class="tr-key">${escHtml(ip.ip)}</span>
                <span class="tr-val">${ip.count} req</span>
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
        pathsEl.innerHTML = data.top_paths.map(p => `
            <div class="table-row">
                <span class="tr-key">${escHtml(p.path)}</span>
                <span class="tr-val">${p.count}</span>
            </div>
        `).join('');
    } else {
        pathsEl.innerHTML = '<div class="table-loading">Aucune donnée</div>';
    }

    // Graphique trafic par heure
    renderChart(data.events_by_hour || []);

    // Recent events (section traffic)
    const reList = document.getElementById('re-list');
    if (data.recent_events && data.recent_events.length > 0) {
        reList.innerHTML = data.recent_events.map(e => `
            <div class="re-item">
                <span class="re-time">${formatTime(e.created_at)}</span>
                <span class="re-ip">${escHtml(e.ip)}</span>
                <span class="re-method">${escHtml(e.method)}</span>
                <span class="re-path">${escHtml(e.path)}</span>
                <span class="re-status ${statusClass(e.status)}">${e.status}</span>
            </div>
        `).join('');
    } else {
        reList.innerHTML = '<div class="table-loading">Aucun événement récent</div>';
    }
}

// ── Rendu graphique ──
let chartInstance = null;

function renderChart(hourData) {
    const canvas = document.getElementById('trafficChart');
    if (!canvas) return;

    // Construit un tableau de 24 heures
    const hours = Array.from({ length: 24 }, (_, i) => i);
    const counts = hours.map(h => {
        const found = hourData.find(d => d.hour === h);
        return found ? found.count : 0;
    });

    const total = counts.reduce((a, b) => a + b, 0);
    const chartTotalEl = document.getElementById('chart-total');
    if (chartTotalEl) chartTotalEl.textContent = `${total} requêtes`;

    const ctx = canvas.getContext('2d');

    if (chartInstance) {
        chartInstance.destroy();
    }

    chartInstance = new SimpleChart(ctx, hours, counts);
}

// ── Chart maison (pas de dépendance externe) ──
class SimpleChart {
    constructor(ctx, labels, data) {
        this.ctx = ctx;
        this.labels = labels;
        this.data = data;
        this.canvas = ctx.canvas;
        this.draw();
    }

    draw() {
        const { ctx, labels, data, canvas } = this;
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);

        const W = rect.width;
        const H = rect.height;
        const pad = { top: 10, right: 10, bottom: 24, left: 30 };
        const chartW = W - pad.left - pad.right;
        const chartH = H - pad.top - pad.bottom;

        const max = Math.max(...data, 1);
        const barW = chartW / data.length;

        ctx.clearRect(0, 0, W, H);

        // Grille horizontale
        ctx.strokeStyle = 'rgba(255,255,255,0.05)';
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
            const y = pad.top + (chartH / 4) * i;
            ctx.beginPath();
            ctx.moveTo(pad.left, y);
            ctx.lineTo(pad.left + chartW, y);
            ctx.stroke();
        }

        // Barres
        data.forEach((val, i) => {
            const x = pad.left + i * barW;
            const barH = val === 0 ? 0 : Math.max(2, (val / max) * chartH);
            const y = pad.top + chartH - barH;

            // Gradient vert
            const grad = ctx.createLinearGradient(0, y, 0, y + barH);
            grad.addColorStop(0, 'rgba(0,245,160,0.8)');
            grad.addColorStop(1, 'rgba(0,245,160,0.2)');
            ctx.fillStyle = grad;
            ctx.fillRect(x + 1, y, barW - 2, barH);
        });

        // Labels heures (chaque 4h)
        ctx.fillStyle = 'rgba(122,144,160,0.8)';
        ctx.font = `10px "DM Mono", monospace`;
        ctx.textAlign = 'center';
        labels.forEach((h, i) => {
            if (h % 4 === 0) {
                const x = pad.left + i * barW + barW / 2;
                ctx.fillText(`${String(h).padStart(2,'0')}h`, x, H - 4);
            }
        });
    }
}

// ── Rendu événements ──
function renderEvents(events) {
    const tbody = document.getElementById('events-tbody');
    if (!events || events.length === 0) {
        tbody.innerHTML = '<div class="table-loading">Aucun événement</div>';
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

// ── Rendu blacklist ──
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

// ── Navigation sections ──
function loadSectionData(section) {
    switch (section) {
        case 'overview': loadStats(); break;
        case 'events': loadEvents(); break;
        case 'blacklist': loadBlacklist(); break;
        case 'traffic': loadStats(); break;
    }
}

// ── Filtres événements ──
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        loadEvents(btn.dataset.type);
    });
});

// ── Bouton refresh ──
document.getElementById('refreshBtn')?.addEventListener('click', () => {
    const btn = document.getElementById('refreshBtn');
    btn.classList.add('loading');
    loadStats().finally(() => {
        setTimeout(() => btn.classList.remove('loading'), 500);
    });
});

// ── Auto-refresh toutes les 30 secondes ──
setInterval(() => {
    const activeSection = document.querySelector('.nav-item.active')?.dataset.section;
    if (activeSection) loadSectionData(activeSection);
}, 30000);

// ── Utils ──
function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
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
    const d = new Date(dateStr);
    return d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDate(dateStr) {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function statusClass(status) {
    if (status >= 200 && status < 300) return 'ev-status-ok';
    if (status >= 400 && status < 500) return 'ev-status-warn';
    return 'ev-status-err';
}

// ── Init ──
loadStats();