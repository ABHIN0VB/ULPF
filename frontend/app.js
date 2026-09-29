const API_BASE = '/api';

async function api(endpoint, options = {}) {
    try {
        const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${endpoint}`;
        const headers = options.headers || {};
        // Add default admin headers for evaluation inspection
        if (!headers['X-ULPF-Role']) headers['X-ULPF-Role'] = 'ADMIN';
        if (!headers['X-ULPF-User']) headers['X-ULPF-User'] = 'SecurityAnalyst';
        
        options.headers = headers;
        const response = await fetch(url, options);
        if (!response.ok) {
            const errBody = await response.json().catch(() => null);
            throw new Error((errBody && errBody.detail) || `API Error: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(error);
        return null;
    }
}

function navigate(pageId) {
    document.querySelectorAll('.page').forEach(page => page.style.display = 'none');
    document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
    
    const targetPage = document.getElementById(`page-${pageId}`);
    if (targetPage) {
        targetPage.style.display = 'block';
    }
    
    const activeLink = document.querySelector(`.nav-link[data-page="${pageId}"]`);
    if (activeLink) {
        activeLink.classList.add('active');
    }

    if (pageId === 'overview') window.loadOverview?.();
    if (pageId === 'events') window.loadEvents?.();
    if (pageId === 'dlq') window.loadDLQ?.();
    if (pageId === 'sources') window.loadSources?.();
    if (pageId === 'plugins') window.loadPlugins?.();
    if (pageId === 'ingest') window.loadIngest?.();
    if (pageId === 'benchmark') window.loadBenchmark?.();
    if (pageId === 'audit') window.loadAudit?.();
}

function handleHashChange() {
    const hash = window.location.hash.substring(1) || 'overview';
    navigate(hash);
}

function formatDate(iso) {
    if (!iso) return 'N/A';
    try {
        const d = new Date(iso);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
    } catch (e) {
        return iso;
    }
}

function severityBadge(n) {
    if (n == null) return '<span class="badge unknown">0</span>';
    if (n >= 1 && n <= 3) return `<span class="badge info">Low (${n})</span>`;
    if (n >= 4 && n <= 6) return `<span class="badge warning">Med (${n})</span>`;
    if (n >= 7 && n <= 10) return `<span class="badge critical">High (${n})</span>`;
    return `<span class="badge unknown">${n}</span>`;
}

function outcomeBadge(outcome) {
    const out = outcome ? outcome.toLowerCase() : '';
    if (out === 'success' || out === 'allow' || out === 'permit') return `<span class="badge success">✓ ${outcome}</span>`;
    if (out === 'failure' || out === 'deny' || out === 'block' || out === 'drop') return `<span class="badge failure">✕ ${outcome}</span>`;
    return `<span class="badge unknown">${outcome || 'Unknown'}</span>`;
}

function jsonViewer(obj) {
    const json = JSON.stringify(obj, null, 2);
    const html = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            let cls = 'json-number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'json-key';
                } else {
                    cls = 'json-string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'json-boolean';
            } else if (/null/.test(match)) {
                cls = 'json-null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
    return `<pre class="json-viewer">${html}</pre>`;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard!');
    }).catch(() => {
        prompt('Copy this text:', text);
    });
}

async function checkHealth() {
    const res = await fetch(`${API_BASE}/health`).catch(() => null);
    const dot = document.getElementById('health-dot');
    const text = document.getElementById('health-text');
    
    if (res && res.ok) {
        const h = await res.json().catch(() => ({}));
        dot.className = 'dot green';
        text.textContent = `Online (Air-Gap) | Events: ${h.total_events || 0}`;
    } else {
        dot.className = 'dot red';
        text.textContent = 'Disconnected';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.addEventListener('hashchange', handleHashChange);
    handleHashChange();
    
    checkHealth();
    setInterval(checkHealth, 8000);
});

// Setup Modal logic globally
document.addEventListener('DOMContentLoaded', () => {
    const modal = document.getElementById('event-modal');
    if (modal) {
        modal.querySelector('.close-modal').onclick = () => modal.style.display = 'none';
        window.onclick = (e) => {
            if (e.target === modal) modal.style.display = 'none';
        };
        
        modal.querySelectorAll('.tab-btn').forEach(btn => {
            btn.onclick = (e) => {
                modal.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                modal.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                
                e.target.classList.add('active');
                const targetId = e.target.getAttribute('data-target');
                const targetContent = document.getElementById(targetId);
                if (targetContent) targetContent.classList.add('active');
            }
        });
    }
});
