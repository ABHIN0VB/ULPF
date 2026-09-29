window.loadOverview = async function() {
    const container = document.getElementById('page-overview');
    container.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <h2>System Overview & Analytics</h2>
            <button onclick="window.loadOverview()" style="padding: 6px 14px;">🔄 Refresh</button>
        </div>

        <!-- Core Telemetry Stat Cards -->
        <div class="grid" id="overview-stats"></div>

        <!-- Section 13: Data Quality & Pipeline Health Cards -->
        <h3 style="margin-top: 25px; margin-bottom: 10px; color: var(--accent);">🛡️ Data Quality & Pipeline Health (Section 13)</h3>
        <div class="grid" id="quality-stats"></div>

        <div class="grid" style="margin-top: 20px;">
            <div class="card">
                <h3>Events by Outcome</h3>
                <canvas id="outcomeChart" height="220"></canvas>
            </div>
            <div class="card">
                <h3>Events by Source Device</h3>
                <canvas id="sourceChart" height="220"></canvas>
            </div>
        </div>

        <div class="grid" style="margin-top: 20px;">
            <div class="card">
                <h3>Events by Parser Engine</h3>
                <canvas id="parserChart" height="220"></canvas>
            </div>
            <div class="card">
                <h3>Pipeline Health Distribution</h3>
                <canvas id="healthDistChart" height="220"></canvas>
            </div>
        </div>

        <div class="card" style="margin-top: 25px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                <h3>Recent Normalized Telemetry</h3>
                <a href="#events" style="color: var(--accent); text-decoration: none; font-size: 0.9em;">View All In Search →</a>
            </div>
            <div id="overview-recent" style="overflow-x: auto;"></div>
        </div>
    `;

    const data = await api('/stats');
    if (!data) {
        document.getElementById('overview-stats').innerHTML = '<p>Failed to load statistics from API.</p>';
        return;
    }

    const totalEvents = data.total_events || 0;
    const totalRaw = data.total_raw_events || totalEvents;
    const dlqCount = data.dlq_quarantine_count || 0;
    const dupCount = data.duplicate_count || 0;
    const sourcesCount = (data.sources && data.sources.length) || 0;
    const parsersCount = (data.events_by_parser && Object.keys(data.events_by_parser).length) || 0;

    const dq = data.data_quality || {
        parse_success_rate: 1.0,
        schema_validation_rate: 1.0,
        avg_field_completeness: 0.85,
        duplicate_rate: 0.0,
        failure_rate: 0.0
    };

    // 1. Render Core Metrics
    document.getElementById('overview-stats').innerHTML = `
        <div class="card stat-card">
            <h3>Normalized Events</h3>
            <div class="value" style="color: var(--accent);">${totalEvents}</div>
        </div>
        <div class="card stat-card">
            <h3>Raw Events Stored</h3>
            <div class="value">${totalRaw}</div>
        </div>
        <div class="card stat-card">
            <h3>Active Sources</h3>
            <div class="value">${sourcesCount}</div>
        </div>
        <div class="card stat-card">
            <h3>Parsers Active</h3>
            <div class="value">${parsersCount || 11}</div>
        </div>
    `;

    // 2. Render Data Quality Cards
    const parseRatePct = (dq.parse_success_rate * 100).toFixed(1) + '%';
    const schemaRatePct = (dq.schema_validation_rate * 100).toFixed(1) + '%';
    const completenessPct = (dq.avg_field_completeness * 100).toFixed(1) + '%';

    document.getElementById('quality-stats').innerHTML = `
        <div class="card stat-card" style="border-left: 4px solid var(--success);">
            <h3>Parse Success Rate</h3>
            <div class="value" style="color: var(--success);">${parseRatePct}</div>
        </div>
        <div class="card stat-card" style="border-left: 4px solid var(--accent);">
            <h3>Schema Valid Rate</h3>
            <div class="value" style="color: var(--accent);">${schemaRatePct}</div>
        </div>
        <div class="card stat-card" style="border-left: 4px solid #58a6ff);">
            <h3>Field Completeness</h3>
            <div class="value" style="color: #58a6ff;">${completenessPct}</div>
        </div>
        <div class="card stat-card" style="border-left: 4px solid ${dlqCount > 0 ? 'var(--danger)' : 'var(--border)'};">
            <h3>DLQ Quarantined</h3>
            <div class="value" style="color: ${dlqCount > 0 ? 'var(--danger)' : 'var(--text-secondary)'};">
                <a href="#dlq" style="color: inherit; text-decoration: none;">${dlqCount}</a>
            </div>
        </div>
        <div class="card stat-card" style="border-left: 4px solid ${dupCount > 0 ? 'var(--warning)' : 'var(--border)'};">
            <h3>Deduplicated</h3>
            <div class="value" style="color: ${dupCount > 0 ? 'var(--warning)' : 'var(--text-secondary)'};">${dupCount}</div>
        </div>
    `;

    // 3. Render Outcome Donut Chart
    const outcomes = data.events_by_outcome || { success: 0, failure: 0, unknown: 0 };
    new Chart(document.getElementById('outcomeChart'), {
        type: 'doughnut',
        data: {
            labels: ['Success (Permit/Allow)', 'Failure (Deny/Drop)', 'Informational / Unknown'],
            datasets: [{
                data: [outcomes.success || 0, outcomes.failure || 0, outcomes.unknown || 0],
                backgroundColor: ['#3fb950', '#f85149', '#8b949e'],
                borderColor: '#161b22',
                borderWidth: 2
            }]
        },
        options: { plugins: { legend: { position: 'bottom', labels: { color: '#e6edf3' } } } }
    });

    // 4. Render Source Bar Chart
    const sourceLabels = [];
    const sourceCounts = [];
    if (data.sources) {
        data.sources.forEach(s => {
            sourceLabels.push(s.source_id);
            sourceCounts.push(s.event_count);
        });
    }

    new Chart(document.getElementById('sourceChart'), {
        type: 'bar',
        data: {
            labels: sourceLabels.length ? sourceLabels : ['None'],
            datasets: [{
                label: 'Events Ingested',
                data: sourceCounts.length ? sourceCounts : [0],
                backgroundColor: '#00d4aa',
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
                y: { ticks: { color: '#8b949e' }, grid: { display: false } }
            }
        }
    });

    // 5. Render Parser Distribution Pie Chart
    const parsers = data.events_by_parser || {};
    new Chart(document.getElementById('parserChart'), {
        type: 'pie',
        data: {
            labels: Object.keys(parsers).length ? Object.keys(parsers) : ['Standard'],
            datasets: [{
                data: Object.values(parsers).length ? Object.values(parsers) : [1],
                backgroundColor: ['#58a6ff', '#00d4aa', '#d29922', '#f85149', '#a5d6ff', '#bc8cff', '#79c0ff']
            }]
        },
        options: { plugins: { legend: { position: 'bottom', labels: { color: '#e6edf3' } } } }
    });

    // 6. Pipeline Health Ratio Donut Chart
    new Chart(document.getElementById('healthDistChart'), {
        type: 'doughnut',
        data: {
            labels: ['Healthy Normalized', 'DLQ Quarantined', 'Deduplicated'],
            datasets: [{
                data: [totalEvents, dlqCount, dupCount],
                backgroundColor: ['#3fb950', '#f85149', '#d29922'],
                borderColor: '#161b22',
                borderWidth: 2
            }]
        },
        options: { plugins: { legend: { position: 'bottom', labels: { color: '#e6edf3' } } } }
    });

    // 7. Recent Events Table
    const recent = await api('/events?limit=8');
    const recentEvents = Array.isArray(recent) ? recent : (recent && recent.events ? recent.events : []);
    
    if (recentEvents.length > 0) {
        let html = `<table><thead><tr>
            <th>Processed At</th>
            <th>Source ID</th>
            <th>Parser Plugin</th>
            <th>Src IP</th>
            <th>Dst IP</th>
            <th>Protocol</th>
            <th>Action</th>
            <th>Outcome</th>
            <th>Completeness</th>
        </tr></thead><tbody>`;

        recentEvents.forEach(e => {
            const comp = ((e.field_completeness || 0.8) * 100).toFixed(0) + '%';
            html += `<tr style="cursor: pointer;" onclick="openEventModal('${e.id}')">
                <td>${formatDate(e.processed_at)}</td>
                <td><span style="font-weight: 600;">${e.source_id || ''}</span></td>
                <td><code>${e.parser_plugin || ''}</code></td>
                <td>${e.src_ip || '—'}</td>
                <td>${e.dst_ip || '—'}</td>
                <td>${(e.protocol || 'tcp').toUpperCase()}</td>
                <td>${e.event_action || '—'}</td>
                <td>${outcomeBadge(e.event_outcome)}</td>
                <td><span style="color: var(--accent); font-weight: 600;">${comp}</span></td>
            </tr>`;
        });
        html += '</tbody></table>';
        document.getElementById('overview-recent').innerHTML = html;
    } else {
        document.getElementById('overview-recent').innerHTML = '<p style="color: var(--text-secondary);">No recent telemetry available.</p>';
    }
};
