window.loadDLQ = async function() {
    const container = document.getElementById('page-dlq');
    container.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <div>
                <h2>Dead Letter Queue (DLQ / Quarantine)</h2>
                <p style="color: var(--text-secondary); margin: 0; font-size: 0.9em;">
                    Section 5 & 6: Malformed, unknown, or failed events are safely quarantined with 100% raw preservation.
                </p>
            </div>
            <div style="display: flex; gap: 8px;">
                <button onclick="reprocessAllDLQ()" style="background: var(--accent); color: #0d1117; font-weight: 600; padding: 6px 14px;">
                    ⚡ Reprocess All DLQ
                </button>
                <button onclick="window.loadDLQ()" style="padding: 6px 14px;">🔄 Refresh</button>
            </div>
        </div>

        <div class="card" style="overflow-x: auto;">
            <table id="dlq-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Source ID</th>
                        <th>Failure Reason</th>
                        <th>Stage</th>
                        <th>Parser Attempted</th>
                        <th>Retries</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>

        <div id="dlq-detail-card" class="card" style="margin-top: 20px; display: none;">
            <h3>Quarantined Event Forensics</h3>
            <div id="dlq-detail-body"></div>
        </div>
    `;

    const res = await api('/dlq?status=quarantined');
    const tbody = document.querySelector('#dlq-table tbody');
    const list = Array.isArray(res) ? res : [];

    if (list.length > 0) {
        tbody.innerHTML = '';
        list.forEach(item => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${formatDate(item.timestamp)}</td>
                <td><b>${item.source_id}</b></td>
                <td><span style="color: var(--danger); font-weight: 600;">${item.failure_reason}</span></td>
                <td><code>${item.processing_stage}</code></td>
                <td><code>${item.parser_attempted}</code></td>
                <td>${item.retry_count || 0}</td>
                <td><span class="badge" style="background: var(--danger);">${item.status}</span></td>
                <td>
                    <button onclick="inspectDLQ('${item.id}')" style="padding: 4px 8px; font-size: 0.85em; margin-right: 4px;">Inspect</button>
                    <button onclick="reprocessDLQItem('${item.id}')" style="padding: 4px 8px; font-size: 0.85em; background: var(--accent); color: #0d1117;">Reprocess</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } else {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" style="text-align: center; padding: 30px; color: var(--success); font-weight: 600;">
                    ✓ Zero Quarantined Events in DLQ. All ingested telemetry normalized successfully!
                </td>
            </tr>
        `;
    }
};

window.inspectDLQ = async function(id) {
    const item = await api('/dlq/' + id);
    if (!item) return;

    const card = document.getElementById('dlq-detail-card');
    card.style.display = 'block';

    document.getElementById('dlq-detail-body').innerHTML = `
        <div style="margin-bottom: 12px; font-size: 0.9em; line-height: 1.6;">
            <div><b>Quarantine ID:</b> <code>${item.id}</code></div>
            <div><b>Original Raw Event ID:</b> <code>${item.raw_event_id}</code></div>
            <div><b>Raw SHA-256 Hash:</b> <code>${item.raw_hash}</code></div>
            <div><b>Failure Reason:</b> <span style="color: var(--danger); font-weight: bold;">${item.failure_reason}</span></div>
            <div><b>Error Diagnostics:</b> <i>${item.error_details || 'No error details'}</i></div>
        </div>
        <label style="font-weight: 600; display: block; margin-bottom: 6px;">Quarantined Raw Event String (100% Preserved):</label>
        <div class="log-box" style="white-space: pre-wrap; font-family: monospace;">${item.raw_log}</div>
        <div style="margin-top: 15px;">
            <button onclick="reprocessDLQItem('${item.id}')" class="primary" style="padding: 8px 16px;">
                🔄 Reprocess with Updated Parsers
            </button>
        </div>
    `;
    card.scrollIntoView({ behavior: 'smooth' });
};

window.reprocessDLQItem = async function(id) {
    const res = await api('/dlq/' + id + '/reprocess', { method: 'POST' });
    if (res && res.success) {
        alert("Event recovered from DLQ successfully! Normalized using " + res.parser_plugin);
        window.loadDLQ();
    } else {
        alert("Reprocessing failed: " + (res?.message || 'No matching parser yet. Onboard new parser first.'));
    }
};

window.reprocessAllDLQ = async function() {
    if (!confirm("Attempt to reprocess all quarantined DLQ events?")) return;
    const res = await api('/dlq/reprocess-all', { method: 'POST' });
    if (res) {
        alert(`DLQ Batch Reprocess: Recovered ${res.recovered}, ${res.remaining_quarantined} remaining.`);
        window.loadDLQ();
    }
};
