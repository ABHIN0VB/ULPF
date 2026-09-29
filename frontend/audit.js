window.loadAudit = async function() {
    const container = document.getElementById('page-audit');
    container.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <div>
                <h2>Security & Administrative Audit Trail</h2>
                <p style="color: var(--text-secondary); margin: 0; font-size: 0.9em;">
                    Section 19: Cryptographically preserved log of administrative operations, plugin uploads, and event reprocessing.
                </p>
            </div>
            <button onclick="window.loadAudit()" style="padding: 6px 14px;">🔄 Refresh</button>
        </div>

        <div class="card" style="overflow-x: auto;">
            <table id="audit-table">
                <thead>
                    <tr>
                        <th>Timestamp (UTC)</th>
                        <th>User</th>
                        <th>Role</th>
                        <th>Action</th>
                        <th>Resource</th>
                        <th>Result</th>
                        <th>Source IP</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
    `;

    const res = await api('/audit-logs');
    const tbody = document.querySelector('#audit-table tbody');
    const list = Array.isArray(res) ? res : [];

    if (list.length > 0) {
        tbody.innerHTML = '';
        list.forEach(a => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${formatDate(a.timestamp)}</td>
                <td><b>${a.user}</b></td>
                <td><span class="badge" style="background: #30363d;">${a.role}</span></td>
                <td><code>${a.action}</code></td>
                <td>${a.resource}</td>
                <td><span class="badge" style="background: ${a.result === 'success' ? 'var(--success)' : 'var(--danger)'};">${a.result}</span></td>
                <td>${a.source_ip}</td>
                <td style="font-size: 0.85em; color: var(--text-secondary); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${a.details || ''}</td>
            `;
            tbody.appendChild(tr);
        });
    } else {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" style="text-align: center; padding: 25px; color: var(--text-secondary);">
                    No audit records logged yet.
                </td>
            </tr>
        `;
    }
};
