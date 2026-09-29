const SAMPLES = {
    cisco: `%ASA-6-302013: Built outbound TCP connection 12345 for outside:203.0.113.5/80 (203.0.113.5/80) to inside:10.0.0.100/54321 (10.0.0.100/54321)`,
    palo: `1705310200,002201234567,TRAFFIC,end,2049,2024/01/15 10:30:00,192.168.1.10,8.8.8.8,0.0.0.0,0.0.0.0,Allow-All,jdoe,,,ssl,vsys1,trust,untrust,ae1.100,ae2,Panorama-log,2024/01/15 10:30:01,12345,1,54321,443,0,0,0x400000,tcp,allow,1024,512,512,5,2024/01/15 10:30:00,60,any,0,1234567890,0x0,US,US,0,3,2,tcp-fin,CORP,jdoe,0,1,2,N/A,0,0,0,0,GlobalProtect`,
    cef: `CEF:0|Cisco|ASA|9.14|106023|Deny tcp|5|src=203.0.113.5 spt=12345 dst=10.0.0.100 dpt=443 proto=TCP act=Deny msg=Deny by access-group deviceExternalId=ASA-01`,
    syslog: `<134>Jan 15 10:30:00 router01 kernel: eth0: 1000Mbps link up`,
    fortigate: `date=2024-01-15 time=10:30:00 devname=FGT60E devid=FGT60E1234567890 logid=0000000013 type=traffic subtype=forward level=notice vd=root srcip=192.168.1.10 srcport=54321 srcintf=port1 dstip=8.8.8.8 dstport=53 dstintf=wan1 proto=17 action=accept policyid=1 service=DNS sentbyte=120 rcvdbyte=200`,
    json: `{"timestamp": "2024-01-15T10:30:00Z", "source_ip": "192.168.1.50", "dest_ip": "10.0.0.1", "action": "blocked", "reason": "policy violation", "user": "badactor", "port": 8080, "protocol": "http"}`
};

window.loadIngest = async function() {
    const container = document.getElementById('page-ingest');
    
    let sourceOptions = '<option value="">Auto-detect (Universal)</option>';
    const sourcesRes = await api('/sources');
    const sourcesList = Array.isArray(sourcesRes) ? sourcesRes : (sourcesRes && sourcesRes.sources ? sourcesRes.sources : []);
    sourcesList.forEach(s => {
        sourceOptions += `<option value="${s.source_id}">${s.source_id}</option>`;
    });

    container.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <div>
                <h2>Universal Log Ingest & Semantic Normalization Tester</h2>
                <p style="color: var(--text-secondary); margin: 0; font-size: 0.9em;">
                    Test raw log parsing across all formats (JSON, Syslog, CEF, LEEF, Cisco, Fortinet, Palo Alto, CSV) with lossless raw preservation and universal outcome classification.
                </p>
            </div>
        </div>

        <div class="grid" style="grid-template-columns: 2fr 1fr; gap: 20px;">
            <div class="card">
                <div style="display:flex; gap:10px; margin-bottom:12px;">
                    <select id="ingest-source" style="flex:1;">${sourceOptions}</select>
                    <input type="text" id="ingest-ip" placeholder="Source IP (e.g. 192.168.1.1)" style="flex:1;">
                </div>
                <label style="font-weight: 600; display: block; margin-bottom: 6px;">Raw Log Input:</label>
                <textarea id="ingest-log" rows="8" style="width:100%; box-sizing:border-box; font-family:monospace; font-size: 0.9em;" placeholder="Paste single or multi-line logs here..."></textarea>
                <div style="margin-top:12px; display:flex; gap:10px;">
                    <button class="primary" id="ingest-btn" style="padding: 9px 18px; font-weight: 600;">⚡ Ingest Log</button>
                    <button id="batch-ingest-btn" style="padding: 9px 18px;">Batch Ingest (Line by Line)</button>
                    <button onclick="document.getElementById('ingest-log').value = ''" style="padding: 9px 14px;">Clear</button>
                </div>
                
                <div id="ingest-result" style="margin-top:20px; display:none;">
                    <h3>Pipeline Normalization Result</h3>
                    <div id="ingest-result-content"></div>
                </div>
            </div>
            
            <div class="card">
                <h3>Pre-loaded Vendor Samples</h3>
                <p style="font-size: 0.85em; color: var(--text-secondary); margin-top: 0;">Click any preset to load real-world perimeter telemetry:</p>
                <div style="display:flex; flex-direction:column; gap:8px;">
                    <button onclick="loadSample('cisco')">🔹 Cisco ASA Firewall (Built Connection)</button>
                    <button onclick="loadSample('palo')">🔹 Palo Alto PAN-OS (Traffic Allow)</button>
                    <button onclick="loadSample('cef')">🔹 ArcSight CEF (Deny Packet)</button>
                    <button onclick="loadSample('fortigate')">🔹 FortiGate FortiOS (Accept Traffic)</button>
                    <button onclick="loadSample('syslog')">🔹 Linux Kernel Syslog (RFC 3164)</button>
                    <button onclick="loadSample('json')">🔹 JSON Stream (Blocked Action)</button>
                </div>
            </div>
        </div>
    `;

    window.loadSample = function(key) {
        if (SAMPLES[key]) {
            document.getElementById('ingest-log').value = SAMPLES[key];
        }
    };

    document.getElementById('ingest-btn').onclick = async () => {
        const log = document.getElementById('ingest-log').value.trim();
        if (!log) return;
        await doIngest([log]);
    };

    document.getElementById('batch-ingest-btn').onclick = async () => {
        const log = document.getElementById('ingest-log').value;
        if (!log) return;
        const lines = log.split('\n').map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('#'));
        await doIngest(lines);
    };

    async function doIngest(logs) {
        const source_id = document.getElementById('ingest-source').value || 'auto';
        const source_ip = document.getElementById('ingest-ip').value || '127.0.0.1';
        
        const resDiv = document.getElementById('ingest-result');
        const resContent = document.getElementById('ingest-result-content');
        resDiv.style.display = 'block';
        resContent.innerHTML = '<div style="padding: 15px; color: var(--accent);">Processing log through ULPF pipeline...</div>';

        try {
            let resultsHtml = '';
            for (let line of logs) {
                const response = await fetch(`${API_BASE}/ingest`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ raw_log: line, source_id, source_ip })
                });

                if (!response.ok) {
                    const err = await response.json().catch(() => ({}));
                    resultsHtml += `
                        <div style="padding:12px; border:1px solid var(--danger); margin-bottom:10px; border-radius:6px; background: rgba(248,81,73,0.1);">
                            <p style="color: var(--danger); font-weight: bold; margin: 0;">Ingestion Error: ${err.detail || response.statusText}</p>
                        </div>
                    `;
                    continue;
                }

                const data = await response.json();
                const isQuarantined = data.status === 'quarantined_dlq';
                const statusBadge = isQuarantined 
                    ? '<span class="badge" style="background: var(--danger); color: white;">⚠️ Quarantined in DLQ</span>' 
                    : '<span class="badge" style="background: var(--success); color: white;">✓ Normalized UES</span>';

                resultsHtml += `
                    <div style="padding:14px; border:1px solid var(--border); margin-bottom:12px; border-radius:6px; background: var(--bg-card);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <div>
                                <span style="font-weight: 600; font-size: 0.95em;">Event ID:</span> 
                                <code style="color: var(--accent);">${data.id || 'N/A'}</code>
                            </div>
                            <div>${statusBadge}</div>
                        </div>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px; font-size: 0.9em; margin-bottom: 10px;">
                            <div><b>Parser Plugin:</b> <code>${data.parser_plugin || 'Unknown'}</code></div>
                            <div><b>Confidence:</b> <b>${((data.confidence || 0) * 100).toFixed(0)}%</b></div>
                            <div><b>Action / Decision:</b> <code>${data.event_action || 'N/A'}</code></div>
                            <div><b>Universal Outcome:</b> ${outcomeBadge(data.event_outcome)}</div>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border); padding-top: 8px; font-size: 0.85em;">
                            <span style="color: var(--text-secondary);">SHA-256: <code style="font-size: 0.85em;">${data.raw_hash ? data.raw_hash.substring(0, 16) + '...' : 'N/A'}</code></span>
                            <a href="#events" onclick="setTimeout(()=>window.openEventModal('${data.id}'), 400)" style="color: var(--accent); text-decoration: none; font-weight: 600;">
                                🔍 Inspect Full Investigation View →
                            </a>
                        </div>
                    </div>
                `;
            }
            resContent.innerHTML = resultsHtml;
        } catch (e) {
            resContent.innerHTML = `<p style="color:var(--danger)">Ingest request failed: ${e.message}</p>`;
        }
    }
};
