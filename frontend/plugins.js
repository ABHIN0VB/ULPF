window.loadPlugins = async function() {
    const container = document.getElementById('page-plugins');
    
    const res = await api('/plugins');
    let pluginsHtml = '';
    
    if (res && res.plugins) {
        res.plugins.forEach(p => {
            pluginsHtml += `
                <div class="card">
                    <div style="display:flex; justify-content:space-between;">
                        <h3>${p.name} <span class="badge success">Active</span></h3>
                        <span class="badge info">Priority: ${p.priority || 1}</span>
                    </div>
                    <p><strong>Source ID:</strong> ${p.source_id || '*'}</p>
                    <p style="color: var(--text-secondary);">${p.description || 'No description'}</p>
                </div>
            `;
        });
    }

    container.innerHTML = `
        <h2>Plugin Manager</h2>
        
        <div class="grid" style="grid-template-columns: 1fr 1fr;">
            <div>
                <h3>Installed Plugins</h3>
                <div style="display:flex; flex-direction:column; gap:10px;">
                    ${pluginsHtml || '<p>No plugins loaded.</p>'}
                </div>
            </div>
            
            <div>
                <div class="card">
                    <h3>Upload Plugin</h3>
                    <input type="file" id="plugin-file" accept=".py">
                    <button class="primary" id="upload-btn">Upload</button>
                    <p id="upload-msg" style="margin-top:10px;"></p>
                </div>
                
                <div class="card">
                    <h3>Test Log Parse</h3>
                    <textarea id="test-log" rows="6" style="width:100%; box-sizing:border-box;" placeholder="Paste raw log string here..."></textarea>
                    <button class="primary" id="test-btn">Test Parse</button>
                    <div id="test-result" style="margin-top: 15px;"></div>
                </div>
            </div>
        </div>
    `;

    document.getElementById('test-btn').onclick = async () => {
        const log = document.getElementById('test-log').value;
        if (!log) return;
        
        document.getElementById('test-result').innerHTML = 'Testing...';
        
        try {
            const response = await fetch(`${API_BASE}/plugins/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ raw_log: log })
            });
            const data = await response.json();
            
            document.getElementById('test-result').innerHTML = `
                <h4>Result</h4>
                ${jsonViewer(data)}
            `;
        } catch (e) {
            document.getElementById('test-result').innerHTML = `<p style="color:var(--danger)">Error testing log</p>`;
        }
    };
    
    document.getElementById('upload-btn').onclick = () => {
        document.getElementById('upload-msg').innerText = "Simulated Upload Success!";
        document.getElementById('upload-msg').style.color = "var(--success)";
    };
};
