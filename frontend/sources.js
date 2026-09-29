window.loadSources = async function() {
    const container = document.getElementById('page-sources');
    
    const res = await api('/sources');
    
    if (res && res.sources) {
        const total = res.sources.length;
        
        let html = `
            <h2>Sources</h2>
            <div class="card" style="margin-bottom: 20px;">
                Total Sources: <strong>${total}</strong>
            </div>
            <div class="grid">
        `;
        
        res.sources.forEach(s => {
            html += `
                <div class="card stat-card" style="cursor:pointer;" onclick="window.location.hash='#events'; setTimeout(()=> { document.querySelector('[name=source_id]').value='${s.id}'; document.getElementById('search-form').dispatchEvent(new Event('submit')); }, 200);">
                    <h3>${s.id}</h3>
                    <div style="margin: 10px 0;">
                        <span class="badge info">Events: ${s.count || 0}</span>
                    </div>
                    <p style="font-size: 0.9em; color: var(--text-secondary);">Last seen: ${formatDate(s.last_seen)}</p>
                    <p style="font-size: 0.9em;">Parser: ${s.parser || 'N/A'}</p>
                </div>
            `;
        });
        
        html += `</div>`;
        container.innerHTML = html;
    } else {
        container.innerHTML = '<h2>Sources</h2><p>Failed to load sources or no sources available.</p>';
    }
};
