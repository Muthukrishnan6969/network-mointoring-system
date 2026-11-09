document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const tableBody = document.querySelector('#devices-table tbody');
    const trafficStream = document.getElementById('traffic-stream');
    const logDiv = document.getElementById('system-log');
    const threatGauge = document.getElementById('threat-gauge');
    const threatStatus = document.getElementById('threat-status');
    const statTotal = document.getElementById('stat-total');
    const statNew = document.getElementById('stat-new');

    const path = window.location.pathname;

    // Topology Initialization (only on topology page)
    let nodes, edges, network;
    if (document.getElementById('network-graph')) {
        const graphContainer = document.getElementById('network-graph');
        nodes = new vis.DataSet([]);
        edges = new vis.DataSet([]);
        const data = { nodes: nodes, edges: edges };
        const options = {
            nodes: {
                shape: 'dot', size: 15,
                font: { color: '#00d2ff', size: 10 },
                borderWidth: 2,
                shadow: { enabled: true, color: 'rgba(0, 210, 255, 0.5)', size: 10 },
                color: { background: '#020606', border: '#00d2ff' }
            },
            edges: {
                color: 'rgba(0, 210, 255, 0.2)', width: 1,
                arrows: { to: { enabled: true, scaleFactor: 0.5 } }
            },
            physics: { stabilization: false, barnesHut: { gravitationalConstant: -2000 } }
        };
        network = new vis.Network(graphContainer, data, options);
        nodes.add({ id: 'router', label: 'GATEWAY', color: '#ff00ff', size: 25, shadow: { color: '#ff00ff' } });
    }

    function log(msg, type = 'info') {
        if (!logDiv) return;
        const time = new Date().toLocaleTimeString();
        const div = document.createElement('div');
        div.style.color = type === 'warn' ? '#ff3e3e' : '#00f38d';
        div.innerHTML = `[${time}] ${msg}`;
        logDiv.prepend(div);
    }

    function updateStats() {
        fetch('/api/stats')
            .then(res => res.json())
            .then(stats => {
                if (statTotal) statTotal.innerText = stats.total;
                if (statNew) statNew.innerText = stats.new;

                // Dashboard specific stats
                if (document.getElementById('stat-total-2')) document.getElementById('stat-total-2').innerText = stats.total;
                if (document.getElementById('stat-threats')) document.getElementById('stat-threats').innerText = stats.threats;
                if (document.getElementById('stat-history')) document.getElementById('stat-history').innerText = stats.history_total;

                if (threatGauge) {
                    const level = (stats.threats / (stats.total || 1)) * 100;
                    threatGauge.style.width = `${Math.min(100, level + 10)}%`;
                    if (level > 50) {
                        threatStatus.innerText = "CRITICAL";
                        threatStatus.className = "warn";
                    } else {
                        threatStatus.innerText = "STABLE";
                        threatStatus.className = "";
                    }
                }
            });
    }

    function fetchTraffic() {
        if (!trafficStream) return;
        const targetMac = document.getElementById('target-selector')?.value || '';
        const url = targetMac ? `/api/traffic?mac=${targetMac}` : '/api/traffic';

        fetch(url)
            .then(res => res.json())
            .then(logs => {
                // If targeting, clear old generic results
                if (targetMac) trafficStream.classList.add('targeted');
                else trafficStream.classList.remove('targeted');

                logs.slice(0, 10).forEach(logItem => {
                    const id = `traffic-${logItem.id}`;
                    if (!document.getElementById(id)) {
                        const card = document.createElement('div');
                        card.id = id;
                        card.className = 'traffic-card';
                        card.style.borderLeft = `3px solid ${targetMac ? 'var(--neon-pink)' : 'var(--neon-blue)'}`;
                        card.innerHTML = `
                            <b>${logItem.ip_address}</b> ➔ <span style="color:#00d2ff">${logItem.domain}</span>
                            <br><small style="opacity:0.5">${new Date(logItem.timestamp).toLocaleTimeString()}</small>
                        `;
                        trafficStream.prepend(card);
                        if (trafficStream.children.length > 30) trafficStream.lastChild.remove();
                    }
                });
            });
    }

    function fetchDevices() {
        fetch('/api/devices')
            .then(res => res.json())
            .then(devices => {
                const selector = document.getElementById('target-selector');
                if (selector) {
                    const currentVal = selector.value;
                    // Keep "All" option
                    selector.innerHTML = '<option value="">ALL ENTITIES (GLOBAL STREAM)</option>';
                    devices.forEach(d => {
                        const opt = document.createElement('option');
                        opt.value = d.mac_address;
                        opt.innerText = `${d.ip_address} (${d.vendor || 'Unknown'})`;
                        if (d.mac_address === currentVal) opt.selected = true;
                        selector.appendChild(opt);
                    });
                }

                if (tableBody) {
                    tableBody.innerHTML = '';
                    devices.forEach(device => {
                        const row = document.createElement('tr');
                        const threatClass = device.threat_level !== 'Low' ? 'warn' : '';
                        row.innerHTML = `
                            <td>${device.ip_address}</td>
                            <td>${device.operating_system || 'Unknown'}<br><small>${device.vendor || 'Unknown'}</small></td>
                            <td class="${threatClass}">${device.threat_level || 'Low'}</td>
                            <td><small>${device.last_seen ? new Date(device.last_seen).toLocaleTimeString() : 'N/A'}</small></td>
                        `;
                        tableBody.appendChild(row);
                    });
                }

                // Update graph if visible
                if (nodes) {
                    const activeMacs = new Set();
                    devices.forEach(device => {
                        activeMacs.add(device.mac_address);
                        if (!nodes.get(device.mac_address)) {
                            nodes.add({
                                id: device.mac_address,
                                label: device.ip_address,
                                title: `OS: ${device.operating_system || 'Unknown'}\nVendor: ${device.vendor || 'Unknown'}`
                            });
                            edges.add({ from: 'router', to: device.mac_address });
                        } else {
                            nodes.update({
                                id: device.mac_address,
                                label: device.ip_address,
                                title: `OS: ${device.operating_system || 'Unknown'}\nVendor: ${device.vendor || 'Unknown'}`
                            });
                        }
                    });

                    // Remove nodes that are no longer online in backend
                    const allNodeIds = nodes.getIds();
                    allNodeIds.forEach(id => {
                        if (id !== 'router' && !activeMacs.has(id)) {
                            nodes.remove(id);
                        }
                    });
                }
                updateStats();
            });
    }

    if (scanBtn) {
        scanBtn.addEventListener('click', () => {
            log("Running manual deep-pulse scan...", 'info');
            fetch('/scan').then(res => res.json()).then(data => log(data.message));
        });
    }

    const selector = document.getElementById('target-selector');
    if (selector) {
        selector.addEventListener('change', () => {
            trafficStream.innerHTML = ''; // Clear stream on target switch
            fetchTraffic();
        });
    }

    // High-Frequency Live Updates
    updateStats();
    fetchDevices();
    if (path === '/surveillance') setInterval(fetchTraffic, 2000);
    setInterval(fetchDevices, 2000); // Poll every 2 seconds for live changes
});
