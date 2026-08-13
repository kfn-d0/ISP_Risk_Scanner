let portsChartInstance = null;
let currentScanData = null;
let ws = null;
let currentPage = 1;
const itemsPerPage = 50;

function escapeHTML(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/[&<>'"]/g,
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        }[tag] || tag)
    );
}

async function detectEnvironment() {
    try {
        const response = await fetch('/api/env');
        const data = await response.json();
        const badge = document.getElementById('env-badge');
        if (!badge) return;

        if (data.is_docker) {
            badge.innerHTML = '<span>Running in Docker</span>';
            badge.className = 'env-docker';
        } else {
            badge.innerHTML = '<span>Native Python (Windows)</span>';
            badge.className = 'env-windows';
        }
        badge.classList.remove('hidden');
    } catch (e) {
        console.error("Erro ao detectar ambiente:", e);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    detectEnvironment();
});

function startScan() {
    const asnInput = document.getElementById('asn-input').value;
    if (!asnInput) return;

    document.getElementById('loader').classList.remove('hidden');
    const dashboard = document.getElementById('results-dashboard');
    if (dashboard) dashboard.classList.add('hidden');

    document.getElementById('error-msg').classList.add('hidden');
    document.getElementById('mock-warning').classList.add('hidden');

    const scanBtn = document.getElementById('scan-btn');
    scanBtn.disabled = true;
    scanBtn.style.opacity = '0.7';

    document.getElementById('ws-status').textContent = "Conectando ao sistema...";

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/api/ws/analyze`;

    if (ws) ws.close();

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        ws.send(JSON.stringify({ asn: asnInput }));
    };

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);

        if (msg.type === "status") {
            document.getElementById('ws-status').textContent = msg.message;
        } else if (msg.type === "complete") {
            document.getElementById('loader').classList.add('hidden');
            scanBtn.disabled = false;
            scanBtn.style.opacity = '1';
            renderDashboard(msg.data);
            ws.close();
        } else if (msg.type === "error") {
            handleError(msg.message);
        }
    };

    ws.onerror = (error) => {
        handleError("Servidor inacessível ou conectividade recusada (WebSocket).");
    };

    ws.onclose = () => {
        if (scanBtn.disabled) {
            handleError("Conexão interrompida de forma inesperada pelo servidor.");
        }
    };
}

function handleError(msg) {
    const errDiv = document.getElementById('error-msg');
    errDiv.textContent = 'Erro ao executar o escaneamento: ' + msg;
    errDiv.classList.remove('hidden');
    document.getElementById('loader').classList.add('hidden');
    const scanBtn = document.getElementById('scan-btn');
    scanBtn.disabled = false;
    scanBtn.style.opacity = '1';
    if (ws) ws.close();
}

function renderDashboard(data) {
    currentScanData = data;
    document.getElementById('results-dashboard').classList.remove('hidden');

    if (data.raw_data && data.raw_data.some(d => d.simulated)) {
        document.getElementById('mock-warning').classList.remove('hidden');
    }

    animateValue("score-val", 0, data.metrics.total_score, 1000);
    animateValue("exposures-val", 0, data.metrics.total_exposures, 1000);
    animateValue("ips-val", 0, data.metrics.total_ips, 1000);
    document.getElementById('time-val').textContent = data.metrics.total_time_seconds + 's';

    renderChart(data.port_distribution);
    
    // Holder Info & Dorks
    if (data.asn_info) {
        document.getElementById('holder-name-display').textContent = data.asn_info.holder;
    }
    if (data.google_dorks) {
        renderDorks(data.google_dorks);
    }
    if (data.subdomains) {
        document.getElementById('subdomain-guess-display').textContent = data.domain_guess;
        renderSubdomains(data.subdomains);
    }

    populateTable('prefixes-table', data.top_prefixes, (item) => `
        <td><code style="color:var(--secondary)">${escapeHTML(item.prefix)}</code></td>
        <td style="font-weight:600">${item.score} <span style="color:var(--text-muted); font-size: 0.8em; margin-left: 5px;">pts</span></td>
    `);

    populateTable('services-table', data.top_services, (item) => `
        <td>${escapeHTML(item.service)}</td>
        <td><span style="background: rgba(0,255,136,0.1); color: var(--primary); padding: 2px 8px; border-radius: 12px">${item.count}</span></td>
    `);

    currentPage = 1;
    updateRawTable();
}

function updateRawTable() {
    if (!currentScanData || !currentScanData.raw_data) return;
    const start = (currentPage - 1) * itemsPerPage;
    const end = start + itemsPerPage;
    const paginatedData = currentScanData.raw_data.slice(start, end);

    populateTable('raw-table', paginatedData, (item) => {
        const trClass = `risk-${item.risk_level.toLowerCase()}`;
        return `
        <td>${escapeHTML(item.ip)}</td>
        <td style="font-size:0.85em; color:var(--text-muted)">${escapeHTML(item.prefix)}</td>
        <td><b>${item.port}</b></td>
        <td>${escapeHTML(item.service)}</td>
        <td class="${trClass}">${escapeHTML(item.risk_level)}</td>
        <td>
            <details style="cursor: pointer; font-size: 0.85em;">
                <summary style="outline: none; color: var(--secondary);">Detalhar</summary>
                <div style="margin-top:5px; padding:5px; background: rgba(0,0,0,0.1); border-radius:4px;">
                    ${escapeHTML(item.banner)}<br>
                    <small>Vulnerabilidades: ${item.vulns_count} | OTX Threat Intel: ${item.has_otx ? 'Sim' : 'Não'}</small>
                </div>
            </details>
        </td>
        `;
    });

    const maxPage = Math.ceil(currentScanData.raw_data.length / itemsPerPage);
    document.getElementById('page-info').textContent = `Página ${currentPage} de ${maxPage || 1}`;
    document.getElementById('prev-btn').disabled = currentPage === 1;
    document.getElementById('next-btn').disabled = currentPage >= maxPage;
}

function changePage(delta) {
    if (!currentScanData) return;
    const maxPage = Math.ceil(currentScanData.raw_data.length / itemsPerPage);
    currentPage += delta;
    if (currentPage < 1) currentPage = 1;
    if (currentPage > maxPage) currentPage = maxPage;
    updateRawTable();
}

function renderChart(portData) {
    const ctx = document.getElementById('portsChart').getContext('2d');
    if (portsChartInstance) {
        portsChartInstance.destroy();
    }
    const labels = Object.keys(portData).map(p => `Port ${p}`);
    const dataVals = Object.values(portData);
    portsChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: dataVals,
                backgroundColor: ['#ff3366', '#00ff88', '#00d2ff', '#ffaa00', '#a333ff', '#33ffaa'],
                borderColor: '#14141e',
                borderWidth: 2,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#dfdfef', font: { family: "'Outfit', sans-serif" } } }
            },
            cutout: '75%'
        }
    });
}

function populateTable(tableId, dataList, rowFormatter) {
    const tbody = document.querySelector(`#${tableId} tbody`);
    if (!tbody) return;
    tbody.innerHTML = '';
    dataList.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = rowFormatter(item);
        tbody.appendChild(tr);
    });
}

function renderDorks(dorks) {
    const container = document.getElementById('dorks-container');
    if (!container) return;
    container.innerHTML = '';
    
    dorks.forEach(d => {
        const card = document.createElement('div');
        card.className = 'dork-card';
        card.innerHTML = `
            <div>
                <div class="dork-category">${escapeHTML(d.category)}</div>
                <div class="dork-title">${escapeHTML(d.title)}</div>
                <div class="dork-query">${escapeHTML(d.dork)}</div>
            </div>
            <a href="${d.url}" target="_blank" class="btn-dork">Executar no Google</a>
        `;
        container.appendChild(card);
    });
}

function renderSubdomains(subdomains) {
    const container = document.getElementById('subdomains-list');
    if (!container) return;
    container.innerHTML = '';
    
    if (subdomains.length === 0) {
        container.innerHTML = '<p style="color: var(--text-muted); font-style: italic;">Nenhum subdomínio encontrado via Cert-Transparency.</p>';
        return;
    }
    
    subdomains.sort().forEach(sub => {
        const span = document.createElement('span');
        span.className = 'subdomain-tag';
        span.textContent = sub;
        container.appendChild(span);
    });
}

function switchTab(event, tabName) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
    if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
    }
    document.getElementById(`tab-${tabName}`).classList.remove('hidden');
}

function generateReport() {
    if (!currentScanData) return;
    const data = currentScanData;
    const dataStr = new Date().toLocaleDateString('pt-BR');
    let reportHTML = `
        <html>
        <head>
            <title>Relatório de Exposição Corporativo - ${escapeHTML(data.asn)}</title>
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700&display=swap');
                body { font-family: 'Outfit', 'Segoe UI', Arial, sans-serif; color: #1a1a24; line-height: 1.6; padding: 50px; max-width: 1100px; margin: auto; background: #fff; }
                .report-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid #00ff88; padding-bottom: 20px; margin-bottom: 30px; }
                .logo-text { font-size: 28px; font-weight: 700; color: #0a0a0f; }
                .logo-text span { color: #00a86b; }
                .report-meta { text-align: right; color: #6c757d; font-size: 14px; }
                
                h1 { color: #0a0a0f; font-size: 24px; margin-top: 0; }
                h2 { color: #0a0a0f; margin-top: 40px; font-size: 20px; border-left: 5px solid #00d2ff; padding-left: 15px; }
                
                .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 30px 0; }
                .summary-card { background: #f8f9fa; padding: 20px; border-radius: 12px; text-align: center; border: 1px solid #e9ecef; }
                .summary-card .label { font-size: 12px; text-transform: uppercase; color: #6c757d; font-weight: 600; margin-bottom: 5px; }
                .summary-card .value { font-size: 24px; font-weight: 700; color: #1a1a24; }
                .summary-card .value.risk { color: #ff3366; }

                .disclaimer { background: #f0f7ff; border: 1px solid #cce5ff; border-radius: 12px; padding: 20px; margin: 30px 0; font-size: 14px; color: #004085; }
                .disclaimer strong { font-size: 16px; display: block; margin-bottom: 10px; }
                
                table { width: 100%; border-collapse: collapse; margin-top: 25px; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
                th { background-color: #f1f3f5; color: #495057; font-weight: 600; text-align: left; padding: 15px; font-size: 13px; text-transform: uppercase; border-bottom: 2px solid #dee2e6; }
                td { padding: 15px; border-bottom: 1px solid #eee; font-size: 14px; color: #343a40; }
                tr:last-child td { border-bottom: none; }
                
                .risk-tag { padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 11px; text-transform: uppercase; }
                .risk-alto { background: #fff5f5; color: #ff3366; border: 1px solid #ffccd5; }
                .risk-médio { background: #fffaf0; color: #ffaa00; border: 1px solid #ffeeba; }
                .risk-baixo { background: #f0fff4; color: #00a86b; border: 1px solid #c6f6d5; }
                
                .footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; color: #adb5bd; font-size: 12px; }
                @media print { body { padding: 20px; } .summary-card { border: 1px solid #ddd; } }
            </style>
        </head>
        <body>
            <div class="report-header">
                <div class="logo-text">ISP Threat Scanner <span>Edge</span></div>
                <div class="report-meta">
                    <strong>ID da Análise:</strong> #OSINT-${Math.floor(Date.now() / 1000)}<br>
                    <strong>Data:</strong> ${dataStr}
                </div>
            </div>

            <h1>Diagnóstico de Exposição de Infraestrutura (ASN ${escapeHTML(data.asn)})</h1>
            
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="label">Score de Risco</div>
                    <div class="value risk">${data.metrics.total_score}</div>
                </div>
                <div class="summary-card">
                    <div class="label">Exposições</div>
                    <div class="value">${data.metrics.total_exposures}</div>
                </div>
                <div class="summary-card">
                    <div class="label">IPs Afetados</div>
                    <div class="value">${data.metrics.total_ips}</div>
                </div>
                <div class="summary-card">
                    <div class="label">Tempo de Coleta</div>
                    <div class="value">${data.metrics.total_time_seconds}s</div>
                </div>
            </div>

            <div class="disclaimer">
                <strong>Metodologia OSINT (Open Source Intelligence)</strong>
                Este relatório foi gerado através de coleta passiva e não-invasiva, utilizando APIs globais de inteligência de ameaças (Shodan, AlienVault OTX e RIPE Stat). 
                Os dados refletem o estado da superfície pública mapeada no momento da última indexação das fontes.
            </div>

            <h2>Ativos Críticos e Vetores de Risco Mapeados</h2>
            <table>
                <thead>
                    <tr>
                        <th>Endereço IP</th>
                        <th>Bloco de Rede</th>
                        <th>Porta/Serviço</th>
                        <th>Nível de Risco</th>
                        <th>Indicadores OSINT</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.raw_data.map(item => `
                        <tr>
                            <td><strong>${escapeHTML(item.ip)}</strong></td>
                            <td style="color:#6c757d">${escapeHTML(item.prefix)}</td>
                            <td>${item.port} / ${escapeHTML(item.service.split('(')[1]?.replace(')', '') || item.service)}</td>
                            <td><span class="risk-tag risk-${item.risk_level.toLowerCase()}">${escapeHTML(item.risk_level)}</span></td>
                            <td style="font-size:12px; color:#495057 italic">${escapeHTML(item.banner.substring(0, 100) || 'Ativo Confirmado')}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>

            <div class="footer">
                Documento Técnico Confidencial - Gerado para gestão de segurança cibernética.<br>
                ISP Threat Scanner Edge © ${new Date().getFullYear()}
            </div>
        </body>
        </html>
    `;
    const printWindow = window.open('', '_blank');
    printWindow.document.write(reportHTML);
    printWindow.document.close();
}

function animateValue(id, start, end, duration) {
    const obj = document.getElementById(id);
    if (!obj) return;
    if (start === end) { obj.innerHTML = end; return; }
    let range = end - start;
    let current = start;
    let increment = end > start ? 1 : -1;
    let stepTime = Math.abs(Math.floor(duration / range)) || 10;
    let timer = setInterval(function () {
        current += increment;
        obj.innerHTML = current;
        if (current == end) clearInterval(timer);
    }, stepTime);
}

function toggleTheme() {
    document.documentElement.classList.toggle('dark-theme');
    const themeIcon = document.getElementById('theme-icon');
    const themeText = document.getElementById('theme-text');
    let theme = document.documentElement.classList.contains('dark-theme') ? 'dark-theme' : 'light-theme';
    if (themeIcon) themeIcon.textContent = theme === 'dark-theme' ? 'O' : 'X';
    if (themeText) themeText.textContent = theme === 'dark-theme' ? 'Modo Claro' : 'Modo Escuro';
    localStorage.setItem('theme', theme);
    if (portsChartInstance) portsChartInstance.update();
}

const savedTheme = localStorage.getItem('theme');
if (savedTheme === 'dark-theme') {
    document.documentElement.classList.add('dark-theme');
    const themeIcon = document.getElementById('theme-icon');
    const themeText = document.getElementById('theme-text');
    if (themeIcon) themeIcon.textContent = 'O';
    if (themeText) themeText.textContent = 'Modo Claro';
}

async function exportData(format) {
    if (!currentScanData || !currentScanData.asn) return;
    try {
        const response = await fetch(`/api/export/${format}/${currentScanData.asn}`);
        if (!response.ok) {
            alert('Falha ao exportar os dados.');
            return;
        }
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_${currentScanData.asn}.${format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (e) {
        console.error("Erro na exportação:", e);
        alert('Erro ao tentar exportar.');
    }
}

async function compareScans() {
    if (!currentScanData || !currentScanData.asn) return;
    try {
        const response = await fetch(`/api/diff/${currentScanData.asn}`);
        if (!response.ok) {
            const err = await response.json();
            alert(err.message || 'Erro ao comparar scans.');
            return;
        }
        const data = await response.json();
        alert(`Comparação concluída!\nNovas exposições encontradas (em relação ao scan anterior): ${data.new_exposures_count}`);
    } catch (e) {
        console.error("Erro na comparação:", e);
        alert('Erro ao tentar comparar os scans.');
    }
}
