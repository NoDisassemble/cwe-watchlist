// Requests stay on this site's origin. server.py forwards /api/v1 requests to MITRE.
const API_BASE = '/api/v1';
let watchlistRecords = [];

const themeButton = document.querySelector('.theme-toggle');
function setTheme(theme) {
  const isDark = theme === 'dark';
  document.documentElement.dataset.theme = theme;
  themeButton.setAttribute('aria-pressed', isDark);
  themeButton.setAttribute('aria-label', `Switch to ${isDark ? 'light' : 'dark'} theme`);
  themeButton.querySelector('.theme-label').textContent = isDark ? 'Light' : 'Dark';
}
setTheme(localStorage.getItem('theme') || 'dark');
themeButton.addEventListener('click', () => { const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; setTheme(next); localStorage.setItem('theme', next); });

async function get(path) {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) throw new Error(`API returned ${response.status}`);
  return response.json();
}

function cleanText(value = '') { return value.replace(/\s+/g, ' ').trim(); }
function escapeHtml(value = '') {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[character]));
}
function renderWeaknesses(weaknesses) {
  const grid = document.querySelector('#weakness-grid');
  grid.innerHTML = weaknesses.map((item) => {
    const description = cleanText(item.Description || 'No description available.');
    const summary = description.slice(0, 145);
    const detailId = `cwe-${item.ID}-description`;
    const owaspMappings = (item.owasp || []).map((category) => `<a class="owasp-badge" href="${escapeHtml(category.url)}" target="_blank" rel="noreferrer" title="CWE-${item.ID} maps to this OWASP category">OWASP ${escapeHtml(category.code)} &middot; #${category.rank} ${escapeHtml(category.name)} &nearr;</a>`).join('');
    return `
    <article class="weakness-card"><header><span>CWE-${item.ID}</span><span class="status">Threat score: ${item.threat_score}</span></header>
    <div class="owasp-mappings">${owaspMappings || '<span class="owasp-badge owasp-badge-none">Not mapped to OWASP Top 10:2025</span>'}</div>
    <h3>${escapeHtml(item.Name || 'Unnamed weakness')}</h3><p>${escapeHtml(summary)}${description.length > 145 ? '…' : ''}</p>
    ${description.length > 145 ? `<button class="desc-toggle" type="button" aria-expanded="false" aria-controls="${detailId}">Full description <span aria-hidden="true">↓</span></button><p class="full-description" id="${detailId}" hidden>${escapeHtml(description)}</p>` : ''}
    <footer>${item.kev_count} KEVs · ${item.ransomware_count} ransomware · EPSS ${item.epss_percentile}%</footer></article>`;
  }).join('');
}
async function loadDashboard() {
  const grid = document.querySelector('#weakness-grid');
  grid.innerHTML = '<p class="loading">Loading live CWE records…</p>';
  try {
    const [version, threatWatchlist] = await Promise.all([get('/cwe/version'), fetch('/api/watchlist').then((response) => {
      if (!response.ok) throw new Error(`Threat watchlist returned ${response.status}`);
      return response.json();
    })]);
    if (!threatWatchlist.items?.length) throw new Error(threatWatchlist.error || 'No threat-ranked CWEs were returned.');
    const watchlistResponse = await get(`/cwe/weakness/${threatWatchlist.items.map((item) => item.id).join(',')}`);
    document.querySelector('#content-version').textContent = `v${version.ContentVersion || '—'}`;
    document.querySelector('#content-date').textContent = version.ContentDate ? `Released ${version.ContentDate.trim()}` : 'Current release';
    document.querySelector('#weakness-count').textContent = Number(version.TotalWeaknesses || 0).toLocaleString();
    document.querySelector('#category-count').textContent = Number(version.TotalCategories || 0).toLocaleString();
    document.querySelector('#view-count').textContent = Number(version.TotalViews || 0).toLocaleString();
    const threatDataById = new Map(threatWatchlist.items.map((item) => [item.id, item]));
    const weaknesses = (watchlistResponse.Weaknesses || []).map((item) => ({ ...item, ...threatDataById.get(item.ID) }));
    weaknesses.sort((a, b) => b.threat_score - a.threat_score);
    watchlistRecords = weaknesses;
    document.querySelector('#download-report').disabled = weaknesses.length === 0;
    renderWeaknesses(weaknesses);
  } catch (error) {
    watchlistRecords = [];
    document.querySelector('#download-report').disabled = true;
    grid.innerHTML = `<p class="loading error">Unable to load live CWE data. ${error.message}</p>`;
    document.querySelector('#content-version').textContent = 'Unavailable';
    document.querySelector('#content-date').textContent = 'Check API connection';
  }
}

function showRecord(item) {
  const result = document.querySelector('#record-result');
  result.hidden = false;
  result.innerHTML = `<p class="eyebrow">CWE-${item.ID} record</p><h3>${item.Name || 'Unnamed weakness'}</h3><p>${cleanText(item.Description || item.ExtendedDescription || 'No description was returned for this record.')}</p><div class="record-meta"><span>${item.Status || 'Status unavailable'}</span><span>${item.Abstraction || 'Type unavailable'}</span>${item.LikelihoodOfExploit ? `<span>Exploit likelihood: ${item.LikelihoodOfExploit}</span>` : ''}</div>`;
  result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
document.querySelector('#lookup-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const id = document.querySelector('#cwe-id').value.replace(/^CWE-/i, '').trim(); const result = document.querySelector('#record-result');
  result.hidden = false; result.innerHTML = '<p class="loading">Fetching CWE record…</p>';
  try { const data = await get(`/cwe/weakness/${encodeURIComponent(id)}`); const item = data.Weaknesses?.[0]; if (!item) throw new Error('No matching CWE weakness found.'); showRecord(item); } catch (error) { result.innerHTML = `<p class="error">Lookup failed: ${error.message}</p>`; }
});
document.querySelectorAll('.example-id').forEach((button) => button.addEventListener('click', () => { document.querySelector('#cwe-id').value = button.dataset.id; document.querySelector('#lookup-form').requestSubmit(); }));
document.querySelector('#refresh-data').addEventListener('click', loadDashboard);
document.querySelector('#download-report').addEventListener('click', () => {
  if (!watchlistRecords.length || !window.jspdf?.jsPDF) return;
  const button = document.querySelector('#download-report');
  button.disabled = true;
  button.textContent = 'Creating PDF…';

  const { jsPDF } = window.jspdf;
  const documentPdf = new jsPDF({ unit: 'pt', format: 'a4' });
  const pageWidth = documentPdf.internal.pageSize.getWidth();
  const pageHeight = documentPdf.internal.pageSize.getHeight();
  const margin = 52;
  const textWidth = pageWidth - margin * 2;
  let y = 58;

  const newPage = () => { documentPdf.addPage(); y = 58; };
  const writeLines = (lines, size, color = [30, 35, 31], gap = 14) => {
    documentPdf.setFontSize(size);
    documentPdf.setTextColor(...color);
    lines.forEach((line) => {
      if (y > pageHeight - 55) newPage();
      documentPdf.text(line, margin, y);
      y += gap;
    });
  };

  documentPdf.setFillColor(169, 67, 27);
  documentPdf.rect(0, 0, pageWidth, 14, 'F');
  documentPdf.setFont('helvetica', 'bold');
  writeLines(['CWE WATCH — TOP 5 THREAT REPORT'], 20, [23, 32, 28], 26);
  documentPdf.setFont('helvetica', 'normal');
  writeLines([`Generated ${new Date().toLocaleString()}`, 'Ranking inputs: CISA Known Exploited Vulnerabilities (KEV), ransomware use, recency, and EPSS.'], 9, [92, 103, 96], 14);
  y += 16;

  watchlistRecords.forEach((item, index) => {
    if (y > pageHeight - 180) newPage();
    documentPdf.setDrawColor(169, 67, 27);
    documentPdf.line(margin, y, pageWidth - margin, y);
    y += 20;
    documentPdf.setFont('helvetica', 'bold');
    writeLines([`${index + 1}. CWE-${item.ID}: ${item.Name || 'Unnamed weakness'}`], 14, [23, 32, 28], 19);
    documentPdf.setFont('helvetica', 'normal');
    writeLines([`Threat score: ${item.threat_score}  |  KEVs: ${item.kev_count}  |  Ransomware-linked: ${item.ransomware_count}  |  EPSS percentile: ${item.epss_percentile}%`], 9, [92, 103, 96], 13);
    const owaspSummary = (item.owasp || []).length
      ? item.owasp.map((category) => `${category.code} (#${category.rank}) ${category.name}`).join('; ')
      : 'Not mapped';
    writeLines([`OWASP Top 10:2025: ${owaspSummary}`], 9, [92, 103, 96], 13);
    y += 6;
    documentPdf.setFont('helvetica', 'bold');
    writeLines(['Full description'], 10, [23, 32, 28], 14);
    documentPdf.setFont('helvetica', 'normal');
    writeLines(documentPdf.splitTextToSize(cleanText(item.Description || item.ExtendedDescription || 'No description was returned.'), textWidth), 10, [50, 59, 53], 14);
    y += 18;
  });

  documentPdf.save(`cwe-watch-top-5-${new Date().toISOString().slice(0, 10)}.pdf`);
  button.disabled = false;
  button.textContent = 'Download PDF ↓';
});
document.querySelector('#weakness-grid').addEventListener('click', (event) => {
  const button = event.target.closest('.desc-toggle');
  if (!button) return;
  const description = document.getElementById(button.getAttribute('aria-controls'));
  const isExpanded = button.getAttribute('aria-expanded') === 'true';
  button.setAttribute('aria-expanded', String(!isExpanded));
  button.innerHTML = `${isExpanded ? 'Full description <span aria-hidden="true">↓</span>' : 'Collapse description <span aria-hidden="true">↑</span>'}`;
  description.hidden = isExpanded;
});
loadDashboard();
