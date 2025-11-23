const SEVERITY_WEIGHTS = { Critical: 4, High: 3, Medium: 2, Low: 1 };
const CATEGORY_ICONS = {
  'Computer Account Delegation': '🖥️',
  'Fine-Grained Password Policies': '🔑',
  'DNS Security Configuration': '🌐',
  'Authentication Policies': '🔒',
  'Audit Configuration': '📑',
  'LAPS Coverage': '🛡️',
  default: '📂',
};

const state = {
  findings: [],
};

function setStatus(message, tone = 'muted') {
  const status = document.getElementById('status-message');
  status.textContent = message;
  status.className = tone;
}

function formatDate(dateString) {
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return 'Unknown date';
  return date.toLocaleString();
}

function computeSummary(findings) {
  return findings.reduce(
    (acc, item) => {
      const severity = item.Severity || 'Low';
      acc[severity] = (acc[severity] || 0) + 1;
      return acc;
    },
    { Critical: 0, High: 0, Medium: 0, Low: 0 }
  );
}

function setCount(id, count, percentage) {
  const countEl = document.getElementById(id);
  const progressEl = document.querySelector(`#${id.replace('-count', '-progress')}`);
  if (countEl) countEl.textContent = count;
  if (progressEl) progressEl.style.width = `${percentage}%`;
}

function highestSeverity(findings) {
  return findings.reduce((top, item) => {
    const sev = item.Severity || 'Low';
    if (!top || SEVERITY_WEIGHTS[sev] > SEVERITY_WEIGHTS[top]) {
      return sev;
    }
    return top;
  }, null);
}

function groupByCategory(findings) {
  return findings.reduce((acc, item) => {
    const category = item.Category || 'Uncategorized';
    if (!acc[category]) {
      acc[category] = { category, findings: [], counts: { Critical: 0, High: 0, Medium: 0, Low: 0 } };
    }
    acc[category].findings.push(item);
    acc[category].counts[item.Severity || 'Low'] += 1;
    return acc;
  }, {});
}

function getCategoryIcon(name) {
  return CATEGORY_ICONS[name] || CATEGORY_ICONS.default;
}

function renderSummary(findings) {
  const summary = computeSummary(findings);
  const total = Math.max(findings.length, 1);

  setCount('critical-count', summary.Critical, (summary.Critical / total) * 100);
  setCount('high-count', summary.High, (summary.High / total) * 100);
  setCount('medium-count', summary.Medium, (summary.Medium / total) * 100);
  setCount('low-count', summary.Low, (summary.Low / total) * 100);

  document.getElementById('total-count').textContent = `${findings.length} findings`;
  const latest = findings.reduce((current, finding) => {
    const candidate = new Date(finding.DetectedDate);
    if (Number.isNaN(candidate.getTime())) return current;
    if (!current || candidate > current) return candidate;
    return current;
  }, null);

  document.getElementById('last-updated').textContent = latest
    ? `Updated ${formatDate(latest)}`
    : 'Waiting for data…';
}

function buildPill(text) {
  const pill = document.createElement('span');
  pill.className = 'pill';
  pill.textContent = text;
  return pill;
}

function renderCategoryGrid(findings) {
  const container = document.getElementById('category-grid');
  container.innerHTML = '';
  const groups = Object.values(groupByCategory(findings)).sort(
    (a, b) => SEVERITY_WEIGHTS[highestSeverity(b.findings)] - SEVERITY_WEIGHTS[highestSeverity(a.findings)]
  );

  if (!groups.length) {
    container.textContent = 'Load an audit JSON file to see category health.';
    return;
  }

  groups.forEach((group) => {
    const card = document.createElement('article');
    card.className = 'category-card';
    const severity = highestSeverity(group.findings) || 'Low';
    const severityClass = `status-${severity.toLowerCase()}`;

    const header = document.createElement('div');
    header.className = 'category-header';
    const title = document.createElement('div');
    title.className = 'category-title';
    title.innerHTML = `<span class="icon">${getCategoryIcon(group.category)}</span><span>${group.category}</span>`;
    const chip = document.createElement('span');
    chip.className = `status-chip ${severityClass}`;
    chip.textContent = `${severity} risk`;

    header.append(title, chip);

    const stats = document.createElement('div');
    stats.innerHTML = `
      <div class="stat-line"><span>Findings</span><strong>${group.findings.length}</strong></div>
      <div class="stat-line"><span>Critical / High</span><strong>${group.counts.Critical} / ${group.counts.High}</strong></div>
    `;

    const pillRow = document.createElement('div');
    pillRow.className = 'pill-row';
    const affectedList = [...new Set(group.findings.map((f) => f.AffectedObject).filter(Boolean))];
    if (affectedList.length) {
      pillRow.append(buildPill(`Key objects: ${affectedList.slice(0, 3).join(', ')}${
        affectedList.length > 3 ? ` +${affectedList.length - 3}` : ''
      }`));
    }
    const topIssue = group.findings.sort(
      (a, b) => SEVERITY_WEIGHTS[b.Severity || 'Low'] - SEVERITY_WEIGHTS[a.Severity || 'Low']
    )[0];
    if (topIssue) {
      pillRow.append(buildPill(`Top issue: ${topIssue.Issue}`));
    }

    const detailSnippets = extractDetailSnippets(group.findings[0]?.Details);
    detailSnippets.forEach((snippet) => pillRow.append(buildPill(snippet)));

    card.append(header, stats, pillRow);
    container.appendChild(card);
  });
}

function extractDetailSnippets(details) {
  if (!details || typeof details !== 'object') return [];
  const entries = Object.entries(details).slice(0, 2);
  return entries.map(([key, value]) => {
    if (Array.isArray(value)) return `${key}: ${value.slice(0, 3).join(', ')}`;
    if (typeof value === 'boolean') return `${key}: ${value ? 'Yes' : 'No'}`;
    return `${key}: ${value}`;
  });
}

function renderFindings(findings) {
  const container = document.getElementById('findings-list');
  container.innerHTML = '';

  if (!findings.length) {
    container.textContent = 'No findings to display yet.';
    return;
  }

  const sorted = [...findings].sort((a, b) => SEVERITY_WEIGHTS[b.Severity || 'Low'] - SEVERITY_WEIGHTS[a.Severity || 'Low']);

  sorted.forEach((finding) => {
    const card = document.createElement('article');
    card.className = 'finding-card';

    const header = document.createElement('div');
    header.className = 'finding-header';

    const title = document.createElement('div');
    title.className = 'finding-title';
    title.innerHTML = `${getCategoryIcon(finding.Category)} <span>${finding.Issue}</span>`;

    const severity = document.createElement('span');
    severity.className = `severity-pill severity-${(finding.Severity || 'Low').toLowerCase()}`;
    severity.textContent = finding.Severity || 'Low';

    header.append(title, severity);

    const meta = document.createElement('div');
    meta.className = 'meta-row';
    meta.innerHTML = `
      <span class="meta-chip">Category: ${finding.Category}</span>
      <span class="meta-chip">Affected: ${finding.AffectedObject || 'Unknown'}</span>
      <span class="meta-chip">Detected: ${formatDate(finding.DetectedDate)}</span>
    `;

    const description = document.createElement('p');
    description.className = 'description';
    description.textContent = finding.Description || 'No description provided.';

    const impact = document.createElement('p');
    impact.className = 'impact';
    impact.innerHTML = `<strong>Impact:</strong> ${finding.Impact || 'No impact provided.'}`;

    const remediation = document.createElement('p');
    remediation.className = 'remediation';
    remediation.innerHTML = `<strong>Remediation:</strong> ${finding.Remediation || 'No remediation provided.'}`;

    card.append(header, meta, description, impact, remediation);
    container.appendChild(card);
  });
}

function render(findings) {
  state.findings = findings;
  renderSummary(findings);
  renderCategoryGrid(findings);
  renderFindings(findings);
  setStatus('Audit data loaded and visualized.');
}

function normalizeFindings(data) {
  if (!data) return [];
  if (Array.isArray(data)) return data;

  if (Array.isArray(data.Findings)) return data.Findings;
  if (Array.isArray(data.findings)) return data.findings;

  if (Array.isArray(data.Results)) {
    return data.Results.flatMap((entry) => entry.Findings || entry.findings || []).filter(Boolean);
  }

  const valueArrays = Object.values(data).filter((value) => Array.isArray(value));
  const findingLikeArrays = valueArrays.filter((arr) =>
    arr.some((item) => typeof item === 'object' && (item.Issue || item.Severity))
  );
  if (findingLikeArrays.length) {
    return findingLikeArrays.flat();
  }

  return [];
}

function reportIngestionResult(findings, sourceLabel = 'data source') {
  if (!findings.length) {
    setStatus(`No findings detected in the ${sourceLabel}. Confirm it includes audit results.`, 'error');
    return;
  }

  const summary = computeSummary(findings);
  const message = `Loaded ${findings.length} findings (Critical: ${summary.Critical}, High: ${summary.High}, Medium: ${summary.Medium}, Low: ${summary.Low}).`;
  setStatus(message, 'muted');
}

async function loadRemoteJson(path) {
  try {
    setStatus('Loading data...', 'muted');
    const response = await fetch(path);
    const data = await response.json();
    const findings = normalizeFindings(data);
    render(findings);
    reportIngestionResult(findings, 'sample file');
  } catch (error) {
    console.error(error);
    setStatus('Unable to load JSON. Please check the file path and try again.', 'error');
  }
}

function handleFileUpload(event) {
  const [file] = event.target.files;
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const parsed = JSON.parse(e.target.result);
      const findings = normalizeFindings(parsed);
      render(findings);
      reportIngestionResult(findings, `uploaded file: ${file.name}`);
    } catch (error) {
      console.error(error);
      setStatus('Could not parse the uploaded JSON file.', 'error');
    }
  };
  reader.readAsText(file);
}

function boot() {
  document.getElementById('file-input').addEventListener('change', handleFileUpload);
  document.getElementById('load-sample').addEventListener('click', () => loadRemoteJson('./sample-data/audit-report.json'));
  loadRemoteJson('./sample-data/audit-report.json');
}

window.addEventListener('DOMContentLoaded', boot);
