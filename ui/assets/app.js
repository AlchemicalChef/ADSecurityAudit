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
  metadata: {},
};

function normalizeSeverity(value) {
  if (!value) return 'Low';
  const normalized = String(value).toLowerCase();
  const lookup = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  return lookup[normalized] || 'Low';
}

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
      const severity = normalizeSeverity(item.Severity);
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

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function highestSeverity(findings) {
  return findings.reduce((top, item) => {
    const sev = normalizeSeverity(item.Severity);
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
    acc[category].counts[normalizeSeverity(item.Severity)] += 1;
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

function renderAdminCounts(metadata) {
  const entries = [
    { id: 'domain-admins-count', value: metadata.domainAdmins },
    { id: 'enterprise-admins-count', value: metadata.enterpriseAdmins },
    { id: 'schema-admins-count', value: metadata.schemaAdmins },
  ];
  entries.forEach((entry) => {
    const display = entry.value ?? '—';
    setText(entry.id, display);
  });
}

function buildPill(text) {
  const pill = document.createElement('span');
  pill.className = 'pill';
  pill.textContent = text;
  return pill;
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
      (a, b) => SEVERITY_WEIGHTS[normalizeSeverity(b.Severity)] - SEVERITY_WEIGHTS[normalizeSeverity(a.Severity)]
    )[0];
    if (topIssue) {
      pillRow.append(buildPill(`Top issue: ${topIssue.Issue}`));
    }

    const detailSnippets = extractDetailSnippets(group.findings[0]?.Details);
    detailSnippets.forEach((snippet) => pillRow.append(buildPill(snippet)));

    card.append(header, stats, pillRow);
    card.addEventListener('click', () => openModal({ title: group.category, findings: group.findings }));
    container.appendChild(card);
  });
}

function renderFindings(findings) {
  const container = document.getElementById('findings-list');
  container.innerHTML = '';

  if (!findings.length) {
    container.textContent = 'No findings to display yet.';
    return;
  }

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_WEIGHTS[normalizeSeverity(b.Severity)] - SEVERITY_WEIGHTS[normalizeSeverity(a.Severity)]
  );

  sorted.forEach((finding) => {
    const card = document.createElement('article');
    card.className = 'finding-card';

    const header = document.createElement('div');
    header.className = 'finding-header';

    const title = document.createElement('div');
    title.className = 'finding-title';
    title.innerHTML = `${getCategoryIcon(finding.Category)} <span>${finding.Issue}</span>`;

    const severityValue = normalizeSeverity(finding.Severity);
    const severity = document.createElement('span');
    severity.className = `severity-pill severity-${severityValue.toLowerCase()}`;
    severity.textContent = severityValue;

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

    const references = buildReferences(finding.RemediationReference || finding.References);

    const button = document.createElement('button');
    button.className = 'detail-button';
    button.textContent = 'View details & evidence';
    button.addEventListener('click', () => openModal(finding));

    card.append(header, meta, description, impact, remediation, references, button);
    container.appendChild(card);
  });
}

function renderRiskCallouts(findings) {
  const severityBuckets = {
    Critical: document.getElementById('critical-summary-list'),
    High: document.getElementById('high-summary-list'),
  };
  const countDisplays = {
    Critical: document.getElementById('critical-summary-count'),
    High: document.getElementById('high-summary-count'),
  };

  Object.entries(severityBuckets).forEach(([severity, container]) => {
    if (!container) return;
    container.innerHTML = '';
    const filtered = findings.filter((f) => (f.Severity || 'Low') === severity);
    if (countDisplays[severity]) countDisplays[severity].textContent = filtered.length;

    if (!filtered.length) {
      container.textContent = `No ${severity.toLowerCase()} findings yet.`;
      return;
    }

    filtered.slice(0, 5).forEach((finding) => {
      const item = document.createElement('div');
      item.className = 'callout-item';
      const left = document.createElement('div');
      left.innerHTML = `
        <strong>${finding.Issue}</strong>
        <div class="meta-row">
          <span>${finding.Category || 'Uncategorized'}</span>
          <span>• Affected: ${finding.AffectedObject || 'Unknown'}</span>
        </div>
      `;

      const right = document.createElement('div');
      right.className = 'meta-row';
      right.innerHTML = `
        <span>Detected: ${formatDate(finding.DetectedDate)}</span>
      `;

      item.append(left, right);
      item.addEventListener('click', () => openModal(finding));
      container.appendChild(item);
    });
  });
}

function render(findings, metadata = {}) {
  state.findings = findings;
  state.metadata = metadata;
  renderSummary(findings);
  renderCategoryGrid(findings);
  renderFindings(findings);
  renderMeta(metadata);
  renderAdminCounts(metadata);
  renderRiskCallouts(findings);
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

function extractMetadata(data) {
  if (!data || typeof data !== 'object') return {};
  const summary = data.Summary || data.summary || {};
  const meta = data.Metadata || data.metadata || {};
  const stats = data.Statistics || data.statistics || {};
  return {
    privilegedAccounts: meta.PrivilegedAccounts || summary.PrivilegedAccounts || stats.PrivilegedAccounts || data.PrivilegedAccountsCount,
    domainControllers: summary.DomainControllers || stats.DomainControllers || meta.DomainControllers,
    auditGenerated: summary.Generated || data.Generated || meta.GeneratedOn,
    staleSeamlessSso: summary.AzureAdSsoExpiredKeys || stats.AzureAdSsoExpiredKeys,
    domainAdmins: summary.DomainAdmins || meta.DomainAdmins || stats.DomainAdmins,
    enterpriseAdmins: summary.EnterpriseAdmins || meta.EnterpriseAdmins || stats.EnterpriseAdmins,
    schemaAdmins: summary.SchemaAdmins || meta.SchemaAdmins || stats.SchemaAdmins,
  };
}

function renderMeta(metadata) {
  const container = document.getElementById('meta-stats');
  container.innerHTML = '';
  const entries = [
    { label: 'Privileged Accounts', value: metadata.privilegedAccounts ?? '—', hint: 'High-risk identities to lock down' },
    { label: 'Domain Controllers', value: metadata.domainControllers ?? '—', hint: 'Visibility across replication scope' },
    { label: 'Seamless SSO keys expired', value: metadata.staleSeamlessSso ?? '—', hint: 'Rotate AzureADSSOACC keys per guidance' },
    { label: 'Audit generated', value: metadata.auditGenerated ? formatDate(metadata.auditGenerated) : '—', hint: 'Report timestamp' },
  ];

  entries.forEach((entry) => {
    const card = document.createElement('div');
    card.className = 'meta-stat-card';
    card.innerHTML = `
      <span class="label">${entry.label}</span>
      <span class="value">${entry.value}</span>
      <span class="hint">${entry.hint}</span>
    `;
    container.appendChild(card);
  });
}

function buildReferences(refs) {
  if (!refs) {
    const wrapper = document.createElement('p');
    wrapper.className = 'references';
    wrapper.innerHTML = '<strong>References:</strong> Not provided';
    return wrapper;
  }

  const list = Array.isArray(refs) ? refs : [refs];
  const wrapper = document.createElement('div');
  wrapper.className = 'references';
  const ul = document.createElement('ul');
  ul.className = 'reference-list';
  list.forEach((ref) => {
    const li = document.createElement('li');
    li.innerHTML = `<a href="${ref}" target="_blank" rel="noreferrer noopener">${ref}</a>`;
    ul.appendChild(li);
  });
  wrapper.innerHTML = '<strong>References:</strong>';
  wrapper.appendChild(ul);
  return wrapper;
}

function buildDetailsGrid(details = {}) {
  const grid = document.createElement('div');
  grid.className = 'detail-grid';
  const entries = Object.entries(details);
  if (!entries.length) {
    grid.textContent = 'No additional detail provided.';
    return grid;
  }

  entries.forEach(([key, value]) => {
    const pill = document.createElement('span');
    pill.className = 'pill';
    pill.innerHTML = `<strong>${key}:</strong> ${Array.isArray(value) ? value.join(', ') : value}`;
    grid.appendChild(pill);
  });
  return grid;
}

function openModal(payload) {
  const modal = document.getElementById('modal');
  const body = document.getElementById('modal-body');
  const isCategory = payload.findings;
  body.innerHTML = '';

  if (isCategory) {
    const title = document.createElement('h2');
    title.textContent = payload.title;
    body.appendChild(title);
    payload.findings.forEach((finding) => body.appendChild(buildModalFinding(finding)));
  } else {
    body.appendChild(buildModalFinding(payload));
  }

  modal.hidden = false;
}

function buildModalFinding(finding) {
  const wrapper = document.createElement('article');
  wrapper.className = 'finding-card';

  const header = document.createElement('div');
  header.className = 'finding-header';
  header.innerHTML = `${getCategoryIcon(finding.Category)} <strong>${finding.Issue}</strong>`;

  const severityValue = normalizeSeverity(finding.Severity);
  const severity = document.createElement('span');
  severity.className = `severity-pill severity-${severityValue.toLowerCase()}`;
  severity.textContent = severityValue;

  header.appendChild(severity);

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

  const references = buildReferences(finding.RemediationReference || finding.References);
  const details = buildDetailsGrid(finding.Details);

  wrapper.append(header, meta, description, impact, remediation, references, details);
  return wrapper;
}

function closeModal() {
  document.getElementById('modal').hidden = true;
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
    ingestData(data, 'sample file');
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
      ingestData(parsed, `uploaded file: ${file.name}`);
    } catch (error) {
      console.error(error);
      setStatus('Could not parse the uploaded JSON file.', 'error');
    }
  };
  reader.readAsText(file);
}

function ingestData(parsed, sourceLabel) {
  const findings = normalizeFindings(parsed);
  const metadata = extractMetadata(parsed);
  render(findings, metadata);
  reportIngestionResult(findings, sourceLabel);
}

async function handleUrlLoad() {
  const urlInput = document.getElementById('remote-url');
  const url = urlInput.value.trim();
  if (!url) {
    setStatus('Enter a URL to load JSON from.', 'error');
    return;
  }

  try {
    setStatus('Fetching JSON from URL...', 'muted');
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const parsed = await response.json();
    ingestData(parsed, `remote URL: ${url}`);
  } catch (error) {
    console.error(error);
    setStatus('Unable to fetch or parse JSON from the provided URL.', 'error');
  }
}

function handlePastedJson() {
  const textarea = document.getElementById('paste-json');
  const text = textarea.value.trim();
  if (!text) {
    setStatus('Paste audit JSON into the field to load it.', 'error');
    return;
  }
  try {
    const parsed = JSON.parse(text);
    ingestData(parsed, 'pasted JSON');
  } catch (error) {
    console.error(error);
    setStatus('Pasted content is not valid JSON.', 'error');
  }
}

function initTabs() {
  const buttons = Array.from(document.querySelectorAll('.tab-button'));
  const panels = Array.from(document.querySelectorAll('.tab-panel'));

  function activate(tabId) {
    buttons.forEach((button) => {
      const isActive = button.dataset.tab === tabId;
      button.classList.toggle('active', isActive);
      button.setAttribute('aria-selected', String(isActive));
    });
    panels.forEach((panel) => {
      const shouldShow = panel.dataset.tabPanel === tabId;
      panel.hidden = !shouldShow;
    });
  }

  buttons.forEach((button) => {
    button.addEventListener('click', () => activate(button.dataset.tab));
  });

  if (buttons[0]) activate(buttons[0].dataset.tab);
}

function boot() {
  document.getElementById('file-input').addEventListener('change', handleFileUpload);
  document.getElementById('load-sample').addEventListener('click', () => loadRemoteJson('./sample-data/audit-report.json'));
  document.getElementById('load-url').addEventListener('click', handleUrlLoad);
  document.getElementById('load-pasted').addEventListener('click', handlePastedJson);
  document.getElementById('close-modal').addEventListener('click', closeModal);
  document.getElementById('modal').addEventListener('click', (e) => {
    if (e.target.id === 'modal') closeModal();
  });
  initTabs();
  loadRemoteJson('./sample-data/audit-report.json');
}

window.addEventListener('DOMContentLoaded', boot);
