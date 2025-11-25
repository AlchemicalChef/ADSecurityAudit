const SEVERITY_WEIGHTS = { Critical: 4, High: 3, Medium: 2, Low: 1 };
const CATEGORY_ICONS = {
  'Computer Account Delegation': '🖥️',
  'Fine-Grained Password Policies': '🔑',
  'DNS Security Configuration': '🌐',
  'Authentication Policies': '🔒',
  'Audit Configuration': '📑',
  'LAPS Coverage': '🛡️',
  'User Account': '👤',
  'Privileged Groups': '👥',
  'AdminSDHolder': '🔐',
  'Group Policy': '📋',
  'Replication Security': '🔄',
  'Domain Security': '🏛️',
  'Dangerous Permissions': '⚠️',
  'Certificate Services': '📜',
  'Kerberos Security': '🎫',
  'Domain Trusts': '🤝',
  'LAPS Deployment': '🔑',
  'Audit Policy': '📊',
  'Kerberos Delegation': '🎭',
  'Admin Equivalence': '👑',
  'Domain Admin Equivalence': '👑',
  'Legacy Attack Vector': '⚡',
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
  if (status) {
    status.textContent = message;
    status.className = tone;
  }
}

function formatDate(dateString) {
  if (!dateString) return 'Unknown date';
  
  // Handle .NET DateTime serialization formats
  let date;
  if (typeof dateString === 'string' && dateString.startsWith('/Date(')) {
    // .NET JSON serialization format: /Date(1234567890000)/
    const match = dateString.match(/\/Date\((\d+)\)\//);
    if (match) {
      date = new Date(parseInt(match[1], 10));
    }
  } else {
    date = new Date(dateString);
  }
  
  if (!date || Number.isNaN(date.getTime())) return 'Unknown date';
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

  const totalCountEl = document.getElementById('total-count');
  if (totalCountEl) totalCountEl.textContent = `${findings.length} findings`;
  
  const latest = findings.reduce((current, finding) => {
    if (!finding.DetectedDate) return current;
    const candidate = new Date(finding.DetectedDate);
    if (Number.isNaN(candidate.getTime())) return current;
    if (!current || candidate > current) return candidate;
    return current;
  }, null);

  const lastUpdatedEl = document.getElementById('last-updated');
  if (lastUpdatedEl) {
    lastUpdatedEl.textContent = latest
      ? `Updated ${formatDate(latest)}`
      : 'Waiting for data…';
  }
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
    if (value === null || value === undefined) return `${key}: N/A`;
    return `${key}: ${value}`;
  });
}

function renderCategoryGrid(findings) {
  const container = document.getElementById('category-grid');
  if (!container) return;
  
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
    title.innerHTML = `<span class="icon">${getCategoryIcon(group.category)}</span><span>${escapeHtml(group.category)}</span>`;
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
    if (topIssue && topIssue.Issue) {
      pillRow.append(buildPill(`Top issue: ${topIssue.Issue}`));
    }

    const detailSnippets = extractDetailSnippets(group.findings[0]?.Details);
    detailSnippets.forEach((snippet) => pillRow.append(buildPill(snippet)));

    card.append(header, stats, pillRow);
    card.addEventListener('click', () => openModal({ title: group.category, findings: group.findings }));
    container.appendChild(card);
  });
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function renderFindings(findings) {
  const container = document.getElementById('findings-list');
  if (!container) return;
  
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
    title.innerHTML = `${getCategoryIcon(finding.Category)} <span>${escapeHtml(finding.Issue || 'Unknown Issue')}</span>`;

    const severityValue = normalizeSeverity(finding.Severity);
    const severity = document.createElement('span');
    severity.className = `severity-pill severity-${severityValue.toLowerCase()}`;
    severity.textContent = severityValue;

    header.append(title, severity);

    const meta = document.createElement('div');
    meta.className = 'meta-row';
    meta.innerHTML = `
      <span class="meta-chip">Category: ${escapeHtml(finding.Category || 'Unknown')}</span>
      <span class="meta-chip">Affected: ${escapeHtml(finding.AffectedObject || 'Unknown')}</span>
      <span class="meta-chip">Detected: ${formatDate(finding.DetectedDate)}</span>
    `;

    const description = document.createElement('p');
    description.className = 'description';
    description.textContent = finding.Description || 'No description provided.';

    const impact = document.createElement('p');
    impact.className = 'impact';
    impact.innerHTML = `<strong>Impact:</strong> ${escapeHtml(finding.Impact || 'No impact provided.')}`;

    const remediation = document.createElement('p');
    remediation.className = 'remediation';
    remediation.innerHTML = `<strong>Remediation:</strong> ${escapeHtml(finding.Remediation || 'No remediation provided.')}`;

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
    const filtered = findings.filter((f) => normalizeSeverity(f.Severity) === severity);
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
        <strong>${escapeHtml(finding.Issue || 'Unknown Issue')}</strong>
        <div class="meta-row">
          <span>${escapeHtml(finding.Category || 'Uncategorized')}</span>
          <span>• Affected: ${escapeHtml(finding.AffectedObject || 'Unknown')}</span>
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
    arr.some((item) => typeof item === 'object' && (item.Issue || item.Severity || item.Category))
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
  if (!container) return;
  
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
      <span class="label">${escapeHtml(entry.label)}</span>
      <span class="value">${escapeHtml(String(entry.value))}</span>
      <span class="hint">${escapeHtml(entry.hint)}</span>
    `;
    container.appendChild(card);
  });
}

function buildReferences(refs) {
  const wrapper = document.createElement('div');
  wrapper.className = 'references';
  
  if (!refs) {
    wrapper.innerHTML = '<strong>References:</strong> Not provided';
    return wrapper;
  }

  const list = Array.isArray(refs) ? refs : [refs];
  const validRefs = list.filter(ref => ref && typeof ref === 'string');
  
  if (!validRefs.length) {
    wrapper.innerHTML = '<strong>References:</strong> Not provided';
    return wrapper;
  }
  
  const ul = document.createElement('ul');
  ul.className = 'reference-list';
  validRefs.forEach((ref) => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = ref;
    a.target = '_blank';
    a.rel = 'noreferrer noopener';
    a.textContent = ref;
    li.appendChild(a);
    ul.appendChild(li);
  });
  wrapper.innerHTML = '<strong>References:</strong>';
  wrapper.appendChild(ul);
  return wrapper;
}

function buildDetailsGrid(details = {}) {
  const grid = document.createElement('div');
  grid.className = 'detail-grid';
  
  if (!details || typeof details !== 'object') {
    grid.textContent = 'No additional detail provided.';
    return grid;
  }
  
  const entries = Object.entries(details);
  if (!entries.length) {
    grid.textContent = 'No additional detail provided.';
    return grid;
  }

  entries.forEach(([key, value]) => {
    const pill = document.createElement('span');
    pill.className = 'pill';
    
    let displayValue;
    if (value === null || value === undefined) {
      displayValue = 'N/A';
    } else if (Array.isArray(value)) {
      displayValue = value.join(', ') || 'Empty';
    } else if (typeof value === 'object') {
      displayValue = JSON.stringify(value);
    } else {
      displayValue = String(value);
    }
    
    pill.innerHTML = `<strong>${escapeHtml(key)}:</strong> ${escapeHtml(displayValue)}`;
    grid.appendChild(pill);
  });
  return grid;
}

function openModal(payload) {
  const modal = document.getElementById('modal');
  const body = document.getElementById('modal-body');
  if (!modal || !body) return;
  
  const isCategory = payload.findings;
  body.innerHTML = '';

  if (isCategory) {
    const title = document.createElement('h2');
    title.textContent = payload.title || 'Findings';
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
  header.innerHTML = `${getCategoryIcon(finding.Category)} <strong>${escapeHtml(finding.Issue || 'Unknown Issue')}</strong>`;

  const severityValue = normalizeSeverity(finding.Severity);
  const severity = document.createElement('span');
  severity.className = `severity-pill severity-${severityValue.toLowerCase()}`;
  severity.textContent = severityValue;

  header.appendChild(severity);

  const meta = document.createElement('div');
  meta.className = 'meta-row';
  meta.innerHTML = `
    <span class="meta-chip">Category: ${escapeHtml(finding.Category || 'Unknown')}</span>
    <span class="meta-chip">Affected: ${escapeHtml(finding.AffectedObject || 'Unknown')}</span>
    <span class="meta-chip">Detected: ${formatDate(finding.DetectedDate)}</span>
  `;

  const description = document.createElement('p');
  description.className = 'description';
  description.textContent = finding.Description || 'No description provided.';

  const impact = document.createElement('p');
  impact.className = 'impact';
  impact.innerHTML = `<strong>Impact:</strong> ${escapeHtml(finding.Impact || 'No impact provided.')}`;

  const remediation = document.createElement('p');
  remediation.className = 'remediation';
  remediation.innerHTML = `<strong>Remediation:</strong> ${escapeHtml(finding.Remediation || 'No remediation provided.')}`;

  const references = buildReferences(finding.RemediationReference || finding.References);
  const details = buildDetailsGrid(finding.Details);

  wrapper.append(header, meta, description, impact, remediation, references, details);
  return wrapper;
}

function closeModal() {
  const modal = document.getElementById('modal');
  if (modal) modal.hidden = true;
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
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
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
  reader.onerror = () => {
    setStatus('Error reading file.', 'error');
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
  if (!urlInput) return;
  
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
  if (!textarea) return;
  
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
  const fileInput = document.getElementById('file-input');
  const loadSample = document.getElementById('load-sample');
  const loadUrl = document.getElementById('load-url');
  const loadPasted = document.getElementById('load-pasted');
  const closeModalBtn = document.getElementById('close-modal');
  const modal = document.getElementById('modal');
  
  if (fileInput) fileInput.addEventListener('change', handleFileUpload);
  if (loadSample) loadSample.addEventListener('click', () => loadRemoteJson('./sample-data/audit-report.json'));
  if (loadUrl) loadUrl.addEventListener('click', handleUrlLoad);
  if (loadPasted) loadPasted.addEventListener('click', handlePastedJson);
  if (closeModalBtn) closeModalBtn.addEventListener('click', closeModal);
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target.id === 'modal') closeModal();
    });
  }
  
  initTabs();
  loadRemoteJson('./sample-data/audit-report.json');
}

window.addEventListener('DOMContentLoaded', boot);
