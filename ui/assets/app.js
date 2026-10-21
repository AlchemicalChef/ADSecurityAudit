// Report contract (v1.20.0): the JSON this dashboard expects mirrors the
// PowerShell module's ADSecurityFinding + Get-ADRiskScore output as closely
// as ConvertTo-Json serializes them. Keep this in sync with Common.ps1 /
// Scoring.ps1 - this comment exists specifically so the two don't drift
// apart again (see CHANGELOG v1.20.0 for the history of why).
//
//   {
//     "Summary": { Generated, PrivilegedAccounts, DomainControllers,
//                  DomainAdmins, EnterpriseAdmins, SchemaAdmins },
//     "RiskScore": {                       // optional; from Get-ADRiskScore
//       TotalScore, MaturityLevel, MaturityLabel, FindingCount,
//       WeightedPoints, SeverityCounts: { Critical, High, Medium, Low, Info },
//       CategoryScores: [ { Category, Score, Findings, RawPoints } ],
//       MitreSummary:   [ { Technique, Name, Count } ]
//     },
//     "Findings": [ {
//       Issue, Category, Severity, SeverityLevel, AnssiControl,
//       MitreTechnique, Weight, Description, Impact, Remediation,
//       RemediationReference, AffectedObject, DetectedDate, Details
//       // Details.HopChain/Source/Target/HopCount for Category=='Attack Paths'
//     } ]
//   }
//
// AD-only scope: no Entra/cloud fields belong here (see CHANGELOG v1.20.0 -
// a stale AzureAdSsoExpiredKeys field was removed from the sample data).

const SEVERITY_WEIGHTS = { Critical: 4, High: 3, Medium: 2, Low: 1 };
// v1.20.1: category emoji icons removed - they rendered inconsistently
// across platforms/print and read too casually for a report shown next to
// leadership. Category cards/finding titles now use text only, consistent
// with the static report's plain-text section headings.

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
      : 'Waiting for data...';
  }
}

function renderAdminCounts(metadata) {
  const entries = [
    { id: 'domain-admins-count', value: metadata.domainAdmins },
    { id: 'enterprise-admins-count', value: metadata.enterpriseAdmins },
    { id: 'schema-admins-count', value: metadata.schemaAdmins },
  ];
  entries.forEach((entry) => {
    const display = entry.value ?? '-';
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
    title.innerHTML = `<span>${escapeHtml(group.category)}</span>`;
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

// Change-management enrichment (v1.24.0) - EstimatedEffort/KnownRisks/
// BackupRollback/OperationalNotes, per Finding-Enrichment-Prompt.md.
// OperationalNotes is genuinely optional and omitted entirely when blank,
// mirroring how Reporting.ps1's Get-FindingHTML handles the same fields.
function buildEnrichmentHtml(finding) {
  const effort = finding.EstimatedEffort || '';
  const risks = finding.KnownRisks || '';
  const rollback = finding.BackupRollback || '';
  const notes = finding.OperationalNotes || '';

  if (!effort && !risks && !rollback) return '';

  let html = '<div class="enrichment-block">';
  if (effort) {
    html += `<p class="enrichment-item"><strong>Estimated Effort:</strong> ${escapeHtml(effort)}</p>`;
  }
  if (risks) {
    html += `<p class="enrichment-item"><strong>Known Risks:</strong> ${escapeHtml(risks)}</p>`;
  }
  if (rollback) {
    html += `<p class="enrichment-item"><strong>Backup / Rollback:</strong> ${escapeHtml(rollback)}</p>`;
  }
  if (notes) {
    html += `<p class="enrichment-item"><strong>Operational Notes:</strong> ${escapeHtml(notes)}</p>`;
  }
  html += '</div>';
  return html;
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
    title.innerHTML = `<span>${escapeHtml(finding.Issue || 'Unknown Issue')}</span>`;

    const severityValue = normalizeSeverity(finding.Severity);
    const severity = document.createElement('span');
    severity.className = `severity-pill severity-${severityValue.toLowerCase()}`;
    severity.textContent = severityValue;

    header.append(title, severity);

    const meta = document.createElement('div');
    meta.className = 'meta-row';
    meta.innerHTML = `
      <span class="meta-chip">Category: ${escapeHtml(finding.Category || 'Unknown')}</span>
      <span class="meta-chip">Affected: <span class="meta-code">${escapeHtml(finding.AffectedObject || 'Unknown')}</span></span>
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

    const enrichment = document.createElement('div');
    enrichment.innerHTML = buildEnrichmentHtml(finding);

    const references = buildReferences(finding.RemediationReference || finding.References);

    const button = document.createElement('button');
    button.className = 'detail-button';
    button.textContent = 'View details & evidence';
    button.addEventListener('click', () => openModal(finding));

    card.append(header, meta, description, impact, remediation, enrichment, references, button);
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
          <span>- Affected: <span class="meta-code">${escapeHtml(finding.AffectedObject || 'Unknown')}</span></span>
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

function truncateLabel(text, maxChars) {
  if (!text) return text;
  if (text.length <= maxChars) return text;
  if (maxChars <= 1) return text.slice(0, Math.max(maxChars, 0));
  return `${text.slice(0, maxChars - 1).trimEnd()}\u2026`;
}

function bandColorForScore(score) {
  if (score >= 75) return '#b3261e';
  if (score >= 50) return '#c8590b';
  if (score >= 25) return '#8a6200';
  return '#1a7f4e';
}

function buildGaugeSvg(score, color) {
  const clamped = Math.max(0, Math.min(100, score));
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const dash = circumference * (clamped / 100);
  const gap = circumference - dash;
  return `
    <div class="gauge-svg-wrap">
      <svg viewBox="0 0 160 160" role="img" aria-label="Risk score ${clamped} out of 100">
        <circle cx="80" cy="80" r="${radius}" fill="none" stroke="#e2e6ea" stroke-width="14" />
        <circle cx="80" cy="80" r="${radius}" fill="none" stroke="${color}" stroke-width="14"
                stroke-linecap="round" stroke-dasharray="${dash} ${gap}"
                transform="rotate(-90 80 80)" />
      </svg>
      <div class="gauge-center">
        <div class="num">${clamped}</div>
        <div class="of">/ 100</div>
      </div>
    </div>
  `;
}

function buildCategoryBarsSvg(categoryScores) {
  const rowHeight = 34;
  const chartWidth = 700;
  const labelWidth = 230;
  const barAreaW = chartWidth - labelWidth - 60;
  const height = rowHeight * categoryScores.length + 10;

  let rowsSvg = '';
  let y = 4;
  categoryScores.forEach((cat) => {
    const score = Math.round(cat.Score ?? 0);
    let barW = (score / 100) * barAreaW;
    if (barW < 2 && score > 0) barW = 2;
    const color = bandColorForScore(score);
    // ~7.2px/char at this font-size; reserve room for the " (NN)" suffix.
    const maxCategoryChars = Math.max(8, Math.floor(labelWidth / 7.2) - 6);
    const categoryLabel = truncateLabel(String(cat.Category ?? ''), maxCategoryChars);
    const findingsCount = cat.Findings ?? 0;
    const fullTitle = escapeHtml(`${cat.Category} (${findingsCount} finding${findingsCount === 1 ? '' : 's'})`);
    const label = escapeHtml(`${categoryLabel} (${findingsCount})`);
    const textY = y + 20;
    const numX = labelWidth + barAreaW + 10;
    rowsSvg += `
      <g><title>${fullTitle}</title>
      <text x="0" y="${textY}" font-size="12.5" fill="#1f2937" font-family="-apple-system,Segoe UI,sans-serif">${label}</text>
      <rect x="${labelWidth}" y="${y}" width="${barAreaW}" height="22" rx="4" fill="#e2e6ea" />
      <rect x="${labelWidth}" y="${y}" width="${barW}" height="22" rx="4" fill="${color}" />
      <text x="${numX}" y="${textY}" font-size="13" font-weight="700" fill="#1f2937" font-family="-apple-system,Segoe UI,sans-serif">${score}</text>
      </g>
    `;
    y += rowHeight;
  });

  return `<svg viewBox="0 0 ${chartWidth} ${height}" role="img" aria-label="Risk score by category">${rowsSvg}</svg>`;
}

function buildControlPathSvg(source, target, hopCount, color) {
  const maxNodeChars = 26;
  const srcFull = escapeHtml(source);
  const tgtFull = escapeHtml(target);
  const srcLabel = escapeHtml(truncateLabel(source, maxNodeChars));
  const tgtLabel = escapeHtml(truncateLabel(target, maxNodeChars));
  const hopLabel = hopCount === 1 ? '1 hop' : `${hopCount} hops`;
  return `
    <div class="control-path-svg">
      <svg viewBox="0 0 640 90" role="img" aria-label="${srcFull} to ${tgtFull} via ${hopLabel}">
        <g><title>${srcFull}</title>
        <rect x="4" y="24" width="220" height="42" rx="6" fill="#f4f6f8" stroke="#e2e6ea" />
        <text x="114" y="50" font-size="13" text-anchor="middle" fill="#1f2937" font-family="-apple-system,Segoe UI,sans-serif">${srcLabel}</text>
        </g>
        <line x1="228" y1="45" x2="404" y2="45" stroke="${color}" stroke-width="3" />
        <polygon points="404,38 418,45 404,52" fill="${color}" />
        <text x="316" y="34" font-size="12" text-anchor="middle" fill="${color}" font-weight="700" font-family="-apple-system,Segoe UI,sans-serif">${hopLabel}</text>
        <g><title>${tgtFull}</title>
        <rect x="418" y="24" width="218" height="42" rx="6" fill="#fdf1f0" stroke="${color}" />
        <text x="527" y="50" font-size="13" text-anchor="middle" fill="#1f2937" font-weight="700" font-family="-apple-system,Segoe UI,sans-serif">${tgtLabel}</text>
        </g>
      </svg>
    </div>
  `;
}

function renderRiskScore(riskScore) {
  const panel = document.getElementById('risk-score-panel');
  if (!panel) return;

  if (!riskScore || !riskScore.CategoryScores || !riskScore.CategoryScores.length) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;

  const score = Math.round(riskScore.TotalScore ?? 0);
  const color = bandColorForScore(score);
  const gaugeContainer = document.getElementById('risk-gauge');
  if (gaugeContainer) gaugeContainer.innerHTML = buildGaugeSvg(score, color);

  const metaEl = document.getElementById('risk-score-meta');
  if (metaEl) {
    metaEl.innerHTML = `<strong>${riskScore.FindingCount ?? 0}</strong> findings scored. Higher is worse - the global score equals the worst category's score, similar in spirit to PingCastle's approach.`;
  }

  const maturityLevel = Number(riskScore.MaturityLevel ?? 5);
  const headEl = document.getElementById('maturity-head');
  if (headEl) headEl.innerHTML = `${maturityLevel} <small>/ 5</small>`;
  setText('maturity-label', riskScore.MaturityLabel || '');

  const labelMap = {
    1: 'Critical gaps',
    2: 'Partial hygiene',
    3: 'Standard hardening',
    4: 'Advanced hardening',
    5: 'Optimal',
  };
  const stepper = document.getElementById('maturity-stepper');
  if (stepper) {
    stepper.innerHTML = '';
    for (let lvl = 1; lvl <= 5; lvl += 1) {
      const chip = document.createElement('div');
      let cls = 'maturity-chip';
      if (lvl === maturityLevel) cls = 'maturity-chip current';
      else if (lvl < maturityLevel) cls = 'maturity-chip reached';
      chip.className = cls;
      chip.innerHTML = `<span class="lvl">${lvl}</span><span>${labelMap[lvl]}</span>`;
      stepper.appendChild(chip);
    }
  }

  const barsContainer = document.getElementById('category-bars-svg');
  if (barsContainer) barsContainer.innerHTML = buildCategoryBarsSvg(riskScore.CategoryScores);

  const mitreSection = document.getElementById('mitre-section');
  const mitreBody = document.getElementById('mitre-table-body');
  if (mitreSection && mitreBody) {
    const mitreSummary = riskScore.MitreSummary || [];
    if (mitreSummary.length) {
      mitreSection.hidden = false;
      const maxCount = Math.max(...mitreSummary.map((t) => t.Count || 0), 1);
      mitreBody.innerHTML = mitreSummary
        .map((t) => {
          const barPct = Math.round(((t.Count || 0) / maxCount) * 100);
          return `
            <tr>
              <td class="mitre-id">${escapeHtml(t.Technique)}</td>
              <td>${escapeHtml(t.Name)}</td>
              <td><div class="mitre-bar-cell"><span class="mitre-bar-track"><span class="mitre-bar-fill" style="width:${barPct}%;"></span></span><span>${t.Count}</span></div></td>
            </tr>
          `;
        })
        .join('');
    } else {
      mitreSection.hidden = true;
    }
  }
}

function renderControlPaths(findings) {
  const panel = document.getElementById('control-paths-panel');
  const container = document.getElementById('control-paths-list');
  if (!panel || !container) return;

  const controlPaths = findings.filter((f) => f.Category === 'Attack Paths');
  if (!controlPaths.length) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  container.innerHTML = '';

  controlPaths
    .slice()
    .sort((a, b) => SEVERITY_WEIGHTS[normalizeSeverity(b.Severity)] - SEVERITY_WEIGHTS[normalizeSeverity(a.Severity)])
    .forEach((cp) => {
      const severityValue = normalizeSeverity(cp.Severity);
      const sevClass = severityValue.toLowerCase();
      const details = cp.Details || {};
      const hopChain = details.HopChain || cp.AffectedObject || '';

      const card = document.createElement('div');
      card.className = `finding-card severity-${sevClass}-card`;

      const header = document.createElement('div');
      header.className = 'finding-header';
      header.innerHTML = `<div class="finding-title">${escapeHtml(cp.Issue || 'Control path')}</div>`;
      const severity = document.createElement('span');
      severity.className = `severity-pill severity-${sevClass}`;
      severity.textContent = severityValue;
      header.appendChild(severity);
      card.appendChild(header);

      if (details.Source && details.Target) {
        const diagramColor = sevClass === 'critical' ? '#b3261e' : '#c8590b';
        const diagramHtml = buildControlPathSvg(details.Source, details.Target, Number(details.HopCount || 1), diagramColor);
        const diagramWrap = document.createElement('div');
        diagramWrap.innerHTML = diagramHtml;
        card.appendChild(diagramWrap);
      }

      const hopChainEl = document.createElement('p');
      hopChainEl.className = 'code-block';
      hopChainEl.textContent = hopChain;
      card.appendChild(hopChainEl);

      container.appendChild(card);
    });
}

function renderPriorityList(findings, riskScore) {
  const container = document.getElementById('priority-list');
  const panel = document.getElementById('priority-panel');
  if (!container || !panel) return;

  if (!findings.length) {
    panel.hidden = true;
    return;
  }

  const catScoreMap = {};
  (riskScore && riskScore.CategoryScores ? riskScore.CategoryScores : []).forEach((c) => {
    catScoreMap[c.Category] = c.Score || 0;
  });

  const groups = new Map();
  findings.forEach((f) => {
    const key = `${f.Category || 'Uncategorized'}|||${f.Issue || 'Unknown'}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  });

  const ranked = Array.from(groups.values())
    .map((group) => {
      const first = group[0];
      const severity = normalizeSeverity(first.Severity);
      return {
        group,
        category: first.Category || 'Uncategorized',
        issue: first.Issue || 'Unknown issue',
        severity,
        severityWeight: SEVERITY_WEIGHTS[severity] || 0,
        categoryScore: catScoreMap[first.Category] || 0,
        count: group.length,
      };
    })
    .sort((a, b) => b.severityWeight - a.severityWeight || b.categoryScore - a.categoryScore || b.count - a.count)
    .slice(0, 10);

  if (!ranked.length) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  container.innerHTML = '';

  ranked.forEach((r, index) => {
    const li = document.createElement('li');
    li.className = 'priority-item';

    const rank = document.createElement('span');
    rank.className = 'priority-rank';
    rank.textContent = String(index + 1);

    const link = document.createElement('button');
    link.type = 'button';
    link.className = 'priority-link';
    link.innerHTML = `${escapeHtml(r.issue)}<span class="priority-cat">${escapeHtml(r.category)} &middot; ${r.count} affected object${r.count === 1 ? '' : 's'}</span>`;
    link.addEventListener('click', () => {
      if (r.group.length === 1) {
        openModal(r.group[0]);
      } else {
        openModal({ title: r.issue, findings: r.group });
      }
    });

    const severityPill = document.createElement('span');
    severityPill.className = `severity-pill severity-${r.severity.toLowerCase()}`;
    severityPill.textContent = r.severity;

    li.append(rank, link, severityPill);
    container.appendChild(li);
  });
}


function render(findings, metadata = {}, riskScore = null) {
  state.findings = findings;
  state.metadata = metadata;
  state.riskScore = riskScore;
  renderSummary(findings);
  renderCategoryGrid(findings);
  renderFindings(findings);
  renderMeta(metadata);
  renderAdminCounts(metadata);
  renderRiskCallouts(findings);
  renderPriorityList(findings, riskScore);
  renderRiskScore(riskScore);
  renderControlPaths(findings);
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
    domainAdmins: summary.DomainAdmins || meta.DomainAdmins || stats.DomainAdmins,
    enterpriseAdmins: summary.EnterpriseAdmins || meta.EnterpriseAdmins || stats.EnterpriseAdmins,
    schemaAdmins: summary.SchemaAdmins || meta.SchemaAdmins || stats.SchemaAdmins,
  };
}

function extractRiskScore(data) {
  if (!data || typeof data !== 'object') return null;
  const riskScore = data.RiskScore || data.riskScore;
  if (!riskScore || typeof riskScore !== 'object') return null;
  return riskScore;
}

function renderMeta(metadata) {
  const container = document.getElementById('meta-stats');
  if (!container) return;
  
  container.innerHTML = '';
  const entries = [
    { label: 'Privileged Accounts', value: metadata.privilegedAccounts ?? '-', hint: 'High-risk identities to lock down' },
    { label: 'Domain Controllers', value: metadata.domainControllers ?? '-', hint: 'Visibility across replication scope' },
    { label: 'Audit generated', value: metadata.auditGenerated ? formatDate(metadata.auditGenerated) : '-', hint: 'Report timestamp' },
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
  header.innerHTML = `<strong>${escapeHtml(finding.Issue || 'Unknown Issue')}</strong>`;

  const severityValue = normalizeSeverity(finding.Severity);
  const severity = document.createElement('span');
  severity.className = `severity-pill severity-${severityValue.toLowerCase()}`;
  severity.textContent = severityValue;

  header.appendChild(severity);

  const meta = document.createElement('div');
  meta.className = 'meta-row';
  meta.innerHTML = `
    <span class="meta-chip">Category: ${escapeHtml(finding.Category || 'Unknown')}</span>
    <span class="meta-chip">Affected: <span class="meta-code">${escapeHtml(finding.AffectedObject || 'Unknown')}</span></span>
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

  const enrichment = document.createElement('div');
  enrichment.innerHTML = buildEnrichmentHtml(finding);

  const references = buildReferences(finding.RemediationReference || finding.References);
  const details = buildDetailsGrid(finding.Details);

  wrapper.append(header, meta, description, impact, remediation, enrichment, references, details);
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
  const riskScore = extractRiskScore(parsed);
  render(findings, metadata, riskScore);
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
  const printBtn = document.getElementById('print-view');

  if (printBtn) printBtn.addEventListener('click', () => window.print());
  
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
