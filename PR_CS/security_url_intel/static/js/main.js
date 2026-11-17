/**
 * Security Analysis & URL Intelligence Generator - Main Frontend Logic (main.js)
 * Manages API communication, reactive UI state, animations, tabs, exports, and toasts.
 */

(function () {
  'use strict';

  // Global State Storage
  window.currentDorksData = null;
  window.currentAnalysisData = null;

  // DOM Elements Cache
  const elements = {
    // Theme & Nav
    themeToggleBtn: document.getElementById('themeToggleBtn'),
    mobileMenuBtn: document.getElementById('mobileMenuBtn'),
    navMenu: document.getElementById('navMenu'),
    liveUtcClock: document.getElementById('liveUtcClock'),

    // Ethical Modal
    ethicsModal: document.getElementById('ethicsModal'),
    acknowledgeEthicsBtn: document.getElementById('acknowledgeEthicsBtn'),

    // OSINT Generator Form & Inputs
    dorkForm: document.getElementById('dorkForm'),
    dorkDomain: document.getElementById('dorkDomain'),
    clearDorkDomain: document.getElementById('clearDorkDomain'),
    generateDorksBtn: document.getElementById('generateDorksBtn'),
    dorkAuthorized: document.getElementById('dorkAuthorized'),
    selectAllCategoriesBtn: document.getElementById('selectAllCategoriesBtn'),
    clearAllCategoriesBtn: document.getElementById('clearAllCategoriesBtn'),

    // OSINT Results
    dorkResultsContainer: document.getElementById('dorkResultsContainer'),
    dorkResultsCountBadge: document.getElementById('dorkResultsCountBadge'),
    dorkTargetDomainBadge: document.getElementById('dorkTargetDomainBadge'),
    dorkCategoryFilters: document.getElementById('dorkCategoryFilters'),
    dorkCardsGrid: document.getElementById('dorkCardsGrid'),
    copyAllDorksBtn: document.getElementById('copyAllDorksBtn'),
    exportDorksDropdownBtn: document.getElementById('exportDorksDropdownBtn'),
    dorksExportMenu: document.getElementById('dorksExportMenu'),

    // URL Analyzer Form & Inputs
    analyzerForm: document.getElementById('analyzerForm'),
    analyzerUrl: document.getElementById('analyzerUrl'),
    clearAnalyzerUrl: document.getElementById('clearAnalyzerUrl'),
    analyzerAuthorized: document.getElementById('analyzerAuthorized'),
    analyzeUrlBtn: document.getElementById('analyzeUrlBtn'),

    // Scanner Overlay
    scannerOverlay: document.getElementById('scannerOverlay'),
    scannerProgressText: document.getElementById('scannerProgressText'),

    // URL Analyzer Results
    analyzerResultsContainer: document.getElementById('analyzerResultsContainer'),
    riskGaugeMeter: document.getElementById('riskGaugeMeter'),
    riskScoreValue: document.getElementById('riskScoreValue'),
    riskLevelBadge: document.getElementById('riskLevelBadge'),
    riskTargetUrl: document.getElementById('riskTargetUrl'),
    riskNarrativeText: document.getElementById('riskNarrativeText'),
    metricRiskPercentage: document.getElementById('metricRiskPercentage'),
    metricIp: document.getElementById('metricIp'),
    metricSafety: document.getElementById('metricSafety'),
    metricScheme: document.getElementById('metricScheme'),
    metricTld: document.getElementById('metricTld'),
    metricLength: document.getElementById('metricLength'),
    metricSsl: document.getElementById('metricSsl'),
    metricHops: document.getElementById('metricHops'),
    metricFlags: document.getElementById('metricFlags'),
    copyAnalysisSummaryBtn: document.getElementById('copyAnalysisSummaryBtn'),
    exportAnalysisDropdownBtn: document.getElementById('exportAnalysisDropdownBtn'),
    analysisExportMenu: document.getElementById('analysisExportMenu'),
    flagsTabCount: document.getElementById('flagsTabCount'),
    analysisTabPanels: document.getElementById('analysisTabPanels'),

    // Tab Panels & Bodies
    structureTableBody: document.getElementById('structureTableBody'),
    queryParamsListContainer: document.getElementById('queryParamsListContainer'),
    queryParamCountLabel: document.getElementById('queryParamCountLabel'),
    primaryIpDisplay: document.getElementById('primaryIpDisplay'),
    dnsDomainValue: document.getElementById('dnsDomainValue'),
    dnsHostValue: document.getElementById('dnsHostValue'),
    dnsIpv4Tags: document.getElementById('dnsIpv4Tags'),
    dnsIpv6Tags: document.getElementById('dnsIpv6Tags'),
    dnsPtrValue: document.getElementById('dnsPtrValue'),
    whoisRegistrar: document.getElementById('whoisRegistrar'),
    whoisAge: document.getElementById('whoisAge'),
    whoisCreated: document.getElementById('whoisCreated'),
    whoisExpires: document.getElementById('whoisExpires'),
    sslStatusNotice: document.getElementById('sslStatusNotice'),
    sslIssuer: document.getElementById('sslIssuer'),
    sslSubject: document.getElementById('sslSubject'),
    sslValidFrom: document.getElementById('sslValidFrom'),
    sslValidTo: document.getElementById('sslValidTo'),
    sslDaysRemaining: document.getElementById('sslDaysRemaining'),
    sslSelfSigned: document.getElementById('sslSelfSigned'),
    sslSanTags: document.getElementById('sslSanTags'),
    redirectHopCountBadge: document.getElementById('redirectHopCountBadge'),
    redirectDowngradeBadge: document.getElementById('redirectDowngradeBadge'),
    redirectCrossDomainBadge: document.getElementById('redirectCrossDomainBadge'),
    redirectTimelineContainer: document.getElementById('redirectTimelineContainer'),
    flagsGridContainer: document.getElementById('flagsGridContainer'),

    // Toasts
    toastStack: document.getElementById('toastStack')
  };

  /* ==========================================================================
     1. Initialization & LifeCycle
     ========================================================================== */
  document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initEthicsModal();
    initLiveClock();
    initMobileNav();
    initQuickPicks();
    initCategoryChips();
    initSearchEngineRadios();
    initEventListeners();
    initTilt();
    animateStatsCounters();
    restorePreviousInputs();
  });

  /* ==========================================================================
     2. Theme & UI Helpers
     ========================================================================== */
  function initTheme() {
    const savedTheme = localStorage.getItem('security_intel_theme') || 'dark';
    applyTheme(savedTheme);

    elements.themeToggleBtn.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      applyTheme(newTheme);
      showToast(`Switched to ${newTheme} mode`, 'info');
    });
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    document.body.className = `theme-${theme}`;
    localStorage.setItem('security_intel_theme', theme);

    if (window.updateThreeTheme) {
      window.updateThreeTheme(theme);
    }
  }

  function initEthicsModal() {
    const accepted = localStorage.getItem('security_intel_ethics_accepted');
    if (!accepted && elements.ethicsModal) {
      elements.ethicsModal.classList.add('show');
    }

    if (elements.acknowledgeEthicsBtn) {
      elements.acknowledgeEthicsBtn.addEventListener('click', () => {
        localStorage.setItem('security_intel_ethics_accepted', 'true');
        elements.ethicsModal.classList.remove('show');
        showToast('Authorized research terms acknowledged.', 'success');
      });
    }
  }

  function initLiveClock() {
    function updateClock() {
      const now = new Date();
      const hours = String(now.getUTCHours()).padStart(2, '0');
      const minutes = String(now.getUTCMinutes()).padStart(2, '0');
      const seconds = String(now.getUTCSeconds()).padStart(2, '0');
      if (elements.liveUtcClock) {
        elements.liveUtcClock.textContent = `${hours}:${minutes}:${seconds} UTC`;
      }
    }
    updateClock();
    setInterval(updateClock, 1000);
  }

  function initMobileNav() {
    if (!elements.mobileMenuBtn || !elements.navMenu) return;
    elements.mobileMenuBtn.addEventListener('click', () => {
      const isVisible = elements.navMenu.style.display === 'flex';
      elements.navMenu.style.display = isVisible ? 'none' : 'flex';
      elements.navMenu.style.flexDirection = 'column';
      elements.navMenu.style.position = 'absolute';
      elements.navMenu.style.top = '72px';
      elements.navMenu.style.left = '0';
      elements.navMenu.style.width = '100%';
      elements.navMenu.style.background = 'var(--bg-card)';
      elements.navMenu.style.padding = '1.5rem';
    });
  }

  function initTilt() {
    if (typeof VanillaTilt !== 'undefined') {
      VanillaTilt.init(document.querySelectorAll('[data-tilt]'), {
        max: 8,
        speed: 400,
        glare: true,
        'max-glare': 0.15
      });
    }
  }

  function animateStatsCounters() {
    const statNumbers = document.querySelectorAll('.stat-number[data-target]');
    statNumbers.forEach(el => {
      const target = parseInt(el.getAttribute('data-target'), 10);
      if (isNaN(target)) return;

      let count = 0;
      const step = Math.max(1, Math.floor(target / 20));
      const interval = setInterval(() => {
        count += step;
        if (count >= target) {
          el.textContent = `${target}+`;
          clearInterval(interval);
        } else {
          el.textContent = count;
        }
      }, 40);
    });
  }

  function restorePreviousInputs() {
    const lastDomain = localStorage.getItem('last_dork_domain');
    const lastUrl = localStorage.getItem('last_analyzer_url');
    if (lastDomain && elements.dorkDomain) elements.dorkDomain.value = lastDomain;
    if (lastUrl && elements.analyzerUrl) elements.analyzerUrl.value = lastUrl;
  }

  /* ==========================================================================
     3. Category Chips & Quick Picks
     ========================================================================== */
  function initQuickPicks() {
    // OSINT Quick domain chips
    document.querySelectorAll('.quick-chip[data-domain]').forEach(btn => {
      btn.addEventListener('click', () => {
        elements.dorkDomain.value = btn.getAttribute('data-domain');
        elements.dorkDomain.focus();
      });
    });

    if (elements.clearDorkDomain) {
      elements.clearDorkDomain.addEventListener('click', () => {
        elements.dorkDomain.value = '';
        elements.dorkDomain.focus();
      });
    }

    // URL Analyzer Test Scenario buttons
    document.querySelectorAll('.test-scenario-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        elements.analyzerUrl.value = btn.getAttribute('data-url');
        elements.analyzerUrl.focus();
      });
    });

    if (elements.clearAnalyzerUrl) {
      elements.clearAnalyzerUrl.addEventListener('click', () => {
        elements.analyzerUrl.value = '';
        elements.analyzerUrl.focus();
      });
    }
  }

  function initCategoryChips() {
    const chips = document.querySelectorAll('.category-chip');
    chips.forEach(chip => {
      const checkbox = chip.querySelector('input[type="checkbox"]');
      chip.addEventListener('click', (e) => {
        // Prevent double trigger if clicking label/inner directly
        if (e.target.tagName !== 'INPUT') {
          checkbox.checked = !checkbox.checked;
        }
        chip.classList.toggle('active', checkbox.checked);
      });
    });

    if (elements.selectAllCategoriesBtn) {
      elements.selectAllCategoriesBtn.addEventListener('click', () => {
        chips.forEach(chip => {
          chip.classList.add('active');
          chip.querySelector('input[type="checkbox"]').checked = true;
        });
      });
    }

    if (elements.clearAllCategoriesBtn) {
      elements.clearAllCategoriesBtn.addEventListener('click', () => {
        chips.forEach(chip => {
          chip.classList.remove('active');
          chip.querySelector('input[type="checkbox"]').checked = false;
        });
      });
    }
  }

  function initSearchEngineRadios() {
    const labels = document.querySelectorAll('.engine-radio-label');
    labels.forEach(label => {
      const radio = label.querySelector('input[type="radio"]');
      radio.addEventListener('change', () => {
        labels.forEach(l => l.classList.remove('active'));
        if (radio.checked) {
          label.classList.add('active');
        }
      });
    });
  }

  /* ==========================================================================
     4. OSINT Query Generator Pipeline
     ========================================================================== */
  function initEventListeners() {
    // OSINT Form Submit
    if (elements.dorkForm) {
      elements.dorkForm.addEventListener('submit', handleDorkSubmit);
    }

    // Copy All Dorks
    if (elements.copyAllDorksBtn) {
      elements.copyAllDorksBtn.addEventListener('click', copyAllDorkQueries);
    }

    // Export Dropdowns toggle
    setupDropdown(elements.exportDorksDropdownBtn, elements.dorksExportMenu);
    setupDropdown(elements.exportAnalysisDropdownBtn, elements.analysisExportMenu);

    // Export options click
    document.querySelectorAll('.export-option').forEach(btn => {
      btn.addEventListener('click', handleExportDownload);
    });

    // URL Analyzer Form Submit
    if (elements.analyzerForm) {
      elements.analyzerForm.addEventListener('submit', handleAnalyzerSubmit);
    }

    // Copy Analysis Summary
    if (elements.copyAnalysisSummaryBtn) {
      elements.copyAnalysisSummaryBtn.addEventListener('click', copyAnalysisSummary);
    }

    // Analysis View Filter Buttons (All Formatted Data vs Specific Section)
    document.querySelectorAll('.view-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetView = btn.getAttribute('data-view');
        document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        if (targetView === 'all') {
          if (elements.analysisTabPanels) {
            elements.analysisTabPanels.classList.add('show-all');
          }
          document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('active'));
        } else {
          if (elements.analysisTabPanels) {
            elements.analysisTabPanels.classList.remove('show-all');
          }
          document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
          const panel = document.getElementById(targetView);
          if (panel) {
            panel.classList.add('active');
            panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        }
      });
    });

    // Backward compatibility for tab-btn if clicked
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

        btn.classList.add('active');
        const panel = document.getElementById(targetTab);
        if (panel) panel.classList.add('active');
      });
    });

    // Knowledge Base Sub-Navigation Tabs
    document.querySelectorAll('.kb-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetKb = btn.getAttribute('data-kb');
        document.querySelectorAll('.kb-tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.kb-panel').forEach(p => p.classList.remove('active'));

        btn.classList.add('active');
        const panel = document.getElementById(targetKb);
        if (panel) panel.classList.add('active');
      });
    });

    // Close dropdowns when clicking outside
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.export-dropdown-wrapper')) {
        if (elements.dorksExportMenu) elements.dorksExportMenu.classList.remove('show');
        if (elements.analysisExportMenu) elements.analysisExportMenu.classList.remove('show');
      }
    });
  }

  function setupDropdown(btn, menu) {
    if (!btn || !menu) return;
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      menu.classList.toggle('show');
    });
  }

  async function handleDorkSubmit(e) {
    e.preventDefault();

    const domain = elements.dorkDomain.value.trim();
    if (!domain) {
      showToast('Please enter a target domain name.', 'error');
      elements.dorkDomain.focus();
      return;
    }

    if (!elements.dorkAuthorized.checked) {
      showToast('Please check the authorization acknowledgment.', 'error');
      elements.dorkAuthorized.focus();
      return;
    }

    // Gather selected categories
    const selectedCats = [];
    document.querySelectorAll('.category-chip input:checked').forEach(cb => {
      selectedCats.push(cb.value);
    });

    if (selectedCats.length === 0) {
      showToast('Please select at least one intelligence category.', 'error');
      return;
    }

    const activeEngineRadio = document.querySelector('input[name="searchEngine"]:checked');
    const engine = activeEngineRadio ? activeEngineRadio.value : 'google';

    // UI Loading state
    elements.generateDorksBtn.classList.add('loading');
    elements.generateDorksBtn.disabled = true;

    try {
      const response = await fetch('/api/dorks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: domain,
          categories: selectedCats,
          engine: engine,
          authorized: true
        })
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        throw new Error(result.error || `HTTP ${response.status}`);
      }

      window.currentDorksData = result.data;
      localStorage.setItem('last_dork_domain', domain);
      renderDorkResults(result.data);
      showToast(`Generated ${result.data.total_queries} queries for ${result.data.domain}`, 'success');

      // Smooth scroll to results
      elements.dorkResultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (err) {
      showToast(`Error: ${err.message}`, 'error');
    } finally {
      elements.generateDorksBtn.classList.remove('loading');
      elements.generateDorksBtn.disabled = false;
    }
  }

  function renderDorkResults(data) {
    elements.dorkResultsContainer.classList.remove('hidden');
    elements.dorkResultsCountBadge.textContent = `${data.total_queries} Queries`;
    elements.dorkTargetDomainBadge.textContent = data.domain;

    // Build Category Filter Pills
    elements.dorkCategoryFilters.innerHTML = `
      <button type="button" class="filter-pill active" data-filter="all">All (${data.total_queries})</button>
    `;

    Object.values(data.categories).forEach(cat => {
      const pill = document.createElement('button');
      pill.type = 'button';
      pill.className = 'filter-pill';
      pill.setAttribute('data-filter', cat.category_id);
      pill.textContent = `${cat.name} (${cat.count})`;
      elements.dorkCategoryFilters.appendChild(pill);
    });

    // Render Query Cards
    renderDorkCards('all');

    // Filter pill click listener
    elements.dorkCategoryFilters.querySelectorAll('.filter-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        elements.dorkCategoryFilters.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        renderDorkCards(pill.getAttribute('data-filter'));
      });
    });
  }

  function renderDorkCards(filterId) {
    if (!window.currentDorksData) return;
    elements.dorkCardsGrid.innerHTML = '';

    const categories = window.currentDorksData.categories;
    const engine = window.currentDorksData.engine;

    Object.values(categories).forEach(cat => {
      if (filterId !== 'all' && cat.category_id !== filterId) return;

      cat.queries.forEach(q => {
        const card = document.createElement('div');
        card.className = 'dork-card';
        card.setAttribute('data-category', cat.category_id);

        card.innerHTML = `
          <div>
            <div class="dork-card-header">
              <span class="dork-label">${escapeHtml(q.label)}</span>
              <span class="dork-category-badge">${escapeHtml(cat.name)}</span>
            </div>
            <p class="dork-desc">${escapeHtml(q.description)}</p>
            <div class="dork-query-box">
              <code class="dork-query-code">${escapeHtml(q.query)}</code>
            </div>
          </div>
          <div class="dork-card-footer">
            <button type="button" class="btn btn-sm btn-outline copy-dork-btn">
              <i class="fas fa-copy"></i> Copy Query
            </button>
            <a href="${escapeHtml(q.search_url)}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-primary">
              <i class="fas fa-external-link-alt"></i> Open in ${capitalize(engine)}
            </a>
          </div>
        `;

        // Wire copy button
        const copyBtn = card.querySelector('.copy-dork-btn');
        copyBtn.addEventListener('click', () => {
          copyToClipboard(q.query);
          showToast(`Copied query: "${q.label}"`, 'success');
        });

        elements.dorkCardsGrid.appendChild(card);
      });
    });

    initTilt();
  }

  function copyAllDorkQueries() {
    if (!window.currentDorksData) return;
    const lines = [];
    Object.values(window.currentDorksData.categories).forEach(cat => {
      cat.queries.forEach(q => {
        lines.push(`# ${q.label} [${cat.name}]`);
        lines.push(q.query);
        lines.push('');
      });
    });

    copyToClipboard(lines.join('\n'));
    showToast(`Copied all ${window.currentDorksData.total_queries} queries to clipboard!`, 'success');
  }

  /* ==========================================================================
     5. URL Analyzer Pipeline
     ========================================================================== */
  async function handleAnalyzerSubmit(e) {
    e.preventDefault();

    const rawUrl = elements.analyzerUrl.value.trim();
    if (!rawUrl) {
      showToast('Please enter a target URL to analyze.', 'error');
      elements.analyzerUrl.focus();
      return;
    }

    if (!elements.analyzerAuthorized.checked) {
      showToast('Please check the authorization acknowledgment.', 'error');
      elements.analyzerAuthorized.focus();
      return;
    }

    // UI Scanner state
    elements.analyzeUrlBtn.classList.add('loading');
    elements.analyzeUrlBtn.disabled = true;
    elements.scannerOverlay.classList.remove('hidden');
    elements.analyzerResultsContainer.classList.add('hidden');

    // Scanning progress text simulation
    const steps = [
      'Resolving DNS records and evaluating SSL handshake...',
      'Tracing redirect chain and checking for protocol downgrades...',
      'Evaluating heuristic threat rules for homoglyphs and deception...',
      'Compiling risk telemetry report...'
    ];
    let stepIndex = 0;
    const progressInterval = setInterval(() => {
      stepIndex = (stepIndex + 1) % steps.length;
      if (elements.scannerProgressText) {
        elements.scannerProgressText.textContent = steps[stepIndex];
      }
    }, 700);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: rawUrl,
          authorized: true
        })
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        throw new Error(result.error || `HTTP ${response.status}`);
      }

      window.currentAnalysisData = result.data;
      localStorage.setItem('last_analyzer_url', rawUrl);
      if (elements.analyzerUrl && result.data.url) {
        elements.analyzerUrl.value = result.data.url;
      }

      // Hide scanner before rendering results so scrollIntoView aligns smoothly
      elements.scannerOverlay.classList.add('hidden');
      clearInterval(progressInterval);

      renderAnalysisResults(result.data);
      showToast(`Scan complete: ${result.data.risk.level} Risk (${result.data.risk.score}/100)`, 'success');

      // Scroll smoothly to results
      elements.analyzerResultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (err) {
      showToast(`Analysis Failed: ${err.message}`, 'error');
    } finally {
      clearInterval(progressInterval);
      elements.scannerOverlay.classList.add('hidden');
      elements.analyzeUrlBtn.classList.remove('loading');
      elements.analyzeUrlBtn.disabled = false;
    }
  }

  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = (val !== null && val !== undefined) ? String(val) : '-';
  }

  function setHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = (html !== null && html !== undefined) ? String(html) : '';
  }

  function renderAnalysisResults(data) {
    if (!data) return;
    const container = document.getElementById('analyzerResultsContainer');
    if (container) container.classList.remove('hidden');

    const risk = data.risk || {};
    const score = (typeof risk.score === 'number') ? risk.score : 0;
    const level = risk.level || 'Low';
    const structure = data.structure || {};
    const domainDetails = data.domain_details || {};
    const redirects = data.redirects || {};
    const flags = data.flags || [];
    const ssl = domainDetails.ssl || {};
    const whois = domainDetails.whois || {};

    // 1. Circular Risk Gauge Animation (SVG-safe: avoid direct .className assignment on SVGCircleElement)
    try {
      const meter = document.getElementById('riskGaugeMeter');
      const circumference = 314.159; // 2 * PI * 50
      const offset = Math.max(0, circumference - (score / 100) * circumference);
      if (meter) {
        meter.style.strokeDasharray = `${circumference}`;
        meter.style.strokeDashoffset = `${offset}`;
        meter.setAttribute('stroke-dashoffset', String(offset));
        const riskClass = level === 'High' ? 'risk-high' : (level === 'Medium' ? 'risk-medium' : 'risk-low');
        meter.setAttribute('class', `gauge-meter ${riskClass}`);
      }
    } catch (e) {
      console.warn('Error setting SVG gauge meter:', e);
    }

    // Risk Level Badge
    const badge = document.getElementById('riskLevelBadge');
    if (badge) {
      badge.className = 'risk-level-badge';
      if (level === 'High') {
        badge.classList.add('level-high');
        badge.textContent = `HIGH RISK (${score}%)`;
      } else if (level === 'Medium') {
        badge.classList.add('level-medium');
        badge.textContent = `MEDIUM RISK (${score}%)`;
      } else {
        badge.classList.add('level-low');
        badge.textContent = `LOW RISK (${score}%)`;
      }
    }

    // Animate score counter inside gauge
    const scoreValEl = document.getElementById('riskScoreValue');
    if (scoreValEl) {
      animateNumber(scoreValEl, score);
    }

    // Update prominent Risk Percentage metric pill in metrics ribbon
    const riskPill = document.getElementById('metricRiskPercentage');
    if (riskPill) {
      riskPill.textContent = `${score}%`;
      riskPill.className = `metric-val ${score >= 70 ? 'text-red' : (score >= 30 ? 'text-yellow' : 'text-green')}`;
    }

    // Populate Primary IP and Safety Index in Metrics Ribbon
    const primaryIp = (domainDetails.ipv4 && domainDetails.ipv4.length > 0)
      ? domainDetails.ipv4[0]
      : (domainDetails.host || 'Unresolved');
    setText('metricIp', primaryIp);

    const safetyVal = (risk.safety_score !== undefined) ? risk.safety_score : Math.max(0, 100 - score);
    const safetyEl = document.getElementById('metricSafety');
    if (safetyEl) {
      safetyEl.textContent = `${safetyVal}% Safe`;
      safetyEl.className = `metric-val ${safetyVal >= 70 ? 'text-green' : (safetyVal >= 40 ? 'text-yellow' : 'text-red')}`;
    }

    setText('riskTargetUrl', data.url || '-');
    setText('riskNarrativeText', risk.summary || 'Passive reconnaissance completed successfully.');

    // Quick Metrics
    setText('metricScheme', structure.scheme ? structure.scheme.toUpperCase() : 'HTTPS');
    setText('metricTld', structure.tld ? `.${structure.tld}` : '(none)');
    setText('metricLength', `${structure.length || 0} chars`);
    setText('metricSsl', ssl.enabled ? 'Active' : 'Inactive');
    setText('metricHops', redirects.hop_count !== undefined ? redirects.hop_count : 0);
    setText('metricFlags', flags.length);
    setText('flagsTabCount', flags.length);

    // 2. Set All-In-One Formatted View (ensures URL Structure, Domain/DNS/IP, SSL, Redirects & Flags are all visible simultaneously)
    const panels = document.getElementById('analysisTabPanels');
    if (panels) panels.classList.add('show-all');

    document.querySelectorAll('.view-btn').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-view') === 'all');
    });
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('active'));

    // 3. Tab 1: Structure Table
    try {
      renderStructureTable(structure);
    } catch (e) {
      console.error('Error rendering structure table:', e);
    }

    // 4. Tab 2: Domain, DNS, IP & SSL
    try {
      renderDomainAndSsl(domainDetails);
    } catch (e) {
      console.error('Error rendering domain & ssl:', e);
    }

    // 5. Tab 3: Redirect Sequence Timeline
    try {
      renderRedirectTimeline(redirects);
    } catch (e) {
      console.error('Error rendering redirect timeline:', e);
    }

    // 6. Tab 4: Security Flags Grid
    try {
      renderSecurityFlags(flags);
    } catch (e) {
      console.error('Error rendering security flags:', e);
    }

    initTilt();
  }

  function renderStructureTable(structure) {
    if (!structure) return;

    const rows = [
      { comp: 'Scheme (Protocol)', val: structure.scheme || 'http', note: structure.scheme === 'https' ? 'Encrypted TLS' : 'Unencrypted Cleartext' },
      { comp: 'Host (Netloc)', val: structure.host || '-', note: structure.host || '-' },
      { comp: 'Subdomain', val: structure.subdomain || '(none)', note: structure.subdomain ? `${structure.subdomain.split('.').length} levels` : 'No subdomain' },
      { comp: 'Registered Domain', val: structure.domain || '-', note: 'Primary identity' },
      { comp: 'Top-Level Domain (TLD)', val: structure.tld ? `.${structure.tld}` : '(none)', note: structure.tld || '(none)' },
      { comp: 'Port', val: structure.port || (structure.scheme === 'https' ? 443 : 80), note: structure.is_standard_port ? 'Standard Web Port' : 'Non-standard port' },
      { comp: 'Path', val: structure.path || '/', note: `${structure.path_length || (structure.path ? structure.path.length : 1)} characters` },
      { comp: 'Query String', val: structure.query_string || '(empty)', note: `${structure.query_param_count || 0} parameters` },
      { comp: 'Fragment', val: structure.fragment || '(none)', note: 'Client-side anchor' },
      { comp: 'Total URL Length', val: `${structure.length || 0} characters`, note: (structure.length || 0) > 75 ? 'Elevated Length' : 'Normal Length' }
    ];

    const body = document.getElementById('structureTableBody');
    if (body) {
      body.innerHTML = rows.map(r => `
        <tr>
          <td><strong>${escapeHtml(r.comp)}</strong></td>
          <td><code>${escapeHtml(String(r.val))}</code></td>
          <td class="text-muted">${escapeHtml(r.note)}</td>
        </tr>
      `).join('');
    }

    setText('queryParamCountLabel', structure.query_param_count || 0);
    const queryContainer = document.getElementById('queryParamsListContainer');
    if (queryContainer) {
      if (structure.query_params && structure.query_params.length > 0) {
        queryContainer.innerHTML = `
          <table class="cyber-table compact-table">
            <thead>
              <tr><th>Parameter Key</th><th>Assigned Value</th></tr>
            </thead>
            <tbody>
              ${structure.query_params.map(p => `
                <tr>
                  <td><code>${escapeHtml(p.key)}</code></td>
                  <td><code>${escapeHtml(p.value)}</code></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `;
      } else {
        queryContainer.innerHTML = '<p class="text-muted">No query parameters present in URL.</p>';
      }
    }
  }

  function renderDomainAndSsl(domainDetails) {
    if (!domainDetails) return;

    setText('dnsDomainValue', domainDetails.domain || '-');
    setText('dnsHostValue', domainDetails.host || '-');

    // Primary IP Callout
    const primaryIpDisplay = document.getElementById('primaryIpDisplay');
    if (primaryIpDisplay) {
      if (domainDetails.ipv4 && domainDetails.ipv4.length > 0) {
        primaryIpDisplay.textContent = domainDetails.ipv4.join('  •  ');
      } else {
        primaryIpDisplay.textContent = domainDetails.host ? `Unresolved (${domainDetails.host})` : 'None / Offline';
      }
    }

    // IPv4
    const ipv4Tags = document.getElementById('dnsIpv4Tags');
    if (ipv4Tags) {
      if (domainDetails.ipv4 && domainDetails.ipv4.length > 0) {
        ipv4Tags.innerHTML = domainDetails.ipv4.map(ip => `<span class="cyber-tag">${escapeHtml(ip)}</span>`).join('');
      } else {
        ipv4Tags.innerHTML = '<span class="cyber-tag">Unresolved</span>';
      }
    }

    // IPv6
    const ipv6Tags = document.getElementById('dnsIpv6Tags');
    if (ipv6Tags) {
      if (domainDetails.ipv6 && domainDetails.ipv6.length > 0) {
        ipv6Tags.innerHTML = domainDetails.ipv6.map(ip => `<span class="cyber-tag">${escapeHtml(ip)}</span>`).join('');
      } else {
        ipv6Tags.innerHTML = '<span class="cyber-tag">None</span>';
      }
    }

    setText('dnsPtrValue', domainDetails.reverse_dns || 'No PTR Record');

    // WHOIS
    const whois = domainDetails.whois || {};
    setText('whoisRegistrar', whois.registrar || 'Unavailable');
    const ageText = (whois.age_days !== null && whois.age_days !== undefined)
      ? `${whois.age_days} days (${(whois.age_days / 365.25).toFixed(1)} yrs)`
      : 'Unavailable';
    setText('whoisAge', ageText);
    setText('whoisCreated', whois.creation_date || 'Unavailable');
    setText('whoisExpires', whois.expiration_date || 'Unavailable');

    // SSL
    const ssl = domainDetails.ssl || {};
    const sslNotice = document.getElementById('sslStatusNotice');
    if (ssl.enabled) {
      if (sslNotice) {
        sslNotice.innerHTML = `
          <div class="alert-box alert-success mb-3" style="background: rgba(0, 245, 160, 0.1); border: 1px solid var(--neon-green); color: var(--neon-green); padding: 0.6rem 0.85rem; border-radius: 6px;">
            <i class="fas fa-check-shield"></i> SSL Handshake Succeeded (CA Trusted)
          </div>
        `;
      }
      setText('sslIssuer', ssl.issuer || 'Unknown');
      setText('sslSubject', ssl.subject || 'Unknown');
      setText('sslValidFrom', ssl.valid_from || 'Unknown');
      setText('sslValidTo', ssl.valid_to || 'Unknown');
      const daysText = (ssl.days_remaining !== null && ssl.days_remaining !== undefined)
        ? `${ssl.days_remaining} days ${ssl.is_expired ? '(EXPIRED)' : 'remaining'}`
        : 'Unknown';
      setText('sslDaysRemaining', daysText);
      setText('sslSelfSigned', ssl.is_self_signed ? 'YES (Untrusted)' : 'No (CA Verified)');

      const sanTags = document.getElementById('sslSanTags');
      if (sanTags) {
        if (ssl.sans && ssl.sans.length > 0) {
          sanTags.innerHTML = ssl.sans.map(san => `<span class="cyber-tag">${escapeHtml(san)}</span>`).join('');
        } else {
          sanTags.innerHTML = '<span class="cyber-tag">None</span>';
        }
      }
    } else {
      if (sslNotice) {
        sslNotice.innerHTML = `
          <div class="alert-box alert-warning mb-3" style="background: rgba(245, 158, 11, 0.1); border: 1px solid var(--neon-yellow); color: var(--neon-yellow); padding: 0.6rem 0.85rem; border-radius: 6px;">
            <i class="fas fa-exclamation-triangle"></i> ${escapeHtml(ssl.error || 'SSL not active on this target')}
          </div>
        `;
      }
      setText('sslIssuer', 'N/A');
      setText('sslSubject', 'N/A');
      setText('sslValidFrom', 'N/A');
      setText('sslValidTo', 'N/A');
      setText('sslDaysRemaining', 'N/A');
      setText('sslSelfSigned', 'N/A');
      setHtml('sslSanTags', '<span class="cyber-tag">N/A</span>');
    }
  }

  function renderRedirectTimeline(redirects) {
    if (!redirects) return;

    setText('redirectHopCountBadge', `${redirects.hop_count || 0} Hops`);

    const downgradeBadge = document.getElementById('redirectDowngradeBadge');
    if (downgradeBadge) {
      if (redirects.is_downgraded) {
        downgradeBadge.className = 'badge text-red';
        downgradeBadge.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Protocol Downgrade (HTTPS → HTTP)';
      } else if (redirects.is_upgraded) {
        downgradeBadge.className = 'badge text-green';
        downgradeBadge.innerHTML = '<i class="fas fa-shield-alt"></i> HTTPS Upgrade Enforced';
      } else {
        downgradeBadge.className = 'badge text-green';
        downgradeBadge.textContent = 'Encrypted / No Downgrade';
      }
    }

    const crossDomainBadge = document.getElementById('redirectCrossDomainBadge');
    if (crossDomainBadge) {
      if (redirects.is_cross_domain) {
        crossDomainBadge.className = 'badge text-yellow';
        crossDomainBadge.innerHTML = '<i class="fas fa-external-link-alt"></i> Cross-Domain Redirect';
      } else {
        crossDomainBadge.className = 'badge text-green';
        crossDomainBadge.textContent = 'Same Domain';
      }
    }

    const container = document.getElementById('redirectTimelineContainer');
    if (container) {
      const chain = redirects.chain || [];
      if (chain.length === 0) {
        container.innerHTML = '<p class="text-muted">No redirect hops recorded (direct response).</p>';
        return;
      }

      container.innerHTML = chain.map(hop => {
        let statusClass = 'status-2xx';
        if (hop.status_code >= 300 && hop.status_code < 400) statusClass = 'status-3xx';
        else if (hop.status_code >= 400 || hop.status_code === 0) statusClass = 'status-4xx';

        return `
          <div class="timeline-hop">
            <div class="timeline-marker">${hop.hop}</div>
            <div class="timeline-card">
              <div class="timeline-header">
                <span class="status-badge ${statusClass}">Status ${hop.status_code}</span>
                <span class="text-muted" style="font-size: 0.78rem;">${escapeHtml(hop.reason || '')}</span>
              </div>
              <div class="timeline-url"><code>${escapeHtml(hop.url)}</code></div>
              ${hop.next_url ? `
                <div class="timeline-next text-muted" style="font-size: 0.8rem; margin-top: 0.4rem;">
                  <i class="fas fa-arrow-right neon-cyan"></i> Redirects to: <code>${escapeHtml(hop.next_url)}</code>
                </div>
              ` : ''}
            </div>
          </div>
        `;
      }).join('');
    }
  }

  function renderSecurityFlags(flags) {
    const container = document.getElementById('flagsGridContainer');
    if (!container) return;

    if (!flags || flags.length === 0) {
      container.innerHTML = `
        <div class="flag-card" style="grid-column: 1 / -1; text-align: center; padding: 2.5rem 1rem;">
          <div style="font-size: 2.2rem; color: var(--neon-green); margin-bottom: 0.5rem;">
            <i class="fas fa-shield-check"></i>
          </div>
          <h5 style="font-size: 1.15rem; font-weight: 700; color: var(--neon-green);">No Malicious Threat Flags Triggered</h5>
          <p class="text-muted" style="max-width: 540px; margin: 0.5rem auto 0;">
            The analyzed URL adheres to RFC structural standards and standard domain infrastructure. No active brand impersonation, deceptive homoglyphs, or credential phishing traits were detected.
          </p>
        </div>
      `;
      return;
    }

    container.innerHTML = flags.map(f => {
      const sev = (f.severity || 'info').toLowerCase();
      return `
        <div class="flag-card sev-${sev}">
          <div class="flag-header">
            <span class="flag-title">${escapeHtml(f.name)}</span>
            <span class="severity-pill severity-${sev}">${escapeHtml(sev)}</span>
          </div>
          <p class="flag-explanation">${escapeHtml(f.explanation)}</p>
          <div class="flag-footer" style="display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted); margin-top: 0.4rem;">
            <span>Rule ID: <code>${escapeHtml(f.rule_id || 'RULE')}</code></span>
            <span>Risk Impact: +${f.weight || 0} pts</span>
          </div>
        </div>
      `;
    }).join('');
  }

  function copyAnalysisSummary() {
    if (!window.currentAnalysisData) return;
    const data = window.currentAnalysisData;
    const text = [
      `Target URL: ${data.url}`,
      `Risk Score: ${data.risk.score}/100 (${data.risk.level} Risk)`,
      `Summary: ${data.risk.summary}`,
      `Detected Flags: ${data.flags.length}`,
      ...data.flags.map(f => `- [${f.severity.toUpperCase()}] ${f.name}: ${f.explanation}`)
    ].join('\n');

    copyToClipboard(text);
    showToast('Analysis summary copied to clipboard!', 'success');
  }

  /* ==========================================================================
     6. Exporting Files (TXT, CSV, JSON)
     ========================================================================== */
  async function handleExportDownload(e) {
    const btn = e.currentTarget;
    const format = btn.getAttribute('data-format');
    const type = btn.getAttribute('data-type'); // 'dorks' or 'analysis'

    const payloadData = type === 'dorks' ? window.currentDorksData : window.currentAnalysisData;

    if (!payloadData) {
      showToast('No active report data to export.', 'error');
      return;
    }

    try {
      showToast(`Generating ${format.toUpperCase()} report...`, 'info');

      const response = await fetch('/api/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: format,
          report_type: type,
          data: payloadData,
          authorized: true
        })
      });

      if (!response.ok) {
        throw new Error(`Export failed with HTTP ${response.status}`);
      }

      // Convert to downloadable blob
      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;

      // Extract filename from Content-Disposition if present
      const disposition = response.headers.get('Content-Disposition');
      let filename = `security_intel_${type}.${format}`;
      if (disposition && disposition.indexOf('filename=') !== -1) {
        const matches = /filename="([^"]+)"/.exec(disposition);
        if (matches && matches[1]) filename = matches[1];
      }

      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(downloadUrl);

      showToast(`Saved report as ${filename}`, 'success');

      // Close dropdown
      if (elements.dorksExportMenu) elements.dorksExportMenu.classList.remove('show');
      if (elements.analysisExportMenu) elements.analysisExportMenu.classList.remove('show');

    } catch (err) {
      showToast(`Export Error: ${err.message}`, 'error');
    }
  }

  /* ==========================================================================
     7. Utilities (Clipboard, Numbers, Toasts, Sanitization)
     ========================================================================== */
  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
    } else {
      fallbackCopy(text);
    }
  }

  function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
    } catch (e) {
      console.warn('Fallback copy failed', e);
    }
    document.body.removeChild(textarea);
  }

  function animateNumber(element, target) {
    if (!element) return;
    if (target === 0) {
      element.textContent = '0';
      return;
    }
    let current = 0;
    const duration = 1000;
    const stepTime = 20;
    const steps = duration / stepTime;
    const increment = target / steps;

    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        element.textContent = Math.round(target);
        clearInterval(timer);
      } else {
        element.textContent = Math.round(current);
      }
    }, stepTime);
  }

  function showToast(message, type = 'info', duration = 3500) {
    if (!elements.toastStack) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let icon = 'fas fa-info-circle';
    if (type === 'success') icon = 'fas fa-check-circle';
    else if (type === 'error') icon = 'fas fa-exclamation-circle';

    toast.innerHTML = `
      <i class="${icon}"></i>
      <span>${escapeHtml(message)}</span>
    `;

    elements.toastStack.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function capitalize(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

})();

