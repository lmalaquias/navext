// NavExt - Extension Security Analyzer
// Author: Leandro Malaquias
// GitHub: @leandromalaquias
// LinkedIn: /in/leandromalaquias

// Dangerous permissions that pose high risk
const DANGEROUS_PERMISSIONS = [
  'webRequest',
  'webRequestBlocking',
  'proxy',
  'cookies',
  'debugger',
  'management',
  'privacy',
  'contentSettings',
  'history',
  'bookmarks',
  'passwords'
];

// Permissions that need careful review
const SENSITIVE_PERMISSIONS = [
  'tabs',
  'activeTab',
  'storage',
  'notifications',
  'downloads',
  'clipboardRead',
  'clipboardWrite',
  'geolocation'
];

// Host permission patterns
const DANGEROUS_HOST_PATTERNS = [
  '<all_urls>',
  '*://*/*',
  'http://*/*',
  'https://*/*'
];

class ExtensionAnalyzer {
  constructor() {
    this.extensions = [];
    this.scanResults = new Map();
  }

  async scanAllExtensions() {
    this.extensions = await chrome.management.getAll();
    
    for (const ext of this.extensions) {
      if (ext.type === 'extension' && ext.id !== chrome.runtime.id) {
        const analysis = await this.analyzeExtension(ext);
        this.scanResults.set(ext.id, analysis);
      }
    }
    
    return this.scanResults;
  }

  async analyzeExtension(extension) {
    try {
      const analysis = {
        id: extension.id,
        name: extension.name,
        version: extension.version,
        enabled: extension.enabled,
        description: extension.description,
        installType: extension.installType,
        mayDisable: extension.mayDisable,
        homepageUrl: extension.homepageUrl,
        updateUrl: extension.updateUrl,
        icons: extension.icons,
        permissions: extension.permissions || [],
        hostPermissions: extension.hostPermissions || [],
        riskScore: 0,
        riskLevel: 'low',
        riskFactors: [],
        analysis: {
          permissions: this.analyzePermissions(extension),
          hostAccess: this.analyzeHostAccess(extension),
          metadata: this.analyzeMetadata(extension),
          behavior: await this.analyzeBehavior(extension)
        }
      };

      // Calculate overall risk score
      analysis.riskScore = this.calculateRiskScore(analysis);
      analysis.riskLevel = this.determineRiskLevel(analysis.riskScore);

      return analysis;
    } catch (error) {
      console.error('Failed to analyze extension:', extension.name, error);
      return {
        id: extension.id,
        name: extension.name,
        version: extension.version,
        enabled: extension.enabled,
        riskScore: 0,
        riskLevel: 'unknown',
        riskFactors: ['Analysis failed'],
        error: error.message
      };
    }
  }

  analyzePermissions(extension) {
    const results = {
      dangerous: [],
      sensitive: [],
      unnecessary: [],
      score: 0
    };

    const perms = extension.permissions || [];
    
    perms.forEach(perm => {
      if (DANGEROUS_PERMISSIONS.includes(perm)) {
        results.dangerous.push(perm);
        results.score += 20;
      } else if (SENSITIVE_PERMISSIONS.includes(perm)) {
        results.sensitive.push(perm);
        results.score += 10;
      }
    });

    // Check for permission combinations that are particularly risky
    if (perms.includes('webRequest') && perms.includes('webRequestBlocking')) {
      results.score += 15;
    }

    if (perms.includes('cookies') && perms.includes('webRequest')) {
      results.score += 15;
    }

    return results;
  }

  analyzeHostAccess(extension) {
    const results = {
      allUrls: false,
      broadAccess: false,
      specificSites: [],
      score: 0
    };

    const hosts = extension.hostPermissions || [];
    
    hosts.forEach(pattern => {
      if (DANGEROUS_HOST_PATTERNS.includes(pattern)) {
        results.allUrls = true;
        results.score += 30;
      } else if (pattern.includes('*')) {
        results.broadAccess = true;
        results.score += 15;
      } else {
        results.specificSites.push(pattern);
        results.score += 5;
      }
    });

    return results;
  }

  analyzeMetadata(extension) {
    const results = {
      issues: [],
      score: 0
    };

    // Check if extension is from web store
    if (extension.installType === 'development') {
      results.issues.push('Development mode - not from store');
      results.score += 20;
    }

    // Check if extension can be disabled
    if (!extension.mayDisable) {
      results.issues.push('Cannot be disabled by user');
      results.score += 25;
    }

    // Check for suspicious update URLs
    if (extension.updateUrl && !extension.updateUrl.includes('google.com')) {
      results.issues.push('Non-standard update URL');
      results.score += 15;
    }

    // Check if extension has no homepage
    if (!extension.homepageUrl) {
      results.issues.push('No homepage URL');
      results.score += 5;
    }

    return results;
  }

  async analyzeBehavior(extension) {
    const results = {
      recentlyUpdated: false,
      communicatesExternally: false,
      score: 0
    };

    // Check if extension was recently updated (would need to store previous state)
    // This is a placeholder for more advanced behavioral analysis
    
    return results;
  }

  calculateRiskScore(analysis) {
    let score = 0;
    
    score += analysis.analysis.permissions.score;
    score += analysis.analysis.hostAccess.score;
    score += analysis.analysis.metadata.score;
    score += analysis.analysis.behavior.score;

    // Add risk factors for reporting
    if (analysis.analysis.permissions.dangerous.length > 0) {
      analysis.riskFactors.push(`${analysis.analysis.permissions.dangerous.length} dangerous permissions`);
    }
    
    if (analysis.analysis.hostAccess.allUrls) {
      analysis.riskFactors.push('Access to all websites');
    }
    
    if (analysis.analysis.metadata.issues.length > 0) {
      analysis.riskFactors.push(...analysis.analysis.metadata.issues);
    }

    return Math.min(score, 100);
  }

  determineRiskLevel(score) {
    if (score >= 60) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
  }
}

// UI Controller
class UIController {
  constructor() {
    this.analyzer = new ExtensionAnalyzer();
    this.initializeElements();
    this.attachEventListeners();
  }

  initializeElements() {
    this.scanButton = document.getElementById('scanButton');
    this.statsDiv = document.getElementById('stats');
    this.loadingDiv = document.getElementById('loading');
    this.extensionsList = document.getElementById('extensionsList');
    this.detailView = document.getElementById('detailView');
    this.backButton = document.getElementById('backButton');
    this.detailTitle = document.getElementById('detailTitle');
    this.detailContent = document.getElementById('detailContent');
  }

  attachEventListeners() {
    this.scanButton.addEventListener('click', () => this.performScan());
    this.backButton.addEventListener('click', () => this.hideDetailView());
  }

  async performScan() {
    this.scanButton.disabled = true;
    this.scanButton.textContent = 'Scanning...';
    this.loadingDiv.style.display = 'block';
    this.extensionsList.innerHTML = '';
    this.statsDiv.style.display = 'none';

    try {
      // Verify we have necessary permissions
      const permissions = await chrome.permissions.getAll();
      if (!permissions.permissions.includes('management')) {
        this.showError('Missing required permissions. Please reinstall the extension.');
        return;
      }

      const results = await this.analyzer.scanAllExtensions();
      this.displayResults(results);
    } catch (error) {
      console.error('Scan error:', error);
      this.showError('Failed to scan extensions: ' + error.message);
    } finally {
      this.scanButton.disabled = false;
      this.scanButton.textContent = 'Scan All Extensions';
      this.loadingDiv.style.display = 'none';
    }
  }

  displayResults(results) {
    let totalCount = 0;
    let highRiskCount = 0;
    let mediumRiskCount = 0;
    let lowRiskCount = 0;

    const sortedResults = Array.from(results.values()).sort((a, b) => b.riskScore - a.riskScore);

    sortedResults.forEach(result => {
      totalCount++;
      
      switch (result.riskLevel) {
        case 'high':
          highRiskCount++;
          break;
        case 'medium':
          mediumRiskCount++;
          break;
        case 'low':
          lowRiskCount++;
          break;
      }

      this.createExtensionCard(result);
    });

    // Update stats
    document.getElementById('totalCount').textContent = totalCount;
    document.getElementById('highRiskCount').textContent = highRiskCount;
    document.getElementById('mediumRiskCount').textContent = mediumRiskCount;
    document.getElementById('lowRiskCount').textContent = lowRiskCount;
    
    this.statsDiv.style.display = 'flex';
  }

  createExtensionCard(result) {
    const card = document.createElement('div');
    card.className = 'extension-item';
    card.addEventListener('click', () => this.showDetailView(result));

    const iconUrl = result.icons && result.icons.length > 0 
      ? result.icons[result.icons.length - 1].url 
      : 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIzMiIgaGVpZ2h0PSIzMiIgZmlsbD0iIzY2NiI+PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNiIvPjwvc3ZnPg==';

    card.innerHTML = `
      <div class="extension-header">
        <img src="${iconUrl}" class="extension-icon" onerror="this.src='data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIzMiIgaGVpZ2h0PSIzMiIgZmlsbD0iIzY2NiI+PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNiIvPjwvc3ZnPg=='">
        <div class="extension-name">${this.escapeHtml(result.name)}</div>
        <div class="risk-badge ${result.riskLevel}">${result.riskLevel} risk</div>
      </div>
      <div class="risk-factors">
        ${result.riskFactors.slice(0, 2).map(factor => 
          `<span class="risk-factor">⚠️ ${this.escapeHtml(factor)}</span>`
        ).join('')}
      </div>
    `;

    this.extensionsList.appendChild(card);
  }

  showDetailView(result) {
    this.detailTitle.textContent = result.name;
    this.detailContent.innerHTML = this.generateDetailHTML(result);
    this.detailView.classList.add('active');
  }

  hideDetailView() {
    this.detailView.classList.remove('active');
  }

  generateDetailHTML(result) {
    const analysis = result.analysis;
    
    let html = `
      <div class="section">
        <div class="risk-badge ${result.riskLevel}" style="font-size: 14px; padding: 8px 16px;">
          ${result.riskLevel.toUpperCase()} RISK - Score: ${result.riskScore}/100
        </div>
      </div>
    `;

    // Risk Factors Summary
    if (result.riskFactors.length > 0) {
      html += `
        <div class="section">
          <h3 class="section-title">⚠️ Risk Factors</h3>
          <div class="warning-box">
            ${result.riskFactors.map(factor => `• ${this.escapeHtml(factor)}`).join('<br>')}
          </div>
        </div>
      `;
    }

    // Permissions Analysis
    html += `
      <div class="section">
        <h3 class="section-title">🔑 Permissions Analysis</h3>
    `;

    if (analysis.permissions.dangerous.length > 0) {
      html += `<h4 style="color: #e74c3c;">Dangerous Permissions:</h4>`;
      analysis.permissions.dangerous.forEach(perm => {
        html += `
          <div class="permission-item dangerous">
            <span class="permission-icon">🚨</span>
            <strong>${perm}</strong> - ${this.getPermissionDescription(perm)}
          </div>
        `;
      });
    }

    if (analysis.permissions.sensitive.length > 0) {
      html += `<h4 style="color: #f39c12;">Sensitive Permissions:</h4>`;
      analysis.permissions.sensitive.forEach(perm => {
        html += `
          <div class="permission-item">
            <span class="permission-icon">⚠️</span>
            <strong>${perm}</strong> - ${this.getPermissionDescription(perm)}
          </div>
        `;
      });
    }

    html += `</div>`;

    // Host Access Analysis
    html += `
      <div class="section">
        <h3 class="section-title">🌐 Website Access</h3>
    `;

    if (analysis.hostAccess.allUrls) {
      html += `
        <div class="warning-box">
          <strong>⚠️ This extension can access ALL websites you visit!</strong><br>
          It can read and modify any data on any website.
        </div>
      `;
    } else if (analysis.hostAccess.broadAccess) {
      html += `
        <div class="warning-box">
          This extension has broad access to many websites.
        </div>
      `;
    }

    if (analysis.hostAccess.specificSites.length > 0) {
      html += `<h4>Specific sites accessed:</h4><ul>`;
      analysis.hostAccess.specificSites.forEach(site => {
        html += `<li>${this.escapeHtml(site)}</li>`;
      });
      html += `</ul>`;
    }

    html += `</div>`;

    // Metadata Issues
    if (analysis.metadata.issues.length > 0) {
      html += `
        <div class="section">
          <h3 class="section-title">ℹ️ Other Concerns</h3>
          <ul>
            ${analysis.metadata.issues.map(issue => 
              `<li>${this.escapeHtml(issue)}</li>`
            ).join('')}
          </ul>
        </div>
      `;
    }

    // Extension Info
    html += `
      <div class="section">
        <h3 class="section-title">📋 Extension Information</h3>
        <p><strong>Version:</strong> ${result.version}</p>
        <p><strong>Enabled:</strong> ${result.enabled ? 'Yes' : 'No'}</p>
        <p><strong>Install Type:</strong> ${result.installType}</p>
        ${result.homepageUrl ? `<p><strong>Homepage:</strong> <a href="${result.homepageUrl}" target="_blank">${result.homepageUrl}</a></p>` : ''}
      </div>
    `;

    return html;
  }

  getPermissionDescription(permission) {
    const descriptions = {
      'webRequest': 'Can intercept and analyze all web traffic',
      'webRequestBlocking': 'Can block or modify web requests',
      'cookies': 'Can access your cookies and session data',
      'history': 'Can read your browsing history',
      'bookmarks': 'Can read and modify your bookmarks',
      'tabs': 'Can see all your open tabs and their URLs',
      'storage': 'Can store data locally',
      'management': 'Can manage other extensions',
      'proxy': 'Can control proxy settings',
      'debugger': 'Can debug and control browser',
      'downloads': 'Can manage your downloads',
      'notifications': 'Can show system notifications',
      'clipboardRead': 'Can read your clipboard',
      'clipboardWrite': 'Can modify your clipboard',
      'geolocation': 'Can access your location',
      'activeTab': 'Can access the current tab',
      'privacy': 'Can change privacy settings',
      'contentSettings': 'Can change content settings',
      'passwords': 'Can access saved passwords'
    };

    return descriptions[permission] || 'Has special browser access';
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  showError(message) {
    this.extensionsList.innerHTML = `
      <div class="warning-box" style="margin: 20px;">
        <strong>Error:</strong> ${this.escapeHtml(message)}
      </div>
    `;
  }
}

// Initialize the UI when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new UIController();
});