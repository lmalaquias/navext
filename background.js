// Background service worker for NavExt
// Author: Leandro Malaquias
// GitHub: @leandromalaquias
// LinkedIn: /in/leandromalaquias
// Monitors extension installations, updates, and behavior

// Store for tracking extension changes
let extensionStates = new Map();
let communicationLog = new Map();

// Initialize on install
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('NavExt installed', details);
  
  // Set up initial extension states
  await initializeExtensionStates();
  
  // Set up periodic scanning
  chrome.alarms.create('periodic-scan', { periodInMinutes: 60 });
  
  // Show welcome notification
  if (details.reason === 'install') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icon128.png') || '',
      title: 'NavExt Installed',
      message: 'Click the extension icon to scan your installed extensions for security risks.'
    });
  }
});

// Initialize extension states
async function initializeExtensionStates() {
  const extensions = await chrome.management.getAll();
  
  extensions.forEach(ext => {
    if (ext.type === 'extension') {
      extensionStates.set(ext.id, {
        version: ext.version,
        permissions: ext.permissions || [],
        hostPermissions: ext.hostPermissions || [],
        enabled: ext.enabled,
        lastChecked: Date.now()
      });
    }
  });
  
  // Store in chrome.storage for persistence
  chrome.storage.local.set({ extensionStates: Object.fromEntries(extensionStates) });
}

// Monitor extension installations
chrome.management.onInstalled.addListener(async (extension) => {
  if (extension.type !== 'extension' || extension.id === chrome.runtime.id) return;
  
  console.log('New extension installed:', extension.name);
  
  // Quick risk assessment
  const riskAssessment = await quickRiskAssessment(extension);
  
  if (riskAssessment.riskLevel === 'high') {
    // Alert user about high-risk installation
    chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icon128.png') || '',
      title: '⚠️ High-Risk Extension Installed',
      message: `"${extension.name}" has dangerous permissions. Click to review.`,
      priority: 2
    });
  }
  
  // Update our state tracking
  extensionStates.set(extension.id, {
    version: extension.version,
    permissions: extension.permissions || [],
    hostPermissions: extension.hostPermissions || [],
    enabled: extension.enabled,
    lastChecked: Date.now()
  });
});

// Monitor extension removals
chrome.management.onUninstalled.addListener((extensionId) => {
  // Clean up stored data for uninstalled extensions
  extensionStates.delete(extensionId);
  communicationLog.delete(extensionId);
  
  // Update storage
  chrome.storage.local.set({ 
    extensionStates: Object.fromEntries(extensionStates),
    communicationLog: Object.fromEntries(communicationLog)
  });
});

// Monitor extension updates
chrome.management.onEnabled.addListener(async (extension) => {
  if (extension.type !== 'extension' || extension.id === chrome.runtime.id) return;
  
  const previousState = extensionStates.get(extension.id);
  
  if (previousState) {
    // Check for permission changes
    const newPerms = extension.permissions || [];
    const oldPerms = previousState.permissions;
    
    const addedPerms = newPerms.filter(p => !oldPerms.includes(p));
    
    if (addedPerms.length > 0) {
      // Alert about new permissions
      chrome.notifications.create({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icon128.png') || '',
        title: '🔑 Extension Permissions Changed',
        message: `"${extension.name}" added new permissions: ${addedPerms.join(', ')}`,
        priority: 1
      });
    }
  }
});

// Quick risk assessment function
async function quickRiskAssessment(extension) {
  const DANGEROUS_PERMISSIONS = [
    'webRequest', 'webRequestBlocking', 'proxy', 'cookies',
    'debugger', 'management', 'privacy', 'contentSettings'
  ];
  
  const DANGEROUS_HOST_PATTERNS = ['<all_urls>', '*://*/*'];
  
  let riskScore = 0;
  const riskFactors = [];
  
  // Check permissions
  const perms = extension.permissions || [];
  const dangerousPerms = perms.filter(p => DANGEROUS_PERMISSIONS.includes(p));
  
  if (dangerousPerms.length > 0) {
    riskScore += dangerousPerms.length * 20;
    riskFactors.push(`${dangerousPerms.length} dangerous permissions`);
  }
  
  // Check host permissions
  const hosts = extension.hostPermissions || [];
  const hasBroadAccess = hosts.some(h => DANGEROUS_HOST_PATTERNS.includes(h));
  
  if (hasBroadAccess) {
    riskScore += 40;
    riskFactors.push('Access to all websites');
  }
  
  // Determine risk level
  let riskLevel = 'low';
  if (riskScore >= 60) riskLevel = 'high';
  else if (riskScore >= 30) riskLevel = 'medium';
  
  return { riskScore, riskLevel, riskFactors };
}

// Monitor cross-extension communication
chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  // Log external messages for analysis
  const timestamp = Date.now();
  const logEntry = {
    from: sender.id,
    message: message,
    timestamp: timestamp
  };
  
  if (!communicationLog.has(sender.id)) {
    communicationLog.set(sender.id, []);
  }
  
  communicationLog.get(sender.id).push(logEntry);
  
  // Store recent communications (limit size)
  const MAX_LOG_ENTRIES = 100;
  const allEntries = Array.from(communicationLog.entries());
  if (allEntries.length > MAX_LOG_ENTRIES) {
    // Keep only the most recent entries
    communicationLog = new Map(allEntries.slice(-MAX_LOG_ENTRIES));
  }
  
  chrome.storage.local.set({
    communicationLog: Object.fromEntries(communicationLog)
  });
  
  console.log('External message received:', logEntry);
});

// Periodic security scan
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'periodic-scan') {
    console.log('Running periodic security scan...');
    
    const extensions = await chrome.management.getAll();
    const updates = [];
    
    for (const ext of extensions) {
      if (ext.type !== 'extension' || ext.id === chrome.runtime.id) continue;
      
      const previousState = extensionStates.get(ext.id);
      
      if (previousState && previousState.version !== ext.version) {
        // Extension was updated
        updates.push({
          name: ext.name,
          oldVersion: previousState.version,
          newVersion: ext.version
        });
        
        // Update stored state
        extensionStates.set(ext.id, {
          version: ext.version,
          permissions: ext.permissions || [],
          hostPermissions: ext.hostPermissions || [],
          enabled: ext.enabled,
          lastChecked: Date.now()
        });
      }
    }
    
    if (updates.length > 0) {
      // Notify about updates
      chrome.notifications.create({
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icon128.png') || '',
        title: '🔄 Extensions Updated',
        message: `${updates.length} extension(s) were updated. Click to review changes.`,
        priority: 1
      });
    }
  }
});

// Handle notification clicks
chrome.notifications.onClicked.addListener((notificationId) => {
  // Open extension in a new tab (popup API doesn't exist in MV3)
  chrome.tabs.create({ 
    url: chrome.runtime.getURL('popup.html')
  });
});

// Message handler for popup communication
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getCommunicationLog') {
    chrome.storage.local.get(['communicationLog'], (result) => {
      sendResponse(result.communicationLog || {});
    });
    return true; // Keep channel open for async response
  }
  
  if (request.action === 'getExtensionStates') {
    chrome.storage.local.get(['extensionStates'], (result) => {
      sendResponse(result.extensionStates || {});
    });
    return true;
  }
  
  if (request.action === 'isReady') {
    // Confirm background script is ready
    sendResponse({ ready: true });
    return true;
  }
});

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    quickRiskAssessment,
    initializeExtensionStates
  };
}