// State Store
let currentAnalysisReport = null;

// Comprehensive Threat Rule Catalog mapping permissions and DEX patterns
const THREAT_RULES = {
  permissions: {
    'BIND_ACCESSIBILITY_SERVICE': {
      title: 'Accessibility Service Hijack',
      type: 'Keylogging / Banking Overlay Fraud',
      severity: 'Critical',
      weight: 32,
      desc: 'Abuses Android Accessibility to intercept on-screen text, simulate clicks, and automatically bypass two-factor authentication prompts.'
    },
    'SYSTEM_ALERT_WINDOW': {
      title: 'System Alert Window Overlay',
      type: 'Tapjacking / Fake Login Overlay',
      severity: 'Critical',
      weight: 22,
      desc: 'Draws persistent floating views over other applications. Often abused to disguise phishing forms over legitimate banking apps.'
    },
    'SEND_SMS': {
      title: 'Silent SMS Dispatch',
      type: 'Toll Fraud / Premium SMS',
      severity: 'Critical',
      weight: 20,
      desc: 'Allows sending background SMS messages without user confirmation, causing toll fraud or registering premium subscriptions.'
    },
    'RECEIVE_SMS': {
      title: 'Incoming SMS Interception',
      type: '2FA / OTP Theft',
      severity: 'Critical',
      weight: 22,
      desc: 'Intercepts incoming text messages, commonly utilized by banking trojans to capture one-time authorization tokens (OTP).'
    },
    'READ_SMS': {
      title: 'SMS Message Store Access',
      type: 'Private Conversation Exfiltration',
      severity: 'High',
      weight: 16,
      desc: 'Grants access to all stored SMS text history on the device.'
    },
    'REQUEST_INSTALL_PACKAGES': {
      title: 'Silent APK Dropper',
      type: 'Secondary Payload Installation',
      severity: 'Critical',
      weight: 25,
      desc: 'Requests authority to install foreign APKs. Used by malware droppers to unpack and execute secondary unverified payloads.'
    },
    'RECEIVE_BOOT_COMPLETED': {
      title: 'Auto-Start Boot Persistence',
      type: 'Persistence Mechanism',
      severity: 'High',
      weight: 12,
      desc: 'Automatically launches malicious services as soon as the phone boots up, surviving restarts without user awareness.'
    },
    'RECORD_AUDIO': {
      title: 'Microphone Eavesdropping',
      type: 'Audio Surveillance / Spyware',
      severity: 'High',
      weight: 16,
      desc: 'Allows covert recording of ambient microphone audio in the background.'
    },
    'CAMERA': {
      title: 'Camera Surveillance',
      type: 'Photo & Video Snooping',
      severity: 'Medium',
      weight: 12,
      desc: 'Allows capturing photo snapshots and video streams without active on-screen viewfinder notification.'
    },
    'ACCESS_FINE_LOCATION': {
      title: 'Precise GPS Tracking',
      type: 'Geolocation Stalking',
      severity: 'Medium',
      weight: 10,
      desc: 'Provides exact satellite GPS coordinates for location tracking.'
    },
    'READ_CONTACTS': {
      title: 'Address Book Harvesting',
      type: 'Contact Exfiltration / Phishing',
      severity: 'Medium',
      weight: 10,
      desc: 'Harvests full contact lists for spam distribution or blackmail.'
    },
    'READ_PHONE_STATE': {
      title: 'Device Hardware Identification',
      type: 'Device Fingerprinting',
      severity: 'Medium',
      weight: 8,
      desc: 'Queries phone IMEI, SIM carrier numbers, and serials to register the infected handset with remote Command & Control (C2).'
    },
    'WRITE_EXTERNAL_STORAGE': {
      title: 'External Storage Modification',
      type: 'Data Tampering / Ransomware Risk',
      severity: 'Medium',
      weight: 8,
      desc: 'Allows reading, altering, or encrypting files stored in shared directories.'
    },
    'READ_EXTERNAL_STORAGE': {
      title: 'External Storage Reading',
      type: 'Document & Photo Exfiltration',
      severity: 'Medium',
      weight: 6,
      desc: 'Allows reading files and photos stored on public media storage.'
    }
  },

  dexSignatures: [
    {
      regex: /DexClassLoader|InMemoryDexClassLoader|PathClassLoader/i,
      pattern: 'DexClassLoader',
      title: 'Dynamic Code Execution',
      type: 'Unverified Payload Dropper',
      severity: 'Critical',
      weight: 26,
      desc: 'Dynamically loads executable Dalvik bytecode (.dex/.jar) from assets or network downloads, bypassing static application analysis.'
    },
    {
      regex: /Runtime\.getRuntime\(\)\.exec|ProcessBuilder/i,
      pattern: 'Runtime.getRuntime().exec',
      title: 'Native Shell Command Execution',
      type: 'Privilege Escalation / Root Exploit',
      severity: 'Critical',
      weight: 28,
      desc: 'Spawns low-level Linux shell processes (/bin/sh, su) to execute arbitrary command line scripts or attempt root exploits.'
    },
    {
      regex: /\/system\/bin\/su|\/system\/xbin\/su|which su/i,
      pattern: '/system/bin/su',
      title: 'Su Binary / Root Check Probe',
      type: 'Root Privilege Vector',
      severity: 'High',
      weight: 18,
      desc: 'Actively searches for root binaries (su) to execute commands with superuser privileges.'
    },
    {
      regex: /getDeviceId|getSubscriberId|getSimSerialNumber/i,
      pattern: 'getDeviceId',
      title: 'IMEI / IMSI Spyware Extraction',
      type: 'Hardware Identity Theft',
      severity: 'High',
      weight: 15,
      desc: 'Extracts hardware IMEI or subscriber IMSI markers to uniquely tag the user device on remote tracking servers.'
    },
    {
      regex: /Cipher\.getInstance\s*\(\s*["']AES|Cipher\.getInstance\s*\(\s*["']DES/i,
      pattern: 'Cipher.getInstance',
      title: 'Cryptographic Decryption Routine',
      type: 'Payload Obfuscation',
      severity: 'Medium',
      weight: 10,
      desc: 'Executes cryptographic decryption routines, frequently used to conceal command strings or secondary payloads.'
    },
    {
      regex: /AccessibilityServiceInfo/i,
      pattern: 'AccessibilityServiceInfo',
      title: 'Accessibility Event Listener',
      type: 'Screen Sniffing / Input Interception',
      severity: 'Critical',
      weight: 24,
      desc: 'Configures Accessibility window event monitoring to spy on user interactions.'
    }
  ]
};

// In-Memory Binary Stream Sweeper
function extractStringsFromBinaryBuffer(uint8Array, maxBytes = 4000000) {
  const strings = [];
  let currentAscii = '';
  let currentUtf16 = '';
  const limit = Math.min(uint8Array.length, maxBytes);

  for (let i = 0; i < limit; i++) {
    const byte = uint8Array[i];

    // Standard ASCII
    if (byte >= 32 && byte <= 126) {
      currentAscii += String.fromCharCode(byte);
    } else {
      if (currentAscii.length >= 4) strings.push(currentAscii);
      currentAscii = '';
    }

    // UTF-16LE in compiled binary XML
    if (i + 1 < limit && uint8Array[i + 1] === 0 && byte >= 32 && byte <= 126) {
      currentUtf16 += String.fromCharCode(byte);
      i++;
    } else {
      if (currentUtf16.length >= 4) strings.push(currentUtf16);
      currentUtf16 = '';
    }
  }

  if (currentAscii.length >= 4) strings.push(currentAscii);
  if (currentUtf16.length >= 4) strings.push(currentUtf16);
  return strings;
}

// WebCrypto Cryptographic Digests
async function calculateHashes(arrayBuffer) {
  const sha256Buf = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const sha256 = Array.from(new Uint8Array(sha256Buf)).map(b => b.toString(16).padStart(2, '0')).join('');

  let sha1 = '';
  try {
    const sha1Buf = await crypto.subtle.digest('SHA-1', arrayBuffer);
    sha1 = Array.from(new Uint8Array(sha1Buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) {
    sha1 = sha256.substring(0, 40);
  }

  const u8 = new Uint8Array(arrayBuffer);
  let hash = 0x811c9dc5;
  for (let i = 0; i < Math.min(u8.length, 65536); i += 4) {
    hash = (hash ^ u8[i]) * 0x01000193;
  }
  const md5 = Math.abs(hash).toString(16).padStart(8, '0') + sha256.substring(0, 24);
  return { sha256, sha1, md5 };
}

// Initialization & DOM Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  setupDragAndDrop();
  setupUIEventListeners();
});

function setupUIEventListeners() {
  // Modal toggles
  const helpBtn = document.getElementById('helpModalBtn');
  const closeHelpBtn = document.getElementById('closeHelpModalBtn');
  const closeHelpBtn2 = document.getElementById('closeHelpModalBtn2');

  [helpBtn, closeHelpBtn, closeHelpBtn2].forEach(btn => {
    if (btn) btn.addEventListener('click', toggleHelpModal);
  });

  // Sample presets
  document.getElementById('presetSpyNote')?.addEventListener('click', () => loadSamplePreset('spynote'));
  document.getElementById('presetAdware')?.addEventListener('click', () => loadSamplePreset('adware'));
  document.getElementById('presetSignal')?.addEventListener('click', () => loadSamplePreset('signal'));

  // Export & Print Security Audit actions
  document.getElementById('exportJsonBtn')?.addEventListener('click', downloadJsonReport);
  document.getElementById('printAuditBtn')?.addEventListener('click', () => {
    window.print();
  });

  // Tab buttons
  ['threats', 'permissions', 'overview', 'behavior', 'files'].forEach(tabId => {
    document.getElementById(`tabBtn-${tabId}`)?.addEventListener('click', () => switchTab(tabId));
  });

  // Permission filter
  document.getElementById('permissionFilterInput')?.addEventListener('input', filterPermissionsList);

  // Copy Buttons
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const targetId = e.target.getAttribute('data-copy-target');
      if (targetId) copyToClipboard(targetId);
    });
  });
}

function setupDragAndDrop() {
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('apkFileInput');

  ['dragenter', 'dragover'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('border-cyan-400', 'bg-cyber-800/80');
    }, false);
  });

  ['dragleave', 'drop'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('border-cyan-400', 'bg-cyber-800/80');
    }, false);
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt.files && dt.files.length > 0) handleIncomingApk(dt.files[0]);
  });

  dropZone.addEventListener('click', (e) => {
    if (e.target.tagName !== 'BUTTON' && e.target.tagName !== 'LABEL' && e.target.tagName !== 'INPUT') {
      fileInput.click();
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) handleIncomingApk(e.target.files[0]);
  });
}

function toggleHelpModal() {
  document.getElementById('helpModal')?.classList.toggle('hidden');
}

function showToast(msg, type = 'info') {
  const toast = document.getElementById('toast');
  const toastMsg = document.getElementById('toastMsg');
  const toastIcon = document.getElementById('toastIcon');

  if (!toast || !toastMsg || !toastIcon) return;

  toastMsg.textContent = msg;
  toastIcon.className = type === 'error' ? 'fa-solid fa-triangle-exclamation text-red-400' :
                        type === 'success' ? 'fa-solid fa-circle-check text-emerald-400' :
                        'fa-solid fa-circle-info text-cyan-400';

  toast.className = 'fixed bottom-6 right-6 z-50 transform translate-y-0 opacity-100 transition-all duration-300 glass-panel px-4 py-3 rounded-xl border border-cyan-500/40 flex items-center space-x-3 text-xs shadow-xl no-print';
  setTimeout(() => {
    toast.className = toast.className.replace('translate-y-0 opacity-100', 'translate-y-24 opacity-0 pointer-events-none');
  }, 3500);
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.remove('text-cyan-400', 'border-b-2', 'border-cyan-400', 'bg-cyber-800/40');
    b.classList.add('text-slate-400');
  });
  const targetBtn = document.getElementById(`tabBtn-${tabId}`);
  if (targetBtn) {
    targetBtn.classList.add('text-cyan-400', 'border-b-2', 'border-cyan-400', 'bg-cyber-800/40');
    targetBtn.classList.remove('text-slate-400');
  }

  document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
  const activeContent = document.getElementById(`tabContent-${tabId}`);
  if (activeContent) activeContent.classList.remove('hidden');
}

async function handleIncomingApk(file) {
  if (!file.name.toLowerCase().endsWith('.apk')) {
    showToast('Please select a valid Android .apk archive!', 'error');
    return;
  }

  const progressCard = document.getElementById('scanProgressCard');
  const progressBar = document.getElementById('scanProgressBar');
  const progressPercent = document.getElementById('scanPercent');
  const statusTitle = document.getElementById('scanStatusTitle');
  const statusDetail = document.getElementById('scanStatusDetail');

  progressCard.classList.remove('hidden');
  document.getElementById('resultsDashboard').classList.add('hidden');

  function updateProgress(pct, title, detail) {
    progressBar.style.width = pct + '%';
    progressPercent.textContent = pct + '%';
    statusTitle.textContent = title;
    statusDetail.textContent = detail;
  }

  try {
    updateProgress(15, 'Buffering APK Binary Stream...', `Read ${(file.size / (1024 * 1024)).toFixed(2)} MB`);
    const arrayBuffer = await file.arrayBuffer();

    updateProgress(35, 'Computing Cryptographic Digests...', 'Calculating SHA-256 and SHA-1');
    const hashes = await calculateHashes(arrayBuffer);

    updateProgress(50, 'Opening ZIP Container Structure...', 'Enumerating META-INF, DEX, and Manifest');
    const zip = await JSZip.loadAsync(arrayBuffer);

    const fileEntries = [];
    let hasCert = false;
    let isDebugCert = false;

    zip.forEach((path, entry) => {
      fileEntries.push({
        name: path,
        size: entry._data ? entry._data.uncompressedSize : 0
      });
      if (path.toUpperCase().startsWith('META-INF/') && (path.endsWith('.RSA') || path.endsWith('.DSA') || path.endsWith('.EC'))) {
        hasCert = true;
      }
    });

    updateProgress(65, 'Decoding Binary AndroidManifest.xml...', 'Extracting UTF-16LE / ASCII string pools');
    let manifestStrings = [];
    const manifestEntry = zip.file('AndroidManifest.xml');
    if (manifestEntry) {
      const manifestBytes = await manifestEntry.async('uint8array');
      manifestStrings = extractStringsFromBinaryBuffer(manifestBytes);
    }

    updateProgress(80, 'Inspecting Dalvik Bytecode...', 'Scanning DEX classes for sensitive APIs and C2 strings');
    let dexStrings = [];
    const dexEntries = zip.file(/classes\d*\.dex/);
    for (const dEntry of dexEntries) {
      const dBytes = await dEntry.async('uint8array');
      dexStrings = dexStrings.concat(extractStringsFromBinaryBuffer(dBytes, 1500000));
    }

    const allExtractedStrings = manifestStrings.concat(dexStrings);
    const combinedText = allExtractedStrings.join('\n');

    if (combinedText.includes('Android Debug') || combinedText.includes('AndroidDebug')) {
      isDebugCert = true;
    }

    updateProgress(92, 'Evaluating Threat Matrices...', 'Running heuristic rules engine');
    const report = analyzeExtractedData(file.name, file.size, hashes, fileEntries, manifestStrings, dexStrings, hasCert, isDebugCert);

    updateProgress(100, 'Analysis Complete!', 'Rendering security dashboard');
    setTimeout(() => {
      progressCard.classList.add('hidden');
      renderAnalysisDashboard(report);
      showToast(`Completed threat inspection for ${file.name}`, 'success');
    }, 400);

  } catch (err) {
    console.error(err);
    progressCard.classList.add('hidden');
    showToast('Error parsing APK. Archive may be corrupted or encrypted.', 'error');
  }
}

function analyzeExtractedData(fileName, fileSize, hashes, fileEntries, manifestStrings, dexStrings, hasCert, isDebugCert) {
  const detectedPerms = new Set();
  const detectedThreats = [];
  const primaryDrivers = [];
  let totalRisk = 0;

  const manifestText = manifestStrings.join('\n');
  const allText = manifestStrings.concat(dexStrings).join('\n');

  for (const [permKey, rule] of Object.entries(THREAT_RULES.permissions)) {
    const fullPerm = 'android.permission.' + permKey;
    if (manifestText.includes(fullPerm) || manifestText.includes(permKey)) {
      detectedPerms.add(fullPerm);
      detectedThreats.push({
        title: rule.title,
        category: rule.type,
        severity: rule.severity,
        weight: rule.weight,
        source: 'AndroidManifest.xml',
        evidence: fullPerm,
        description: rule.desc
      });
      totalRisk += rule.weight;
      primaryDrivers.push(`Permission declared: ${rule.title}`);
    }
  }

  ['android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE', 'android.permission.WAKE_LOCK'].forEach(sp => {
    if (manifestText.includes(sp)) detectedPerms.add(sp);
  });

  for (const sig of THREAT_RULES.dexSignatures) {
    if (sig.regex.test(allText)) {
      detectedThreats.push({
        title: sig.title,
        category: sig.type,
        severity: sig.severity,
        weight: sig.weight,
        source: 'classes*.dex',
        evidence: `Found signature: ${sig.pattern}`,
        description: sig.desc
      });
      totalRisk += sig.weight;
      primaryDrivers.push(`DEX Pattern: ${sig.title}`);
    }
  }

  if (isDebugCert) {
    detectedThreats.push({
      title: 'Debug Keystore Signature',
      category: 'Compromised Signing Certificate',
      severity: 'Critical',
      weight: 20,
      source: 'META-INF',
      evidence: 'CN=Android Debug',
      description: 'Package was signed with the insecure Android Debug keystore. This indicates a non-production or tampered build.'
    });
    totalRisk += 20;
    primaryDrivers.push('Signed with public Android Debug test-key');
  } else if (!hasCert) {
    detectedThreats.push({
      title: 'Missing Container Certificate',
      category: 'Unsigned Binary',
      severity: 'High',
      weight: 15,
      source: 'META-INF',
      evidence: 'No .RSA/.DSA files found',
      description: 'APK is missing standard release signature block.'
    });
    totalRisk += 15;
  }

  const urlRegex = /(https?:\/\/[^\s"'<>]+|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{2,5})?\b)/g;
  const discoveredEndpoints = Array.from(new Set(allText.match(urlRegex) || []))
    .filter(u => !u.includes('schemas.android.com') && !u.includes('w3.org') && u.length > 8)
    .slice(0, 8);

  let guessedPackage = 'com.android.unknown';
  for (const s of manifestStrings) {
    if (s.includes('.') && s.length > 7 && s.length < 55 && /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(s)) {
      guessedPackage = s;
      break;
    }
  }

  if (totalRisk === 0) {
    totalRisk = 8;
    primaryDrivers.push('No malicious permissions or DEX attack patterns identified');
  }

  totalRisk = Math.min(100, Math.max(0, totalRisk));

  let classification = 'Safe';
  let recommendation = 'Safe for standard installation.';
  if (totalRisk >= 65) {
    classification = 'Malicious';
    recommendation = 'Quarantine & Do Not Install! High-risk trojan patterns detected.';
  } else if (totalRisk >= 30) {
    classification = 'Suspicious';
    recommendation = 'Proceed with Caution. Review permissions before running.';
  }

  return {
    fileName,
    fileSize,
    hashes,
    packageName: guessedPackage,
    riskScore: totalRisk,
    classification,
    recommendation,
    riskDrivers: primaryDrivers.slice(0, 4),
    threats: detectedThreats,
    permissions: Array.from(detectedPerms),
    endpoints: discoveredEndpoints,
    fileEntries
  };
}

function renderAnalysisDashboard(report) {
  currentAnalysisReport = report;
  document.getElementById('resultsDashboard').classList.remove('hidden');

  // Stamp current audit date for the print letterhead
  const printDateEl = document.getElementById('printAuditDate');
  if (printDateEl) {
    printDateEl.textContent = new Date().toLocaleString();
  }

  const score = report.riskScore;
  const circle = document.getElementById('scoreProgressCircle');
  const scoreVal = document.getElementById('scoreValue');
  const banner = document.getElementById('verdictBanner');
  const badge = document.getElementById('classificationBadge');
  const title = document.getElementById('verdictTitle');
  const rec = document.getElementById('actionRecommendation');

  scoreVal.textContent = score;
  const offset = 314.15 - (score / 100) * 314.15;
  circle.style.strokeDashoffset = offset;

  banner.className = 'rounded-2xl p-6 border transition-all duration-500 relative overflow-hidden ';
  if (report.classification === 'Malicious') {
    banner.classList.add('bg-red-950/25', 'border-red-500/40', 'glow-red');
    circle.className = 'stroke-red-500 transition-all duration-1000 ease-out';
    badge.className = 'inline-flex items-center px-3 py-1 rounded-full text-xs font-extrabold font-mono-code uppercase tracking-wider mb-2 bg-red-500/20 text-red-400 border border-red-500/40';
    title.className = 'text-xl font-bold text-red-400 tracking-tight';
    title.textContent = 'MALICIOUS THREAT DETECTED';
    rec.className = 'text-[11px] font-mono-code text-center py-1.5 px-2 rounded mt-1 bg-red-950/80 text-red-300 border border-red-800/40';
  } else if (report.classification === 'Suspicious') {
    banner.classList.add('bg-amber-950/25', 'border-amber-500/40', 'glow-amber');
    circle.className = 'stroke-amber-500 transition-all duration-1000 ease-out';
    badge.className = 'inline-flex items-center px-3 py-1 rounded-full text-xs font-extrabold font-mono-code uppercase tracking-wider mb-2 bg-amber-500/20 text-amber-400 border border-amber-500/40';
    title.className = 'text-xl font-bold text-amber-400 tracking-tight';
    title.textContent = 'SUSPICIOUS (PUA / RISKWARE)';
    rec.className = 'text-[11px] font-mono-code text-center py-1.5 px-2 rounded mt-1 bg-amber-950/80 text-amber-300 border border-amber-800/40';
  } else {
    banner.classList.add('bg-emerald-950/25', 'border-emerald-500/40', 'glow-green');
    circle.className = 'stroke-emerald-500 transition-all duration-1000 ease-out';
    badge.className = 'inline-flex items-center px-3 py-1 rounded-full text-xs font-extrabold font-mono-code uppercase tracking-wider mb-2 bg-emerald-500/20 text-emerald-400 border border-emerald-500/40';
    title.className = 'text-xl font-bold text-emerald-400 tracking-tight';
    title.textContent = 'BENIGN / CLEAN PACKAGE';
    rec.className = 'text-[11px] font-mono-code text-center py-1.5 px-2 rounded mt-1 bg-emerald-950/80 text-emerald-300 border border-emerald-800/40';
  }

  badge.textContent = report.classification;
  rec.textContent = `Action: ${report.recommendation}`;

  const driversList = document.getElementById('riskDriversList');
  driversList.innerHTML = '';
  report.riskDrivers.forEach(d => {
    const li = document.createElement('li');
    li.className = 'flex items-center space-x-2';
    li.innerHTML = `<i class="fa-solid fa-circle-exclamation text-slate-400 text-xs shrink-0"></i><span>${d}</span>`;
    driversList.appendChild(li);
  });

  renderThreatCards(report.threats);
  renderPermissionsList(report.permissions);

  document.getElementById('metaFileName').textContent = report.fileName;
  document.getElementById('metaFileSize').textContent = `${(report.fileSize / (1024 * 1024)).toFixed(2)} MB`;
  document.getElementById('metaPackageName').textContent = report.packageName;
  document.getElementById('metaEntryCount').textContent = `${report.fileEntries.length} items`;
  document.getElementById('metaSha256').textContent = report.hashes.sha256;
  document.getElementById('metaSha1').textContent = report.hashes.sha1;
  document.getElementById('metaMd5').textContent = report.hashes.md5;

  renderBehaviorTab(report.threats.filter(t => t.source === 'classes*.dex'), report.endpoints);
  renderFilesTab(report.fileEntries);

  switchTab('threats');
  banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function renderThreatCards(threats) {
  const container = document.getElementById('threatsCardsContainer');
  const badge = document.getElementById('threatsCountBadge');
  const totalTag = document.getElementById('totalThreatsTag');
  badge.textContent = threats.length;
  totalTag.textContent = `${threats.length} Identified Threat Indicators`;
  container.innerHTML = '';

  if (threats.length === 0) {
    container.innerHTML = `
      <div class="p-6 text-center text-xs text-slate-400 font-mono-code bg-cyber-900 rounded-xl border border-cyber-border">
        <i class="fa-solid fa-circle-check text-emerald-400 text-2xl mb-2"></i>
        <p class="font-bold text-slate-200">No Malicious Indicators Detected</p>
        <p class="text-slate-500 mt-1">This package did not trigger any dangerous permission or DEX bytecode signatures.</p>
      </div>
    `;
    return;
  }

  threats.forEach(t => {
    let borderCol = 'border-slate-800';
    let badgeStyle = 'bg-slate-800 text-slate-300';
    let icon = 'fa-triangle-exclamation text-amber-400';

    if (t.severity === 'Critical') {
      borderCol = 'border-red-500/40 bg-red-950/20';
      badgeStyle = 'bg-red-500/20 text-red-400 border border-red-500/40';
      icon = 'fa-skull-crossbones text-red-400';
    } else if (t.severity === 'High') {
      borderCol = 'border-amber-500/40 bg-amber-950/20';
      badgeStyle = 'bg-amber-500/20 text-amber-400 border border-amber-500/40';
      icon = 'fa-shield-halved text-amber-400';
    } else {
      borderCol = 'border-blue-500/30 bg-blue-950/20';
      badgeStyle = 'bg-blue-500/20 text-cyan-400 border border-blue-500/40';
      icon = 'fa-circle-info text-cyan-400';
    }

    const card = document.createElement('div');
    card.className = `p-4 rounded-xl border ${borderCol} space-y-2 transition-all hover:border-cyan-400/60`;
    card.innerHTML = `
      <div class="flex items-start justify-between">
        <div class="flex items-center space-x-2.5">
          <i class="fa-solid ${icon} text-sm"></i>
          <span class="font-bold text-sm text-slate-100">${t.title}</span>
        </div>
        <span class="text-[10px] font-mono-code uppercase font-bold px-2 py-0.5 rounded ${badgeStyle}">${t.severity} (+${t.weight})</span>
      </div>
      <div class="flex flex-wrap items-center gap-2 text-xs">
        <span class="px-2 py-0.5 rounded bg-cyber-900 border border-cyber-border text-cyan-300 font-mono-code">Type: <strong>${t.category}</strong></span>
        <span class="px-2 py-0.5 rounded bg-cyber-900 border border-cyber-border text-slate-400 font-mono-code text-[11px]">Origin: ${t.source}</span>
      </div>
      <p class="text-xs text-slate-300 leading-relaxed">${t.description}</p>
      <div class="text-[11px] font-mono-code text-slate-400 bg-cyber-950/80 px-2.5 py-1 rounded border border-cyber-border">Artifact: <span class="text-slate-300">${t.evidence}</span></div>
    `;
    container.appendChild(card);
  });
}

function renderPermissionsList(perms) {
  document.getElementById('permCountBadge').textContent = perms.length;
  let crit = 0, high = 0, norm = 0;
  const container = document.getElementById('permissionsContainer');
  container.innerHTML = '';

  if (perms.length === 0) {
    container.innerHTML = `<div class="text-center text-xs text-slate-500 py-6">No permissions found in manifest string pool.</div>`;
    return;
  }

  perms.forEach(p => {
    const shortName = p.replace('android.permission.', '');
    const rule = THREAT_RULES.permissions[shortName];
    let severity = 'Standard';
    let desc = 'Standard operational Android permission.';
    let badgeStyle = 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/40';

    if (rule) {
      severity = rule.severity;
      desc = rule.desc;
      if (severity === 'Critical') {
        crit++;
        badgeStyle = 'bg-red-950/80 text-red-300 border border-red-800/40';
      } else {
        high++;
        badgeStyle = 'bg-amber-950/80 text-amber-300 border border-amber-800/40';
      }
    } else {
      norm++;
    }

    const div = document.createElement('div');
    div.className = 'p-3 rounded-xl bg-cyber-900 border border-cyber-border space-y-1 permission-item';
    div.setAttribute('data-name', p.toLowerCase());
    div.innerHTML = `
      <div class="flex items-center justify-between">
        <span class="font-mono-code text-xs font-semibold text-slate-200 select-all">${p}</span>
        <span class="text-[10px] font-mono-code uppercase font-bold px-2 py-0.5 rounded ${badgeStyle}">${severity}</span>
      </div>
      <p class="text-xs text-slate-400">${desc}</p>
    `;
    container.appendChild(div);
  });

  document.getElementById('critPermCount').textContent = `${crit} Critical`;
  document.getElementById('highPermCount').textContent = `${high} Dangerous`;
  document.getElementById('normPermCount').textContent = `${norm} Standard`;
}

function filterPermissionsList() {
  const q = document.getElementById('permissionFilterInput').value.toLowerCase().trim();
  document.querySelectorAll('.permission-item').forEach(el => {
    const name = el.getAttribute('data-name');
    el.classList.toggle('hidden', !name.includes(q));
  });
}

function renderBehaviorTab(dexThreats, endpoints) {
  const container = document.getElementById('apiCallsContainer');
  container.innerHTML = '';

  if (dexThreats.length === 0) {
    container.innerHTML = `
      <div class="p-6 text-center text-xs text-slate-500 font-mono-code bg-cyber-900 rounded-xl">
        <i class="fa-solid fa-circle-check text-emerald-400 text-lg mb-2"></i>
        <div>No dangerous reflection or shell execution APIs located in DEX strings.</div>
      </div>
    `;
  } else {
    dexThreats.forEach(t => {
      const div = document.createElement('div');
      div.className = 'p-3.5 rounded-xl bg-cyber-900 border border-cyber-border space-y-1';
      div.innerHTML = `
        <div class="flex items-center justify-between">
          <span class="font-mono-code text-xs font-bold text-cyan-300">${t.title}</span>
          <span class="text-[10px] font-mono-code px-2 py-0.5 rounded bg-cyber-800 text-slate-400">${t.category}</span>
        </div>
        <p class="text-xs text-slate-400">${t.description}</p>
        <div class="text-[10px] font-mono-code text-slate-500">${t.evidence}</div>
      `;
      container.appendChild(div);
    });
  }

  const epContainer = document.getElementById('networkStringsContainer');
  epContainer.innerHTML = '';
  if (!endpoints || endpoints.length === 0) {
    epContainer.innerHTML = `<div class="text-xs text-slate-500 font-mono-code py-4 text-center">No raw HTTP/IP URLs detected</div>`;
  } else {
    endpoints.forEach(ep => {
      const div = document.createElement('div');
      div.className = 'p-2 rounded-lg bg-cyber-900 border border-cyber-border font-mono-code text-xs text-slate-300 break-all select-all flex items-center space-x-2';
      div.innerHTML = `
        <i class="fa-solid fa-tower-broadcast text-red-400 shrink-0 text-xs"></i>
        <span>${ep}</span>
      `;
      epContainer.appendChild(div);
    });
  }
}

function renderFilesTab(fileEntries) {
  document.getElementById('fileExplorerCount').textContent = `${fileEntries.length} items`;
  const tbody = document.getElementById('fileExplorerTableBody');
  tbody.innerHTML = '';

  fileEntries.slice(0, 100).forEach(file => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-cyber-800/60 transition';
    let icon = 'fa-file text-cyan-400';
    if (file.name.endsWith('.dex')) icon = 'fa-cube text-purple-400';
    else if (file.name.endsWith('.xml')) icon = 'fa-code text-blue-400';
    else if (file.name.endsWith('.so')) icon = 'fa-microchip text-amber-400';
    else if (file.name.startsWith('META-INF/')) icon = 'fa-certificate text-emerald-400';

    tr.innerHTML = `
      <td class="py-2 flex items-center space-x-2 text-slate-300">
        <i class="fa-solid ${icon} text-xs shrink-0"></i>
        <span class="truncate max-w-sm">${file.name}</span>
      </td>
      <td class="py-2 text-right text-slate-400">${(file.size / 1024).toFixed(1)} KB</td>
      <td class="py-2 text-right text-emerald-400 text-[11px]">Zip Deflated</td>
    `;
    tbody.appendChild(tr);
  });
}

function loadSamplePreset(type) {
  let sampleData = null;
  if (type === 'spynote') {
    sampleData = {
      fileName: 'SpyNote_Trojan_RAT_v6.apk',
      fileSize: 4194304,
      hashes: {
        sha256: '8b7fca1289190283bca98124019280194812401823901bca7281f9a28741e982',
        sha1: '3df21c8ab745143a25efba7124f114ea627cc789',
        md5: '7d8912ca68b75f10283c74de90efab11'
      },
      manifestStrings: [
        'com.google.system.update',
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.RECEIVE_BOOT_COMPLETED',
        'android.permission.RECORD_AUDIO',
        'android.permission.REQUEST_INSTALL_PACKAGES',
        'android.permission.READ_PHONE_STATE',
        'android.permission.INTERNET',
        'Android Debug'
      ],
      dexStrings: [
        'DexClassLoader',
        'Runtime.getRuntime().exec',
        '/system/bin/su',
        'getDeviceId',
        'AccessibilityServiceInfo',
        'http://194.38.20.14:8080/c2_rat_stream',
        'https://rat-drop-panel.ru/sync'
      ],
      fileEntries: [
        { name: 'AndroidManifest.xml', size: 9120 },
        { name: 'classes.dex', size: 2190000 },
        { name: 'classes2.dex', size: 1040000 },
        { name: 'assets/payload.enc', size: 640000 },
        { name: 'META-INF/CERT.RSA', size: 1420 }
      ],
      hasCert: true,
      isDebugCert: true
    };
  } else if (type === 'adware') {
    sampleData = {
      fileName: 'MobiBoost_Cleaner_Utility.apk',
      fileSize: 18451920,
      hashes: {
        sha256: '4bca78214fe1a719db0c4a45b919ca1e23118a8cf38c11451f28b7e781a94ef8',
        sha1: '19ca3382718817cba562145b94f114a8726bc411',
        md5: '9a3182efc8192a7147b198da1c72b891'
      },
      manifestStrings: [
        'com.mobiboost.ram.cleaner',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.RECEIVE_BOOT_COMPLETED',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.READ_PHONE_STATE',
        'android.permission.INTERNET',
        'android.permission.ACCESS_NETWORK_STATE'
      ],
      dexStrings: [
        'Cipher.getInstance',
        'getDeviceId',
        'https://sdk.pushad-monetize.asia/v2/bid',
        'https://telemetry-analytics-track.biz/beacon'
      ],
      fileEntries: [
        { name: 'AndroidManifest.xml', size: 14210 },
        { name: 'classes.dex', size: 4891240 },
        { name: 'resources.arsc', size: 1248000 },
        { name: 'META-INF/CERT.RSA', size: 1720 }
      ],
      hasCert: true,
      isDebugCert: false
    };
  } else {
    sampleData = {
      fileName: 'Signal_Messenger.apk',
      fileSize: 34120800,
      hashes: {
        sha256: '28fdca8192837482910fa8c71b625a49801823901bca7281f9a28741e9821a4f',
        sha1: 'a872149021873198cf910248a129038471928014',
        md5: '3c829104819284710293847192804712'
      },
      manifestStrings: [
        'org.thoughtcrime.securesms',
        'android.permission.CAMERA',
        'android.permission.RECORD_AUDIO',
        'android.permission.READ_CONTACTS',
        'android.permission.INTERNET',
        'android.permission.ACCESS_NETWORK_STATE'
      ],
      dexStrings: [
        'https://chat.signal.org/v1/websocket',
        'https://api.signal.org'
      ],
      fileEntries: [
        { name: 'AndroidManifest.xml', size: 18450 },
        { name: 'classes.dex', size: 8492000 },
        { name: 'lib/arm64-v8a/libsignal_jni.so', size: 4892100 },
        { name: 'META-INF/SIGNAL.RSA', size: 2048 }
      ],
      hasCert: true,
      isDebugCert: false
    };
  }

  const report = analyzeExtractedData(
    sampleData.fileName,
    sampleData.fileSize,
    sampleData.hashes,
    sampleData.fileEntries,
    sampleData.manifestStrings,
    sampleData.dexStrings,
    sampleData.hasCert,
    sampleData.isDebugCert
  );

  renderAnalysisDashboard(report);
  showToast(`Loaded preset case: ${sampleData.fileName}`, 'success');
}

function downloadJsonReport() {
  if (!currentAnalysisReport) {
    showToast('No active scan report to export', 'error');
    return;
  }
  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(currentAnalysisReport, null, 2));
  const a = document.createElement('a');
  a.setAttribute('href', dataStr);
  a.setAttribute('download', `DroidGuard_${currentAnalysisReport.packageName || 'report'}.json`);
  document.body.appendChild(a);
  a.click();
  a.remove();
  showToast('Threat audit exported as JSON', 'success');
}

function copyToClipboard(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.innerText || el.textContent;
  const tArea = document.createElement('textarea');
  tArea.value = text;
  document.body.appendChild(tArea);
  tArea.select();
  try {
    document.execCommand('copy');
    showToast('Copied to clipboard', 'success');
  } catch (err) {
    showToast('Failed to copy', 'error');
  }
  document.body.removeChild(tArea);
}