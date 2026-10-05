import crypto from 'crypto';
import JSZip from 'jszip';

const THREAT_RULES = {
  permissions: {
    // Critical tier: Permissions frequently weaponized by RATs, Trojans, and Spyware
    critical: [
      { 
        id: 'SYSTEM_ALERT_WINDOW', 
        name: 'Screen Overlay Tapjacking', 
        category: 'Overlay Hijack / Banking Trojan', 
        score: 25, 
        detail: 'Can display deceptive overlays on top of other apps to intercept credentials.' 
      },
      { 
        id: 'BIND_ACCESSIBILITY_SERVICE', 
        name: 'Accessibility Service Abuse', 
        category: 'Keylogging / Auto-Fraud', 
        score: 35, 
        detail: 'Can read screen text, monitor keystrokes, and automatically click buttons.' 
      },
      { 
        id: 'RECEIVE_BOOT_COMPLETED', 
        name: 'Persistent Startup', 
        category: 'Persistence Mechanism', 
        score: 15, 
        detail: 'Launches malicious services immediately when the device powers on.' 
      },
      { 
        id: 'INSTALL_PACKAGES', 
        name: 'Silent App Installation', 
        category: 'Payload Dropper', 
        score: 30, 
        detail: 'Attempts to install secondary payloads without user intervention.' 
      },
      { 
        id: 'REQUEST_INSTALL_PACKAGES', 
        name: 'Arbitrary APK Installation', 
        category: 'Dropper Vector', 
        score: 20, 
        detail: 'Requests permission to prompt users for unknown package installations.' 
      },
      { 
        id: 'RECORD_AUDIO', 
        name: 'Microphone Eavesdropping', 
        category: 'Surveillance / Spyware', 
        score: 20, 
        detail: 'Can secretly record ambient sound or phone conversations.' 
      },
      { 
        id: 'CAMERA', 
        name: 'Secret Camera Access', 
        category: 'Surveillance / Espionage', 
        score: 15, 
        detail: 'Can secretly take photographs or record video.' 
      }
    ],
    // Dangerous tier: Standard sensitive runtime permissions requiring user authorization
    dangerous: [
      { 
        id: 'READ_SMS', 
        name: 'SMS Message Interception', 
        category: 'OTP / 2FA Theft', 
        score: 25, 
        detail: 'Can steal two-factor authentication SMS verification codes.' 
      },
      { 
        id: 'SEND_SMS', 
        name: 'Silent SMS Dispatch', 
        category: 'Toll Fraud / Premium Rate', 
        score: 25, 
        detail: 'Can send messages to premium-rate numbers incurring carrier charges.' 
      },
      { 
        id: 'RECEIVE_SMS', 
        name: 'Incoming SMS Sniffing', 
        category: 'OTP / 2FA Theft', 
        score: 20, 
        detail: 'Can intercept incoming transaction authorization tokens.' 
      },
      { 
        id: 'READ_CONTACTS', 
        name: 'Address Book Harvesting', 
        category: 'Data Exfiltration', 
        score: 15, 
        detail: 'Uploads contact lists to command-and-control servers.' 
      },
      { 
        id: 'ACCESS_FINE_LOCATION', 
        name: 'Precise GPS Tracking', 
        category: 'Location Spyware', 
        score: 15, 
        detail: 'Monitors real-time physical device coordinates.' 
      },
      { 
        id: 'READ_PHONE_STATE', 
        name: 'IMEI / Device Identification', 
        category: 'Device Fingerprinting', 
        score: 10, 
        detail: 'Harvests device serial numbers, IMEI, and IMSI identifiers.' 
      }
    ]
  },
  // Dalvik Bytecode Signatures: Suspicious API invocations extracted from classes*.dex
  bytecode: [
    { 
      pattern: /DexClassLoader|PathClassLoader/i, 
      name: 'Dynamic Code Loading (DEX)', 
      category: 'Encrypted Payload Dropper', 
      score: 30, 
      detail: 'Loads and executes external unverified DEX files from remote servers.' 
    },
    { 
      pattern: /Runtime\.getRuntime\(\)\.exec|ProcessBuilder/i, 
      name: 'Native Shell Command Execution', 
      category: 'Privilege Escalation', 
      score: 30, 
      detail: 'Executes low-level Linux shell commands directly in the OS environment.' 
    },
    { 
      pattern: /\/system\/bin\/su|\/system\/xbin\/su/i, 
      name: 'Root Privilege Seeking', 
      category: 'Privilege Escalation', 
      score: 25, 
      detail: 'Actively searches for superuser (su) binaries to obtain full root control.' 
    },
    { 
      pattern: /getDeviceId|getSubscriberId|getSimSerialNumber/i, 
      name: 'Hardware Telemetry Harvesting', 
      category: 'Device Fingerprinting', 
      score: 15, 
      detail: 'Calls private telephony APIs to harvest device identifiers.' 
    }
  ]
};

function extractStringsFromBuffer(buffer) {
  const extracted = [];
  let currentAscii = '';
  let currentUtf16 = '';

  for (let i = 0; i < buffer.length; i++) {
    const b = buffer[i];

    // Branch A: Standard 7-bit printable ASCII characters (range 32..126)
    if (b >= 32 && b <= 126) {
      currentAscii += String.fromCharCode(b);
    } else {
      if (currentAscii.length >= 4) extracted.push(currentAscii);
      currentAscii = '';
    }

    // Branch B: UTF-16LE encoding (common in compiled Android binary XML pools)
    // Checks if current byte is printable and followed by a null high byte
    if (i + 1 < buffer.length && buffer[i + 1] === 0 && b >= 32 && b <= 126) {
      currentUtf16 += String.fromCharCode(b);
      i++; // Skip the high-order null byte
    } else {
      if (currentUtf16.length >= 4) extracted.push(currentUtf16);
      currentUtf16 = '';
    }
  }

  return extracted;
}
export async function parseAndAnalyzeApk(fileBuffer) {
  // Step 4.1: Compute unique cryptographic fingerprints
  const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');
  const md5 = crypto.createHash('md5').update(fileBuffer).digest('hex');

  // Step 4.2: Load APK archive into memory via JSZip
  const zip = await JSZip.loadAsync(fileBuffer);
  let rawStrings = [];
  const extractedPermissions = new Set();
  const detectedThreats = [];
  let riskScore = 0;

  // Step 4.3: Extract and inspect AndroidManifest.xml string tables
  const manifestFile = zip.file('AndroidManifest.xml');
  if (manifestFile) {
    const manifestBuffer = await manifestFile.async('nodebuffer');
    const strings = extractStringsFromBuffer(manifestBuffer);
    rawStrings = rawStrings.concat(strings);

    // Identify standard Android permission identifiers
    for (const str of strings) {
      const match = str.match(/android\.permission\.([A-Z_]+)/);
      if (match) extractedPermissions.add(match[1]);
    }
  }

  // Step 4.4: Loop through all DEX bytecode files (Multi-DEX support)
  const dexFiles = zip.file(/classes\d*\.dex/);
  for (const dexEntry of dexFiles) {
    const dexBuffer = await dexEntry.async('nodebuffer');
    const dexStrings = extractStringsFromBuffer(dexBuffer);
    rawStrings = rawStrings.concat(dexStrings);
  }

  const combinedDEXStrings = rawStrings.join('\n');

  // Step 4.5: Score critical permissions against detection catalog
  for (const p of THREAT_RULES.permissions.critical) {
    if (extractedPermissions.has(p.id)) {
      detectedThreats.push({
        severity: 'Critical',
        title: p.name,
        category: p.category,
        scoreImpact: p.score,
        detail: p.detail
      });
      riskScore += p.score;
    }
  }

  // Step 4.6: Score dangerous permissions against detection catalog
  for (const p of THREAT_RULES.permissions.dangerous) {
    if (extractedPermissions.has(p.id)) {
      detectedThreats.push({
        severity: 'Dangerous',
        title: p.name,
        category: p.category,
        scoreImpact: p.score,
        detail: p.detail
      });
      riskScore += p.score;
    }
  }

  // Step 4.7: Evaluate Dalvik bytecode string patterns
  for (const rule of THREAT_RULES.bytecode) {
    if (rule.pattern.test(combinedDEXStrings)) {
      detectedThreats.push({
        severity: 'High',
        title: rule.name,
        category: rule.category,
        scoreImpact: rule.score,
        detail: rule.detail
      });
      riskScore += rule.score;
    }
  }

  // Step 4.8: Verify APK signing integrity in META-INF/
  const certFiles = zip.file(/^META-INF\/.*\.(RSA|DSA|EC)$/i);
  if (certFiles.length === 0) {
    detectedThreats.push({
      severity: 'High',
      title: 'Missing or Unsigned Certificate',
      category: 'Package Tampering',
      scoreImpact: 20,
      detail: 'The APK lacks a standard cryptographic signature in META-INF/.'
    });
    riskScore += 20;
  }

  // Step 4.9: Normalize final score (0..100 range) and assign classification
  const finalScore = Math.min(100, Math.max(0, riskScore));
  let verdict = 'Safe';
  if (finalScore >= 70) verdict = 'Malicious';
  else if (finalScore >= 40) verdict = 'Suspicious';

  // Return formatted report object
  return {
    meta: {
      sha256,
      md5,
      totalDexFiles: dexFiles.length,
      manifestFound: !!manifestFile
    },
    riskScore: finalScore,
    verdict,
    permissions: Array.from(extractedPermissions),
    threats: detectedThreats
  };
}

