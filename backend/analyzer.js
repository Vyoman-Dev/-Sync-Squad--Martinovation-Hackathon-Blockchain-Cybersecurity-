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
