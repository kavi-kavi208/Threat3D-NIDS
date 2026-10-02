// Threat3D NIDS NOVA Tactical Voice Assistant Service
// SIMULATION ONLY — ZERO CORE DETECTION / BACKEND MODIFICATIONS
// Supports English (en-US) & Tamil (ta-IN) Speech Recognition and Synthesis

import { detectionApi, threatApi, trafficApi } from './api';
import { fetchThreatExplanation } from './chatService';
import type { Language } from '../i18n/translations';

export interface CommandExecutionResult {
  recognizedText: string;
  responseMessage: string;
  actionExecuted?: string;
  success: boolean;
  navDestination?: string;
  languageChangedTo?: Language;
}

// Check Web Speech API Recognition support
export const isSpeechRecognitionSupported = (): boolean => {
  if (typeof window === 'undefined') return false;
  return !!(
    (window as unknown as { SpeechRecognition?: unknown }).SpeechRecognition ||
    (window as unknown as { webkitSpeechRecognition?: unknown }).webkitSpeechRecognition
  );
};

// Check Web Speech API Synthesis support
export const isSpeechSynthesisSupported = (): boolean => {
  if (typeof window === 'undefined') return false;
  return 'speechSynthesis' in window && 'SpeechSynthesisUtterance' in window;
};

/**
 * Debug helper that logs ALL available voices in a console table.
 */
export const logAvailableVoices = (): void => {
  if (!isSpeechSynthesisSupported()) return;
  const voices = window.speechSynthesis.getVoices();
  if (voices && voices.length > 0) {
    console.table(
      voices.map((v) => ({
        name: v.name,
        lang: v.lang,
        localService: v.localService,
      }))
    );
  }
};

export interface SpeechChunk {
  text: string;
  lang: 'ta' | 'en';
}

/**
 * Checks if a character is within Tamil Unicode block (U+0B80–U+0BFF).
 */
export const isTamilChar = (c: string): boolean => {
  const code = c.charCodeAt(0);
  return code >= 0x0b80 && code <= 0x0bff;
};

/**
 * Returns true if text contains any Tamil Unicode character (U+0B80–U+0BFF).
 */
export const isTamilText = (text: string): boolean => {
  if (!text) return false;
  for (let i = 0; i < text.length; i++) {
    if (isTamilChar(text[i])) {
      return true;
    }
  }
  return false;
};

/**
 * Helper to check if a string contains any Latin alphabet letters (a-z, A-Z).
 */
export const containsLatinLetters = (text: string): boolean => {
  return /[a-zA-Z]/.test(text);
};

const TAMIL_UNITS: Record<number, string> = {
  0: 'பூஜ்ஜியம்',
  1: 'ஒன்று',
  2: 'இரண்டு',
  3: 'மூன்று',
  4: 'நான்கு',
  5: 'ஐந்து',
  6: 'ஆறு',
  7: 'ஏழு',
  8: 'எட்டு',
  9: 'ஒன்பது',
  10: 'பத்து',
  11: 'பதினொன்று',
  12: 'பன்னிரண்டு',
  13: 'பதிமூன்று',
  14: 'பதினான்கு',
  15: 'பதினைந்து',
  16: 'பதினாறு',
  17: 'பதினேழு',
  18: 'பதினெட்டு',
  19: 'பத்தொன்பது',
};

const TAMIL_TENS: Record<number, string> = {
  20: 'இருபது',
  30: 'முப்பது',
  40: 'நாற்பது',
  50: 'ஐம்பது',
  60: 'அறுபது',
  70: 'எழுபது',
  80: 'எண்பது',
  90: 'தொண்ணூறு',
};

const TAMIL_TENS_PREFIX: Record<number, string> = {
  20: 'இருபத்து ',
  30: 'முப்பத்து ',
  40: 'நாற்பத்து ',
  50: 'ஐம்பத்து ',
  60: 'அறுபத்து ',
  70: 'எழுபத்து ',
  80: 'எண்பத்து ',
  90: 'தொண்ணூற்று ',
};

const TAMIL_HUNDREDS: Record<number, string> = {
  100: 'நூறு',
  200: 'இருநூறு',
  300: 'முந்நூறு',
  400: 'நானூறு',
  500: 'ஐந்நூறு',
  600: 'அறுநூறு',
  700: 'எழுநூறு',
  800: 'எண்ணூறு',
  900: 'தொள்ளாயிரம்',
};

const TAMIL_HUNDREDS_PREFIX: Record<number, string> = {
  100: 'நூற்று ',
  200: 'இருநூற்று ',
  300: 'முந்நூற்று ',
  400: 'நானூற்று ',
  500: 'ஐந்நூற்று ',
  600: 'அறுநூற்று ',
  700: 'எழுநூற்று ',
  800: 'எண்ணூற்று ',
  900: 'தொள்ளாயிரத்து ',
};

/**
 * Converts integers to formal spoken Tamil words (0 to 9,999,999).
 */
export const integerToTamilWords = (n: number): string => {
  if (n < 0) return 'மைனஸ் ' + integerToTamilWords(-n);
  if (n <= 19) return TAMIL_UNITS[n];
  if (n < 100) {
    const tens = Math.floor(n / 10) * 10;
    const rem = n % 10;
    if (rem === 0) return TAMIL_TENS[tens];
    return TAMIL_TENS_PREFIX[tens] + TAMIL_UNITS[rem];
  }
  if (n < 1000) {
    const hundreds = Math.floor(n / 100) * 100;
    const rem = n % 100;
    if (rem === 0) return TAMIL_HUNDREDS[hundreds];
    return TAMIL_HUNDREDS_PREFIX[hundreds] + integerToTamilWords(rem);
  }
  if (n < 100000) {
    const thousands = Math.floor(n / 1000);
    const rem = n % 1000;
    const thPrefix = thousands === 1 ? 'ஆயிரத்து ' : integerToTamilWords(thousands) + ' ஆயிரத்து ';
    const thExact = thousands === 1 ? 'ஆயிரம்' : integerToTamilWords(thousands) + ' ஆயிரம்';
    if (rem === 0) return thExact;
    return thPrefix + integerToTamilWords(rem);
  }
  if (n < 10000000) {
    const lakhs = Math.floor(n / 100000);
    const rem = n % 100000;
    const lkPrefix = integerToTamilWords(lakhs) + ' லட்சத்து ';
    const lkExact = integerToTamilWords(lakhs) + ' லட்சம்';
    if (rem === 0) return lkExact;
    return lkPrefix + integerToTamilWords(rem);
  }
  return String(n)
    .split('')
    .map((d) => TAMIL_UNITS[parseInt(d, 10)] || d)
    .join(' ');
};

/**
 * Normalizes all numbers, IP addresses, percentages, and decimals into spoken Tamil words.
 */
export const convertNumbersInText = (text: string): string => {
  // IP addresses e.g. 192.168.1.1
  let res = text.replace(
    /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g,
    (_, a, b, c, d) =>
      `${integerToTamilWords(parseInt(a, 10))} புள்ளி ${integerToTamilWords(
        parseInt(b, 10)
      )} புள்ளி ${integerToTamilWords(parseInt(c, 10))} புள்ளி ${integerToTamilWords(
        parseInt(d, 10)
      )}`
  );

  // Decimals e.g. 50.5
  res = res.replace(/\b(\d+)\.(\d+)\b/g, (_, a, b) => {
    return `${integerToTamilWords(parseInt(a, 10))} புள்ளி ${integerToTamilWords(
      parseInt(b, 10)
    )}`;
  });

  // Percentages e.g. 50%
  res = res.replace(/\b(\d+)\s*%/g, (_, a) => {
    return `${integerToTamilWords(parseInt(a, 10))} சதவீதம்`;
  });

  // Ranges e.g. 1-10
  res = res.replace(/\b(\d+)\s*-\s*(\d+)\b/g, (_, a, b) => {
    return `${integerToTamilWords(parseInt(a, 10))} முதல் ${integerToTamilWords(
      parseInt(b, 10)
    )}`;
  });

  // Standalone numbers e.g. 50
  res = res.replace(/\b\d+\b/g, (match) => {
    const num = parseInt(match, 10);
    return isNaN(num) ? match : integerToTamilWords(num);
  });

  return res;
};

const TAMIL_LETTER_SOUNDS: Record<string, string> = {
  A: 'ஏ',
  B: 'பி',
  C: 'சி',
  D: 'டி',
  E: 'இ',
  F: 'எஃப்',
  G: 'ஜி',
  H: 'எச்',
  I: 'ஐ',
  J: 'ஜே',
  K: 'கே',
  L: 'எல்',
  M: 'எம்',
  N: 'என்',
  O: 'ஓ',
  P: 'பி',
  Q: 'க்யூ',
  R: 'ஆர்',
  S: 'எஸ்',
  T: 'டி',
  U: 'யு',
  V: 'வி',
  W: 'டபிள்யூ',
  X: 'எக்ஸ்',
  Y: 'ஒய்',
  Z: 'இஸட்',
};

const PHRASE_REPLACEMENTS: [RegExp, string][] = [
  // Full phrase examples from requirements & system models
  [/\bNIDS\s+ஒரு\s+network\s+security\s+system(?:\.|$)/gi, 'என் ஐ டி எஸ் என்பது பிணைய பாதுகாப்பு அமைப்பாகும்.'],
  [/\bThreat3D\s+ஒரு\s+Network\s+Intrusion\s+Detection\s+System(?:\.|$)/gi, 'த்ரெட் த்ரீ டி என்பது பிணைய ஊடுருவல் கண்டறிதல் அமைப்பாகும்.'],
  [/\bNetwork\s+Intrusion\s+Detection\s+System(?:\.|$)/gi, 'பிணைய ஊடுருவல் கண்டறிதல் அமைப்பாகும்.'],
  [/\bNetwork\s+Intrusion\s+Detection\s+System\b/gi, 'பிணைய ஊடுருவல் கண்டறிதல் அமைப்பு'],
  [/\bNetwork\s+Security\s+System(?:\.|$)/gi, 'பிணைய பாதுகாப்பு அமைப்பாகும்.'],
  [/\bNetwork\s+Security\s+System\b/gi, 'பிணைய பாதுகாப்பு அமைப்பு'],
  [/\bNetwork\s+Security\b/gi, 'பிணைய பாதுகாப்பு'],
  [/\bIntrusion\s+Detection\s+System(?:\.|$)/gi, 'ஊடுருவல் கண்டறிதல் அமைப்பாகும்.'],
  [/\bIntrusion\s+Detection\s+System\b/gi, 'ஊடுருவல் கண்டறிதல் அமைப்பு'],
  [/\bIntrusion\s+Detection\b/gi, 'ஊடுருவல் கண்டறிதல்'],
  [/\bNetwork\s+Intrusion\b/gi, 'பிணைய ஊடுருவல்'],

  // Frameworks & terms
  [/\bMITRE\s+ATT&CK\b/gi, 'மைட்ரே அட்டாக்'],
  [/\bMITRE\s+ATT\s*&\s*CK\b/gi, 'மைட்ரே அட்டாக்'],
  [/\bMITRE\s+Attack\b/gi, 'மைட்ரே அட்டாக்'],
  [/\bSYN\s+Flood\b/gi, 'சின் வெள்ளம்'],
  [/\bPort\s+Scan(?:ning)?\b/gi, 'போர்ட் ஸ்கேன்'],
  [/\bSQL\s+Injection\b/gi, 'எஸ் க்யூ எல் ஊடுருவல்'],
  [/\bBrute\s+Force\b/gi, 'ப்ரூட் ஃபோர்ஸ்'],
  [/\bDenial\s+of\s+Service\b/gi, 'சேவை மறுப்பு'],
  [/\bDistributed\s+Denial\s+of\s+Service\b/gi, 'விநியோகிக்கப்பட்ட சேவை மறுப்பு'],
  [/\bZero\s+Day\b/gi, 'ஜீரோ டே'],
  [/\bMan\s+in\s+the\s+Middle\b/gi, 'மேன் இன் தி மிடில்'],

  // Threat3D specific terms
  [/\bThreat3D\b/gi, 'த்ரெட் த்ரீ டி'],
  [/\bThreat\s*3D\b/gi, 'த்ரெட் த்ரீ டி'],
  [/\b3D\b/gi, 'த்ரீ டி'],
  [/\bWelford(?:'s)?\s+Algorithm\b/gi, 'வெல்ஃபோர்ட் வழிமுறை'],
  [/\bWelford\b/gi, 'வெல்ஃபோர்ட்'],
  [/\bSnort\s+Signature(?:s)?\b/gi, 'ஸ்னார்ட் கையொப்பங்கள்'],
  [/\bSnort\b/gi, 'ஸ்னார்ட்'],
  [/\bZ[- ]Score\b/gi, 'இஸட் ஸ்கோர்'],
  [/\bAnomaly\s+Detection\b/gi, 'ஒழுங்கின்மை கண்டறிதல்'],
  [/\bSignature\s+Detection\b/gi, 'கையொப்பம் கண்டறிதல்'],
  [/\bHybrid\s+Detection\b/gi, 'கலப்பின கண்டறிதல்'],
  [/\bStatistical\s+Anomaly\b/gi, 'புள்ளிவிவர ஒழுங்கின்மை'],
  [/\bThreat\s+Score\b/gi, 'அச்சுறுத்தல் மதிப்பெண்'],
  [/\bThreat\s+Level\b/gi, 'அச்சுறுத்தல் நிலை'],
  [/\bThreat\s+Summary\b/gi, 'அச்சுறுத்தல் சுருக்கம்'],
  [/\bEngine\s+Status\b/gi, 'இயந்திர நிலை'],
  [/\bTraffic\s+Flows?\b/gi, 'போக்குவரத்து ஓட்டங்கள்'],
  [/\bTraffic\s+Pipeline\b/gi, 'போக்குவரத்து வரிசை'],
  [/\bNetwork\s+Topology\b/gi, 'பிணைய இடவியல்'],
  [/\bAttack\s+Simulation\b/gi, 'தாக்குதல் உருவகப்படுத்துதல்'],
  [/\bSimulation\s+Hub\b/gi, 'உருவகப்படுத்துதல் மையம்'],
  [/\bLearning\s+Center\b/gi, 'கற்றல் மையம்'],
  [/\b5[- ]tuple\b/gi, 'ஐந்து டூப்பிள்'],
];

const TERM_MAP: Record<string, string> = {
  nids: 'என் ஐ டி எஸ்',
  ids: 'ஐ டி எஸ்',
  ips: 'ஐ பி எஸ்',
  tcp: 'டி சி பி',
  udp: 'யு டி பி',
  http: 'எச் டி டி பி',
  https: 'எச் டி டி பி எஸ்',
  ip: 'ஐ பி',
  sql: 'எஸ் க்யூ எல்',
  ai: 'ஏ ஐ',
  api: 'ஏ பி ஐ',
  soc: 'எஸ் ஓ சி',
  dos: 'டி ஓ எஸ்',
  ddos: 'டி டி ஓ எஸ்',
  syn: 'சின்',
  ack: 'அக்',
  icmp: 'ஐ சி எம் பி',
  dns: 'டி என் எஸ்',
  ssh: 'எஸ் எஸ் எச்',
  ftp: 'எஃப் டி பி',
  mac: 'மேக்',
  lan: 'லேன்',
  wan: 'வேன்',
  vpn: 'வி பி என்',
  cve: 'சி வி இ',
  os: 'ஓ எஸ்',
  cpu: 'சி பி யு',
  ram: 'ரேம்',
  ui: 'யூ ஐ',
  url: 'யு ஆர் எல்',
  id: 'ஐ டி',
  pcap: 'பி கேப்',
  mitre: 'மைட்ரே',
  nova: 'நோவா',

  score: 'மதிப்பெண்',
  network: 'பிணைய',
  security: 'பாதுகாப்பு',
  system: 'அமைப்பு',
  systems: 'அமைப்புகள்',
  traffic: 'போக்குவரத்து',
  alert: 'எச்சரிக்கை',
  alerts: 'எச்சரிக்கைகள்',
  packet: 'பாக்கெட்',
  packets: 'பாக்கெட்டுகள்',
  threat: 'அச்சுறுத்தல்',
  threats: 'அச்சுறுத்தல்கள்',
  attack: 'தாக்குதல்',
  attacks: 'தாக்குதல்கள்',
  attacker: 'தாக்குதல் நடத்துபவர்',
  anomaly: 'ஒழுங்கின்மை',
  anomalies: 'ஒழுங்கின்மைகள்',
  signature: 'கையொப்பம்',
  signatures: 'கையொப்பங்கள்',
  baseline: 'அடிப்படைக்கோடு',
  rule: 'விதி',
  rules: 'விதிகள்',
  simulation: 'உருவகப்படுத்துதல்',
  topology: 'இடவியல்',
  engine: 'இயந்திரம்',
  engines: 'இயந்திரங்கள்',
  dashboard: 'டாஷ்போர்டு',
  flow: 'ஓட்டம்',
  flows: 'ஓட்டங்கள்',
  model: 'மாதிரி',
  models: 'மாதிரிகள்',
  data: 'தரவு',
  server: 'சர்வர்',
  servers: 'சர்வர்கள்',
  client: 'கிளையன்ட்',
  host: 'ஹோஸ்ட்',
  hosts: 'ஹோஸ்ட்கள்',
  node: 'முனை',
  nodes: 'முனைகள்',
  port: 'போர்ட்',
  ports: 'போர்ட்கள்',
  scan: 'ஸ்கேன்',
  probe: 'ஆய்வு',
  flood: 'வெள்ளம்',
  firewall: 'ஃபயர்வால்',
  malware: 'மால்வேர்',
  ransomware: 'ரான்சம்வேர்',
  phishing: 'ஃபிஷிங்',
  vulnerability: 'பாதிப்பு',
  vulnerabilities: 'பாதிப்புகள்',
  mitigation: 'தணிப்பு',
  severity: 'தீவிரத்தன்மை',
  status: 'நிலை',
  admin: 'நிர்வாகி',
  analyst: 'பகுப்பாய்வாளர்',
  student: 'மாணவர்',
  role: 'பங்கு',
  roles: 'பங்குகள்',
  user: 'பயனர்',
  users: 'பயனர்கள்',
  normal: 'இயல்பான',
  high: 'உயர்',
  medium: 'நடுத்தர',
  low: 'குறைந்த',
  critical: 'முக்கியமான',
  active: 'செயலில் உள்ள',
  inactive: 'செயலிழந்த',
  blocked: 'தடுக்கப்பட்டது',
  allowed: 'அனுமதிக்கப்பட்டது',
  detected: 'கண்டறியப்பட்டது',
  mean: 'சராசரி',
  variance: 'மாறுபாடு',
  sample: 'மாதிரி',
  samples: 'மாதிரிகள்',
  rate: 'விகிதம்',
  threshold: 'வரம்பு',
  online: 'ஆன்லைனில் உள்ளது',
  offline: 'ஆஃப்லைனில் உள்ளது',
  connected: 'இணைக்கப்பட்டுள்ளது',
  disconnected: 'துண்டிக்கப்பட்டது',
  ready: 'தயார்',
  calibrating: 'அளவீடு செய்கிறது',
  total: 'மொத்தம்',
  count: 'எண்ணிக்கை',
  level: 'நிலை',
  source: 'மூலம்',
  destination: 'இலக்கு',
  action: 'நடவடிக்கை',
  actions: 'நடவடிக்கைகள்',
  recommendation: 'பரிந்துரை',
  recommendations: 'பரிந்துரைகள்',
};

const transliterateRemainingLatin = (word: string): string => {
  if (/^[A-Z]+$/.test(word)) {
    return word
      .split('')
      .map((ch) => TAMIL_LETTER_SOUNDS[ch] || ch)
      .join(' ');
  }

  const dig: [string, string][] = [
    ['tion', 'ஷன்'],
    ['sion', 'ஷன்'],
    ['ing', 'இங்'],
    ['th', 'த்'],
    ['ch', 'ச்'],
    ['sh', 'ஷ்'],
    ['ph', 'ஃப்'],
    ['wh', 'வ்'],
    ['ck', 'க்'],
    ['ng', 'ங்'],
    ['ee', 'ஈ'],
    ['oo', 'ஊ'],
    ['ai', 'ஐ'],
    ['ay', 'ஏ'],
    ['ea', 'ஈ'],
    ['qu', 'க்வ'],
  ];

  let w = word.toLowerCase();
  for (const [en, ta] of dig) {
    w = w.split(en).join(ta);
  }

  const charMap: Record<string, string> = {
    a: 'அ',
    b: 'ப்',
    c: 'க்',
    d: 'ட்',
    e: 'எ',
    f: 'ஃப்',
    g: 'க்',
    h: 'ஹ்',
    i: 'இ',
    j: 'ஜ்',
    k: 'க்',
    l: 'ல்',
    m: 'ம்',
    n: 'ன்',
    o: 'ஒ',
    p: 'ப்',
    q: 'க்',
    r: 'ர்',
    s: 'ஸ்',
    t: 'ட்',
    u: 'உ',
    v: 'வ்',
    w: 'வ்',
    x: 'க்ஸ்',
    y: 'ய்',
    z: 'ஸ்',
  };

  return w
    .split('')
    .map((ch) => charMap[ch] || ch)
    .join('');
};

/**
 * Transforms any bilingual or mixed technical response completely into pure Tamil script.
 * Zero Latin letters or English abbreviations remain. Numbers are converted to Tamil words.
 */
export const convertTextToTamilScriptOnly = (text: string): string => {
  if (!text || !text.trim()) return '';

  let processed = text.trim();

  // 1. Convert numbers first into Tamil words
  processed = convertNumbersInText(processed);

  // 2. Apply multi-word cybersecurity phrases
  for (const [regex, replacement] of PHRASE_REPLACEMENTS) {
    processed = processed.replace(regex, replacement);
  }

  // 3. Convert individual technical terms, acronyms, and remaining Latin words
  processed = processed.replace(/[a-zA-Z]+/g, (match) => {
    const lower = match.toLowerCase();
    if (TERM_MAP[lower]) {
      return TERM_MAP[lower];
    }
    if (/^[A-Z]+$/.test(match)) {
      return match
        .split('')
        .map((ch) => TAMIL_LETTER_SOUNDS[ch] || ch)
        .join(' ');
    }
    return transliterateRemainingLatin(match);
  });

  // Clean extra spaces
  processed = processed.replace(/\s+/g, ' ').trim();

  // Clean trailing duplicate punctuation
  processed = processed.replace(/அமைப்பாகும்\s*\./g, 'அமைப்பாகும்.').replace(/\.\./g, '.');

  return processed;
};

/**
 * Splits pure Tamil script text safely by sentence boundaries (to prevent speech synthesis
 * length-limit timeouts on Chrome/Edge) while ensuring 100% of chunks stay in 'ta'.
 */
export const segmentTamilSpeech = (text: string): SpeechChunk[] => {
  if (!text || !text.trim()) return [];
  const trimmed = text.trim();

  // If sentence is relatively short (< 250 chars), keep as single chunk for uninterrupted flow
  if (trimmed.length < 250) {
    return [{ text: trimmed, lang: 'ta' }];
  }

  // Split by sentence terminators (., !, ?, \n)
  const sentences = trimmed
    .split(/([.!?\n]+)/)
    .reduce<string[]>((acc, part, i, arr) => {
      if (i % 2 === 0) {
        const punctuation = arr[i + 1] || '';
        const combined = (part + punctuation).trim();
        if (combined) acc.push(combined);
      }
      return acc;
    }, []);

  if (sentences.length === 0) {
    return [{ text: trimmed, lang: 'ta' }];
  }

  return sentences.map((s) => ({ text: s, lang: 'ta' }));
};

/**
 * Word/Phrase-based Language Segmentation.
 * In Tamil voice mode, all text is normalized to 100% Tamil script to ensure
 * voice continuity without switching to an English voice mid-sentence.
 */
export const segmentSpeechText = (text: string, defaultLang: Language = 'en'): SpeechChunk[] => {
  if (!text || !text.trim()) return [];

  const rawTrimmed = text.trim();
  const hasTamil = isTamilText(rawTrimmed);
  const isTamilMode = defaultLang === 'ta' || hasTamil;

  // In Tamil voice mode, convert any mixed/technical content completely into Tamil script
  // and do NOT split across English chunks or switch voices mid-sentence.
  if (isTamilMode) {
    const tamilScriptOnly = convertTextToTamilScriptOnly(rawTrimmed);
    return segmentTamilSpeech(tamilScriptOnly);
  }

  // Pure English speech
  return [{ text: rawTrimmed, lang: 'en' }];
};

let cachedVoices: SpeechSynthesisVoice[] = [];

/**
 * Asynchronously ensures the browser voice list has populated before voice selection.
 * Handles both immediate cache and asynchronous 'voiceschanged' browser events.
 */
export const ensureVoicesLoaded = (): Promise<SpeechSynthesisVoice[]> => {
  return new Promise((resolve) => {
    if (!isSpeechSynthesisSupported()) {
      resolve([]);
      return;
    }

    const current = window.speechSynthesis.getVoices();
    if (current && current.length > 0) {
      cachedVoices = current;
      resolve(current);
      return;
    }

    let resolved = false;
    const cleanupAndResolve = (voices: SpeechSynthesisVoice[]) => {
      if (resolved) return;
      resolved = true;
      cachedVoices = voices;
      resolve(voices);
    };

    const handleVoicesChanged = () => {
      const v = window.speechSynthesis.getVoices();
      if (v && v.length > 0) {
        window.speechSynthesis.removeEventListener('voiceschanged', handleVoicesChanged);
        cleanupAndResolve(v);
      }
    };

    window.speechSynthesis.addEventListener('voiceschanged', handleVoicesChanged);

    // Polling fallback every 50ms up to 1000ms for fast initial resolution
    const startTime = Date.now();
    const intervalId = setInterval(() => {
      const v = window.speechSynthesis.getVoices();
      if (v && v.length > 0) {
        clearInterval(intervalId);
        window.speechSynthesis.removeEventListener('voiceschanged', handleVoicesChanged);
        cleanupAndResolve(v);
      } else if (Date.now() - startTime > 1000) {
        clearInterval(intervalId);
        window.speechSynthesis.removeEventListener('voiceschanged', handleVoicesChanged);
        cleanupAndResolve(v || []);
      }
    }, 50);
  });
};

// Eagerly pre-load voices on module import
if (typeof window !== 'undefined' && isSpeechSynthesisSupported()) {
  ensureVoicesLoaded();
  window.speechSynthesis.addEventListener('voiceschanged', () => {
    const v = window.speechSynthesis.getVoices();
    if (v && v.length > 0) {
      cachedVoices = v;
    }
  });
}

/**
 * Robust Tamil Voice Selector.
 * Priority:
 * FIRST:
 *   voice.lang === "ta-IN" (normalized)
 *   Among ta-IN voices prefer names containing:
 *   - Valluvar / வள்ளுவர்
 *   - Pallavi / பல்லவி
 *   - Google தமிழ்
 *   - Tamil / தமிழ்
 *   - Any ta-IN voice
 * SECOND:
 *   any real voice where voice.lang startsWith("ta") (ta-LK, ta-SG, ta-MY, ta)
 *   preferring Valluvar, Pallavi, Google தமிழ், Tamil
 * THIRD:
 *   voice.name containing Tamil/தமிழ் if lang does not start with "en"
 * NEVER returns an English voice or treats "ta-IN Browser Engine" as a dedicated Tamil voice.
 */
export const getTamilVoice = (customVoices?: SpeechSynthesisVoice[]): SpeechSynthesisVoice | null => {
  if (!isSpeechSynthesisSupported()) return null;
  const current = customVoices && customVoices.length > 0 ? customVoices : window.speechSynthesis.getVoices();
  const voices = current && current.length > 0 ? current : cachedVoices;
  if (!voices || voices.length === 0) return null;

  const normalizeLang = (l: string) => (l || '').trim().toLowerCase().replace('_', '-');

  // FIRST: voice.lang === "ta-IN"
  const exactTaInVoices = voices.filter((v) => normalizeLang(v.lang) === 'ta-in');

  if (exactTaInVoices.length > 0) {
    const valluvar = exactTaInVoices.find((v) => {
      const n = (v.name || '').toLowerCase();
      return n.includes('valluvar') || v.name.includes('வள்ளுவர்');
    });
    if (valluvar) return valluvar;

    const pallavi = exactTaInVoices.find((v) => {
      const n = (v.name || '').toLowerCase();
      return n.includes('pallavi') || v.name.includes('பல்லவி');
    });
    if (pallavi) return pallavi;

    const googleTamil = exactTaInVoices.find((v) => {
      const n = (v.name || '').toLowerCase();
      return n.includes('google') && (n.includes('tamil') || v.name.includes('தமிழ்'));
    });
    if (googleTamil) return googleTamil;

    const namedTamil = exactTaInVoices.find((v) => {
      const n = (v.name || '').toLowerCase();
      return n.includes('tamil') || v.name.includes('தமிழ்');
    });
    if (namedTamil) return namedTamil;

    return exactTaInVoices[0];
  }

  // SECOND: any real voice where voice.lang startsWith("ta")
  const anyTaVoices = voices.filter((v) => normalizeLang(v.lang).startsWith('ta'));

  if (anyTaVoices.length > 0) {
    const valluvar = anyTaVoices.find((v) => {
      const n = (v.name || '').toLowerCase();
      return n.includes('valluvar') || v.name.includes('வள்ளுவர்');
    });
    if (valluvar) return valluvar;

    const pallavi = anyTaVoices.find((v) => {
      const n = (v.name || '').toLowerCase();
      return n.includes('pallavi') || v.name.includes('பல்லவி');
    });
    if (pallavi) return pallavi;

    const googleTamil = anyTaVoices.find((v) => {
      const n = (v.name || '').toLowerCase();
      return n.includes('google') && (n.includes('tamil') || v.name.includes('தமிழ்'));
    });
    if (googleTamil) return googleTamil;

    const namedTamil = anyTaVoices.find((v) => {
      const n = (v.name || '').toLowerCase();
      return n.includes('tamil') || v.name.includes('தமிழ்');
    });
    if (namedTamil) return namedTamil;

    return anyTaVoices[0];
  }

  // THIRD: Secondary fallback: check voice.name containing tamil / தமிழ் as long as it's not an English voice
  const namedTamilVoice = voices.find((v) => {
    const n = (v.name || '').toLowerCase();
    const l = normalizeLang(v.lang);
    return (n.includes('tamil') || v.name.includes('தமிழ்')) && !l.startsWith('en');
  });
  if (namedTamilVoice) return namedTamilVoice;

  return null;
};

/**
 * Robust English Voice Selector.
 * Priority: en-IN, en-US, en-GB, or any English voice.
 */
export const getEnglishVoice = (customVoices?: SpeechSynthesisVoice[]): SpeechSynthesisVoice | null => {
  if (!isSpeechSynthesisSupported()) return null;
  const current = customVoices && customVoices.length > 0 ? customVoices : window.speechSynthesis.getVoices();
  const voices = current && current.length > 0 ? current : cachedVoices;
  if (!voices || voices.length === 0) return null;

  const normalizeLang = (l: string) => (l || '').trim().toLowerCase().replace('_', '-');

  const enInVoice = voices.find((v) => normalizeLang(v.lang) === 'en-in');
  if (enInVoice) return enInVoice;

  const enUsVoice = voices.find((v) => normalizeLang(v.lang) === 'en-us');
  if (enUsVoice) return enUsVoice;

  const anyEnVoice = voices.find((v) => normalizeLang(v.lang).startsWith('en'));
  if (anyEnVoice) return anyEnVoice;

  return voices[0] || null;
};

/**
 * Best available voice matcher for a given language.
 */
export const getBestVoice = (lang: Language, customVoices?: SpeechSynthesisVoice[]): SpeechSynthesisVoice | null => {
  if (lang === 'ta') {
    return getTamilVoice(customVoices);
  }
  return getEnglishVoice(customVoices);
};

// Global session & utterance references to prevent V8 garbage collection bug during speech
interface SpeechSession {
  id: number;
  isCancelled: boolean;
}

let currentSession: SpeechSession | null = null;
let activeUtterances: SpeechSynthesisUtterance[] = [];
let sessionCounter = 0;

export const getActiveUtterances = (): SpeechSynthesisUtterance[] => activeUtterances;

/**
 * Safe, sequential, language-aware vocalization using browser SpeechSynthesis.
 * Preserves 100% of tokens and speaks them in their original order.
 */
export const speakUtterance = (
  text: string,
  lang: Language,
  onStart?: () => void,
  onEnd?: () => void
): void => {
  if (!isSpeechSynthesisSupported() || !text || !text.trim()) {
    if (onEnd) onEnd();
    return;
  }

  // 1. Cancel previous session and clear utterances
  if (currentSession) {
    currentSession.isCancelled = true;
    currentSession = null;
  }
  activeUtterances = [];

  // Cancel any ongoing browser speech synthesis safely
  if (window.speechSynthesis.speaking || window.speechSynthesis.pending) {
    try {
      window.speechSynthesis.cancel();
    } catch {
      // ignore
    }
  }

  // Unpause if stuck
  if (window.speechSynthesis.paused) {
    try {
      window.speechSynthesis.resume();
    } catch {
      // ignore
    }
  }

  const originalText = text.trim();
  const isTamil = lang === 'ta' || isTamilText(originalText);
  const textToVocalize = isTamil ? convertTextToTamilScriptOnly(originalText) : originalText;
  const segments = segmentSpeechText(textToVocalize, isTamil ? 'ta' : lang);

  if (segments.length === 0) {
    if (onEnd) onEnd();
    return;
  }

  // Preservation validation check
  const reconstructedText = segments.map((s) => s.text).join(' ');
  const normalize = (s: string) => s.replace(/\s+/g, ' ').trim();
  const preserved = normalize(reconstructedText) === normalize(textToVocalize);

  console.log("TTS ORIGINAL INPUT:", originalText);
  console.log("TTS VOCALIZED (TAMIL SCRIPT ONLY):", textToVocalize);
  console.log("TTS SEGMENTS:", segments);
  console.log("TTS RECONSTRUCTED:", reconstructedText);
  console.log("TTS TEXT PRESERVED:", preserved);

  // Queue validation logging
  segments.forEach((segment, index) => {
    console.log(
      "TTS SEGMENT",
      index,
      segment.text,
      segment.lang === 'ta' ? 'ta-IN' : 'en-US'
    );
  });

  const sessionId = ++sessionCounter;
  const session: SpeechSession = { id: sessionId, isCancelled: false };
  currentSession = session;

  // Asynchronously ensure voices are loaded before beginning speech
  ensureVoicesLoaded().then((loadedVoices) => {
    if (session.isCancelled || currentSession !== session) return;

    const allVoices = loadedVoices && loadedVoices.length > 0 ? loadedVoices : window.speechSynthesis.getVoices();
    const normalizeLang = (l: string) => (l || '').trim().toLowerCase().replace('_', '-');
    const tamilCandidates = allVoices.filter((v) => {
      const vLang = normalizeLang(v.lang);
      const vName = (v.name || '').toLowerCase();
      return (
        vLang.startsWith('ta') ||
        vName.includes('tamil') ||
        v.name.includes('தமிழ்') ||
        vName.includes('valluvar') ||
        v.name.includes('வள்ளுவர்') ||
        vName.includes('pallavi') ||
        v.name.includes('பல்லவி')
      );
    });

    const selectedTamilVoice = getTamilVoice(allVoices);
    const isDedicatedTamil = !!selectedTamilVoice;

    console.log(
      "TTS ALL VOICES:",
      allVoices.map((v) => ({
        name: v.name,
        lang: v.lang,
        default: v.default,
        localService: v.localService,
      }))
    );
    console.log(
      "TTS TAMIL CANDIDATES:",
      tamilCandidates.map((v) => ({
        name: v.name,
        lang: v.lang,
        default: v.default,
        localService: v.localService,
      }))
    );
    console.log("TTS SELECTED TAMIL VOICE:", selectedTamilVoice ? selectedTamilVoice.name : "None");
    console.log("TTS SELECTED VOICE NAME:", selectedTamilVoice ? selectedTamilVoice.name : "None");
    console.log("TTS SELECTED VOICE LANG:", selectedTamilVoice ? selectedTamilVoice.lang : "ta-IN");
    console.log("TTS DEDICATED TAMIL VOICE:", isDedicatedTamil);

    if (isTamil && !selectedTamilVoice) {
      console.warn("NO REAL ta-IN VOICE AVAILABLE IN THIS BROWSER");
      console.log("TTS ALL VOICES (getVoices):", allVoices.map(v => `${v.name} (${v.lang})`));
    }

    // Allow cancellation IPC to complete before queueing new utterances
    setTimeout(() => {
      if (session.isCancelled || currentSession !== session) return;

      let hasStarted = false;

      const playChunk = (index: number) => {
        if (session.isCancelled || currentSession !== session) return;

        if (index >= segments.length) {
          if (currentSession === session) {
            currentSession = null;
          }
          activeUtterances = [];
          if (onEnd) onEnd();
          return;
        }

        if (!hasStarted) {
          hasStarted = true;
          if (onStart) onStart();
        }

        const segment = segments[index];
        const isTa = segment.lang === 'ta';
        const voice = isTa ? getTamilVoice(allVoices) : getEnglishVoice(allVoices);
        const languageTag = isTa ? (voice?.lang || 'ta-IN') : (voice?.lang || 'en-US');

        console.log("TTS CHUNK", {
          text: segment.text,
          language: languageTag,
          voiceName: voice?.name ?? "None",
          voiceLang: voice?.lang ?? languageTag,
        });
        console.log("TTS SELECTED VOICE NAME:", voice?.name ?? "None");
        console.log("TTS SELECTED VOICE LANG:", voice?.lang ?? languageTag);

        try {
          const utterance = new SpeechSynthesisUtterance(segment.text);
          utterance.lang = languageTag;
          if (voice) {
            utterance.voice = voice;
            utterance.lang = voice.lang;
          }
          utterance.rate = isTa ? 0.95 : 1.0;
          utterance.pitch = 1.0;

          console.log("TTS UTTERANCE VOICE:", utterance.voice ? utterance.voice.name : "None");
          console.log("TTS UTTERANCE LANG:", utterance.lang);

          activeUtterances.push(utterance);

          let advanced = false;
          const advance = () => {
            if (advanced) return;
            advanced = true;
            if (!session.isCancelled && currentSession === session) {
              playChunk(index + 1);
            }
          };

          utterance.onstart = () => {
            console.log("TTS EVENT START", {
              chunkIndex: index,
              language: utterance.lang,
              voice: utterance.voice ? utterance.voice.name : "None",
              text: segment.text,
            });
          };

          utterance.onend = () => {
            console.log("TTS EVENT END", {
              chunkIndex: index,
              language: utterance.lang,
              voice: utterance.voice ? utterance.voice.name : "None",
              text: segment.text,
            });
            advance();
          };

          utterance.onerror = (event: any) => {
            console.error("TTS ERROR", {
              chunkIndex: index,
              language: utterance.lang,
              voice: utterance.voice ? utterance.voice.name : "None",
              error: event.error,
              text: segment.text,
            });
            advance();
          };

          utterance.onpause = () => console.log("TTS EVENT PAUSE");
          utterance.onresume = () => console.log("TTS EVENT RESUME");

          window.speechSynthesis.speak(utterance);
        } catch (err) {
          console.error("TTS ERROR exception during speak:", err);
          if (!session.isCancelled && currentSession === session) {
            playChunk(index + 1);
          }
        }
      };

      playChunk(0);
    }, 50);
  });
};

// Cancel active speech synthesis immediately
export const stopSpeech = (): void => {
  if (currentSession) {
    currentSession.isCancelled = true;
    currentSession = null;
  }
  activeUtterances = [];
  if (isSpeechSynthesisSupported()) {
    try {
      window.speechSynthesis.cancel();
    } catch {
      // ignore
    }
  }
};

/**
 * Determine if a query is a cybersecurity/app Q&A question.
 * These should go to the backend chat API.
 */
const isCybersecurityQuestion = (q: string): boolean => {
  const qKeywords = [
    // English Q&A keywords
    'what is', 'what are', 'how does', 'how do', 'how to', 'explain',
    'why is', 'why does', 'tell me about', 'describe', 'define',
    'nids', 'welford', 'anomaly', 'snort', 'hybrid', 'threat score',
    'detection', 'pipeline', 'signature', 'baseline', 'z-score',
    'intrusion', 'syn flood', 'dos', 'sql injection', 'port scan',
    'brute force', 'icmp', 'mitre', 'att&ck', 'learning',
    'use this app', 'step by step', 'get started',
    'alert #', 'alert id', 'threat #', 'threat id',
    'what should', 'next step', 'do next', 'severity',
    // Tamil & Thanglish Q&A keywords
    'enna', 'epdi', 'epadi', 'eppadi', 'yeppadi', 'pannanum', 'panrathu', 'panradhu', 'enga paarkka',
    'na enna', 'irukku', 'la irukku', 'iruku', 'yen', 'yenn',
    'nids na', 'threat detect', 'welford work', 'indha app', 'app epdi',
    // Tamil script Q&A
    'என்ன', 'எப்படி', 'ஏன்', 'விளக்கம்', 'வழிகாட்டல்', 'இருப்பது', 'இருக்கு',
  ];
  return qKeywords.some((kw) => q.includes(kw));
};

// Tactical Command Processor connecting to real SOC telemetry & navigation
export const processTacticalCommand = async (
  rawQuery: string,
  currentLang: Language
): Promise<CommandExecutionResult> => {
  const q = rawQuery.trim().toLowerCase();

  // 1. STOP / MUTE / SILENCE  (always local)
  if (
    q === 'stop' || q === 'mute' || q === 'silence' ||
    q.includes('stop speaking') || q === 'நிறுத்து' || q === 'அமைதி' ||
    q.includes('பேச்சை நிறுத்து')
  ) {
    stopSpeech();
    return {
      recognizedText: rawQuery,
      responseMessage: currentLang === 'ta' ? 'நோவா அமைதியாக உள்ளது.' : 'NOVA speech muted.',
      actionExecuted: 'SILENCE',
      success: true,
    };
  }

  // 2. LANGUAGE SWITCHING  (always local)
  if (
    q.includes('switch to tamil') || q.includes('change to tamil') ||
    q.includes('tamil language') || q.includes('தமிழுக்கு மாறு') || q.includes('தமிழ் மொழி')
  ) {
    return {
      recognizedText: rawQuery,
      responseMessage: 'நோவா இடைமுகம் மற்றும் குரல் தமிழுக்கு மாற்றப்பட்டது.',
      actionExecuted: 'SWITCH_LANGUAGE_TA',
      languageChangedTo: 'ta',
      success: true,
    };
  }

  if (
    q.includes('switch to english') || q.includes('change to english') ||
    q.includes('english language') || q.includes('ஆங்கிலத்திற்கு மாறு') || q.includes('ஆங்கில மொழி')
  ) {
    return {
      recognizedText: rawQuery,
      responseMessage: 'NOVA interface and speech switched to English.',
      actionExecuted: 'SWITCH_LANGUAGE_EN',
      languageChangedTo: 'en',
      success: true,
    };
  }

  // 3. HELP / COMMANDS  (always local)
  if (q.includes('help') || q.includes('commands') || q.includes('உதவி') || q.includes('கட்டளை')) {
    const isTa = currentLang === 'ta' || q.includes('உதவி');
    return {
      recognizedText: rawQuery,
      responseMessage: isTa
        ? 'கிடைக்கும் கட்டளைகள்: "engine status", "show threats", "traffic flows", "open topology", "run simulation", "view rules", "switch to english". நீங்கள் NIDS, Welford, SYN Flood, போன்ற கேள்விகளையும் கேட்கலாம்!'
        : 'Available commands: "engine status", "show threats", "traffic flows", "open topology", "run simulation", "view rules", "switch to tamil". You can also ask cybersecurity questions like "What is NIDS?" or "How does Welford work?"',
      actionExecuted: 'HELP',
      success: true,
    };
  }

  // 4. CYBERSECURITY Q&A — Route to backend chat API
  if (isCybersecurityQuestion(q)) {
    try {
      const response = await fetchThreatExplanation(rawQuery);
      return {
        recognizedText: rawQuery,
        responseMessage: response.answer || 'No response available.',
        actionExecuted: 'CYBER_QA',
        success: true,
      };
    } catch {
      // Fall through to local handling
    }
  }

  // 5. DETECTION ENGINES & SIGNATURE STATUS  (live telemetry)
  if (
    q.includes('engine') || q.includes('status') || q.includes('baseline') || q.includes('snort') ||
    q.includes('இயந்திர') || q.includes('அடிப்படை') || q.includes('நிலை') ||
    q.includes('engine status') || q.includes('snort status')
  ) {
    try {
      const res = await detectionApi.getEngineStatus();
      const status = res.data;
      const activeRules = status?.signatureEngine?.activeRulesCount ?? 12;
      const baselineReady = status?.anomalyEngine?.baselineReady;
      const sampleCount = status?.anomalyEngine?.sampleCount ?? 0;

      if (currentLang === 'ta' || q.includes('நிலை') || q.includes('இயந்திர')) {
        return {
          recognizedText: rawQuery,
          responseMessage: `SOC இயந்திரம் செயல்படுகிறது. ஸ்னார்ட் கையொப்ப இயந்திரம் ${activeRules} விதிகளுடன் தயாராக உள்ளது. ஜாவா புள்ளிவிவர ஒழுங்கின்மை இயந்திரம்: ${
            baselineReady ? 'அடிப்படை தயார்' : `${sampleCount} மாதிரிகளுடன் அளவீடு செய்கிறது`
          }.`,
          actionExecuted: 'QUERY_ENGINE_STATUS',
          success: true,
        };
      }

      return {
        recognizedText: rawQuery,
        responseMessage: `SOC Defensive Engines Online. Snort signature matcher active with ${activeRules} rules. Pure-Java statistical anomaly engine is ${
          baselineReady ? 'Baseline Ready' : `calibrating (${sampleCount}/50 samples)`
        }.`,
        actionExecuted: 'QUERY_ENGINE_STATUS',
        success: true,
      };
    } catch {
      return {
        recognizedText: rawQuery,
        responseMessage:
          currentLang === 'ta'
            ? 'இயந்திர நிலையை வினவ முடியவில்லை.'
            : 'Unable to query detection engine status from SOC core.',
        actionExecuted: 'QUERY_ENGINE_STATUS',
        success: false,
      };
    }
  }

  // 6. THREAT ALERTS & SUMMARY  (live telemetry + navigation)
  if (
    q.includes('threat') || q.includes('alert') || q.includes('incident') ||
    q.includes('அச்சுறுத்தல்') || q.includes('எச்சரிக்கை') ||
    q.includes('show threats') || q.includes('view threats')
  ) {
    try {
      const res = await threatApi.getSummary();
      const summary = res.data;
      const total = summary?.totalAlerts ?? 0;
      const active = summary?.activeAlerts ?? 0;
      const critical = summary?.severityCounts?.['CRITICAL'] ?? 0;

      if (currentLang === 'ta' || q.includes('அச்சுறுத்தல்') || q.includes('எச்சரிக்கை')) {
        return {
          recognizedText: rawQuery,
          responseMessage: `தற்போது மொத்தம் ${total} அச்சுறுத்தல்கள் பதிவாகியுள்ளன. ${active} செயலில் உள்ளன, இதில் ${critical} மிகக் கடுமையானவை. அச்சுறுத்தல் பக்கத்திற்கு செல்கிறது.`,
          actionExecuted: 'NAVIGATE_THREATS',
          navDestination: '/threats',
          success: true,
        };
      }

      return {
        recognizedText: rawQuery,
        responseMessage: `Threat Summary: ${total} total alerts recorded. ${active} active, ${critical} critical. Opening Threat Management console.`,
        actionExecuted: 'NAVIGATE_THREATS',
        navDestination: '/threats',
        success: true,
      };
    } catch {
      return {
        recognizedText: rawQuery,
        responseMessage:
          currentLang === 'ta'
            ? 'அச்சுறுத்தல் தரவை பெற முடியவில்லை. அச்சுறுத்தல் பக்கத்திற்கு செல்கிறது.'
            : 'Opening Threat Alerts console.',
        actionExecuted: 'NAVIGATE_THREATS',
        navDestination: '/threats',
        success: true,
      };
    }
  }

  // 7. TRAFFIC & FLOWS  (live telemetry + navigation)
  if (
    q.includes('traffic') || q.includes('flow') || q.includes('packet') ||
    q.includes('போக்குவரத்து') || q.includes('ஓட்டம்') || q.includes('பாக்கெட்')
  ) {
    try {
      const res = await trafficApi.getStats();
      const stats = res.data;
      const packets = stats?.totalRecordsProcessed ?? 0;
      const flows = stats?.activeFlowCount ?? 0;

      if (currentLang === 'ta' || q.includes('போக்குவரத்து') || q.includes('ஓட்டம்')) {
        return {
          recognizedText: rawQuery,
          responseMessage: `பிணைய போக்குவரத்து: ${packets} பாக்கெட்டுகள் செயலாக்கப்பட்டன, ${flows} செயலில் உள்ள 5-டூப்பிள் ஓட்டங்கள் கண்காணிக்கப்படுகின்றன. போக்குவரத்து பக்கத்திற்கு செல்கிறது.`,
          actionExecuted: 'NAVIGATE_TRAFFIC',
          navDestination: '/traffic',
          success: true,
        };
      }

      return {
        recognizedText: rawQuery,
        responseMessage: `Traffic Pipeline: ${packets} packets processed across ${flows} active 5-tuple flows. Navigating to Traffic & Flows.`,
        actionExecuted: 'NAVIGATE_TRAFFIC',
        navDestination: '/traffic',
        success: true,
      };
    } catch {
      return {
        recognizedText: rawQuery,
        responseMessage:
          currentLang === 'ta'
            ? 'போக்குவரத்து பக்கத்திற்கு செல்கிறது.'
            : 'Navigating to Traffic & Flow Analysis.',
        actionExecuted: 'NAVIGATE_TRAFFIC',
        navDestination: '/traffic',
        success: true,
      };
    }
  }

  // 8. SIMULATION HUB NAVIGATION
  if (
    q.includes('simulation') || q.includes('simulate') || q.includes('scenario') ||
    q.includes('attack burst') || q.includes('run simulation') || q.includes('launch simulation') ||
    q.includes('உருவகப்படுத்துதல்') || q.includes('தாக்குதல்')
  ) {
    return {
      recognizedText: rawQuery,
      responseMessage:
        currentLang === 'ta'
          ? 'சைபர் தாக்குதல் உருவகப்படுத்துதல் மையத்திற்கு செல்கிறது. Port Scan, SYN Flood, Brute Force போன்ற உருவகப்படுத்துதல்களை இயக்கலாம்.'
          : 'Navigating to Cyber Attack Simulation Hub. You can launch Port Scan, SYN Flood, Brute Force, and other simulations from there.',
      actionExecuted: 'NAVIGATE_SIMULATION',
      navDestination: '/simulation',
      success: true,
    };
  }

  // 9. 3D TOPOLOGY NAVIGATION
  if (
    q.includes('topology') || q.includes('3d') || q.includes('network node') ||
    q.includes('network map') || q.includes('இடவியல்') || q.includes('முனை')
  ) {
    return {
      recognizedText: rawQuery,
      responseMessage:
        currentLang === 'ta'
          ? '3D பிணைய இடவியல் காட்சிக்கு செல்கிறது.'
          : 'Opening 3D Network Topology visualization.',
      actionExecuted: 'NAVIGATE_TOPOLOGY',
      navDestination: '/topology',
      success: true,
    };
  }

  // 10. RULES & ENGINES NAVIGATION
  if (
    q.includes('rule') || q.includes('signature') || q.includes('engines') ||
    q.includes('விதி') || q.includes('கையொப்பம்')
  ) {
    return {
      recognizedText: rawQuery,
      responseMessage:
        currentLang === 'ta'
          ? 'கண்டறிதல் விதிகள் மற்றும் இயந்திரங்கள் பக்கத்திற்கு செல்கிறது.'
          : 'Navigating to Detection Engines & Snort Signatures.',
      actionExecuted: 'NAVIGATE_RULES',
      navDestination: '/rules',
      success: true,
    };
  }

  // 11. LEARNING CENTER NAVIGATION
  if (
    q.includes('learning') || q.includes('learn') || q.includes('dossier') ||
    q.includes('கற்றல்') || q.includes('mitre')
  ) {
    return {
      recognizedText: rawQuery,
      responseMessage:
        currentLang === 'ta'
          ? 'SOC கற்றல் மையத்திற்கு செல்கிறது.'
          : 'Navigating to SOC Learning Center.',
      actionExecuted: 'NAVIGATE_LEARNING',
      navDestination: '/learning',
      success: true,
    };
  }

  // 12. DASHBOARD NAVIGATION
  if (
    q.includes('dashboard') || q.includes('home') || q.includes('main') || q.includes('soc') ||
    q.includes('முகப்பு') || q.includes('கட்டுப்பாட்டு மையம்')
  ) {
    return {
      recognizedText: rawQuery,
      responseMessage:
        currentLang === 'ta'
          ? 'SOC பிரதான கட்டுப்பாட்டு மையத்திற்கு செல்கிறது.'
          : 'Navigating to SOC Dashboard.',
      actionExecuted: 'NAVIGATE_DASHBOARD',
      navDestination: '/',
      success: true,
    };
  }

  // 13. FALLBACK — Try backend chat API for any unrecognized query
  try {
    const response = await fetchThreatExplanation(rawQuery);
    if (response.answer) {
      return {
        recognizedText: rawQuery,
        responseMessage: response.answer,
        actionExecuted: 'CYBER_QA_FALLBACK',
        success: true,
      };
    }
  } catch {
    // Backend unavailable
  }

  // 14. DEFAULT / UNRECOGNIZED
  const isTa = currentLang === 'ta';
  return {
    recognizedText: rawQuery,
    responseMessage: isTa
      ? `"${rawQuery}" புரியவில்லை. "என் ஐ டி எஸ் என்றால் என்ன?", "உருவகப்படுத்துதல் எப்படி இயக்குவது?", "அச்சுறுத்தல்களை எங்கு பார்ப்பது?" போன்ற கேள்விகளை கேட்கலாம். அல்லது "உதவி" என்று சொல்லுங்கள்.`
      : `I didn't understand "${rawQuery}". Try asking: "What is NIDS?", "How do I run a simulation?", "Show threats", or say "help" for available commands.`,
    actionExecuted: 'UNRECOGNIZED',
    success: false,
  };
};
