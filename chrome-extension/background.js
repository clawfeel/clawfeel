const RELAY_URL = 'https://api.clawfeel.ai';
const ALARM_NAME = 'clawfeel-report';

// ── Entropy collection (service worker compatible) ──

function getTimingJitter() {
  const samples = [];
  for (let i = 0; i < 100; i++) {
    const t0 = performance.now();
    let x = 0;
    for (let j = 0; j < 1000; j++) x += j;
    samples.push(performance.now() - t0);
  }
  const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
  const variance = samples.reduce((a, b) => a + (b - mean) ** 2, 0) / samples.length;
  return Math.sqrt(variance);
}

function getCryptoEntropy() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function computeFeel(clawId, seq) {
  const timing = getTimingJitter();
  const cryptoHex = getCryptoEntropy();

  const parts = [
    `timing:${timing.toFixed(12)}`,
    `crypto:${cryptoHex}`,
    `ts:${Date.now()}`,
    `perf:${performance.now()}`,
    `seq:${seq}`,
    `id:${clawId}`,
  ];

  const encoded = new TextEncoder().encode(parts.join('|'));
  const hashBuf = await crypto.subtle.digest('SHA-256', encoded);
  const hashArr = new Uint8Array(hashBuf);
  const hash = Array.from(hashArr).map(b => b.toString(16).padStart(2, '0')).join('');

  const feel = parseInt(hash.substring(0, 8), 16) % 101;
  const era = feel <= 30 ? 'Chaos' : feel <= 70 ? 'Transition' : 'Eternal';

  return {
    feel, era, hash, entropy: hash,
    seq, timestamp: new Date().toISOString(),
    clawId, alias: 'Ext-' + clawId.substring(0, 8),
    type: 'extension', sensorCount: 2,
    authenticity: 2, entropyQuality: 45,
    sensorFlags: '11',
  };
}

// ── Report to relay ──

async function reportEntropy() {
  const data = await chrome.storage.local.get(['clawId', 'contributing', 'seq', 'contributions']);
  if (!data.contributing || !data.clawId) return;

  const seq = (data.seq || 0) + 1;
  try {
    const result = await computeFeel(data.clawId, seq);
    const res = await fetch(RELAY_URL + '/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Claw-Id': data.clawId },
      body: JSON.stringify(result),
    });
    const json = await res.json();
    await chrome.storage.local.set({
      seq,
      contributions: (data.contributions || 0) + 1,
      lastFeel: result.feel,
      lastEra: result.era,
      lastHash: result.hash,
    });
  } catch { /* relay offline, skip */ }
}

// ── Alarm-based scheduling ──

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_NAME) reportEntropy();
});

// ── Message handling from popup ──

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === 'start') {
    chrome.alarms.create(ALARM_NAME, { periodInMinutes: 0.5 });
    reportEntropy(); // immediate first report
  } else if (msg.action === 'stop') {
    chrome.alarms.clear(ALARM_NAME);
  }
});

// ── On install: set defaults, start if previously contributing ──

chrome.runtime.onInstalled.addListener(async () => {
  const data = await chrome.storage.local.get(['clawId', 'contributing']);
  if (!data.clawId) {
    const arr = new Uint8Array(6);
    crypto.getRandomValues(arr);
    const clawId = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    await chrome.storage.local.set({ clawId, contributing: false, seq: 0, contributions: 0 });
  }
});

// ── On startup: resume alarm if contributing ──

chrome.runtime.onStartup.addListener(async () => {
  const data = await chrome.storage.local.get('contributing');
  if (data.contributing) {
    chrome.alarms.create(ALARM_NAME, { periodInMinutes: 0.5 });
  }
});
