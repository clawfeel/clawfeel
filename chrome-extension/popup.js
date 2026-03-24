const RELAY_URL = 'https://api.clawfeel.ai';

// ── Entropy Collection (same approach as browser-entropy.js) ──

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
  const cores = navigator.hardwareConcurrency || 4;
  const mem = navigator.deviceMemory || 4;

  const parts = [
    `timing:${timing.toFixed(12)}`,
    `crypto:${cryptoHex}`,
    `memory:${mem}`,
    `cores:${cores}`,
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
    type: 'extension', sensorCount: 4,
    authenticity: (navigator.deviceMemory ? 4 : 3),
    entropyQuality: navigator.deviceMemory ? 65 : 55,
    sensorFlags: `11${navigator.deviceMemory ? '1' : '0'}1`,
  };
}

// ── UI Logic ──

const $ = (id) => document.getElementById(id);

let pollInterval = null;

async function init() {
  const data = await chrome.storage.local.get(['clawId', 'contributing', 'contributions', 'startedAt', 'seq']);

  let clawId = data.clawId;
  if (!clawId) {
    const arr = new Uint8Array(6);
    crypto.getRandomValues(arr);
    clawId = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    await chrome.storage.local.set({ clawId });
  }

  $('clawId').textContent = 'Claw-' + clawId.substring(0, 8);
  $('dashboardLink').href = `https://clawfeel.ai/simulator.html?me=${clawId}`;

  const contributing = data.contributing ?? false;
  $('toggleContrib').checked = contributing;
  updateStatusDot(contributing);
  $('contributions').textContent = data.contributions || 0;
  updateUptime(data.startedAt);

  if (contributing) {
    await refreshFeel(clawId, data.seq || 0);
  }

  fetchPeers();

  // Poll UI updates every 5s while popup is open
  pollInterval = setInterval(async () => {
    const d = await chrome.storage.local.get(['contributing', 'contributions', 'startedAt', 'lastFeel', 'lastEra', 'lastHash']);
    $('contributions').textContent = d.contributions || 0;
    updateUptime(d.startedAt);
    if (d.lastFeel != null) {
      $('feelValue').textContent = d.lastFeel;
      $('feelEra').textContent = d.lastEra || '';
      $('feelHash').textContent = d.lastHash ? d.lastHash.substring(0, 32) + '...' : '--';
    }
  }, 5000);

  $('toggleContrib').addEventListener('change', async (e) => {
    const on = e.target.checked;
    updateStatusDot(on);
    if (on) {
      await chrome.storage.local.set({ contributing: true, startedAt: Date.now() });
      chrome.runtime.sendMessage({ action: 'start' });
      await refreshFeel(clawId, (await chrome.storage.local.get('seq')).seq || 0);
    } else {
      await chrome.storage.local.set({ contributing: false, startedAt: null });
      chrome.runtime.sendMessage({ action: 'stop' });
    }
  });
}

function updateStatusDot(online) {
  const dot = $('statusDot');
  dot.className = 'status-dot ' + (online ? 'online' : 'offline');
}

function updateUptime(startedAt) {
  if (!startedAt) { $('uptime').textContent = '--'; return; }
  const sec = Math.floor((Date.now() - startedAt) / 1000);
  if (sec < 60) $('uptime').textContent = sec + 's';
  else if (sec < 3600) $('uptime').textContent = Math.floor(sec / 60) + 'm';
  else $('uptime').textContent = Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm';
}

async function refreshFeel(clawId, seq) {
  try {
    const result = await computeFeel(clawId, seq + 1);
    $('feelValue').textContent = result.feel;
    $('feelEra').textContent = result.era;
    $('feelHash').textContent = result.hash.substring(0, 32) + '...';
    await chrome.storage.local.set({
      lastFeel: result.feel, lastEra: result.era, lastHash: result.hash,
    });
  } catch { /* silent */ }
}

async function fetchPeers() {
  try {
    const res = await fetch(RELAY_URL + '/api/nodes', { cache: 'no-store' });
    const data = await res.json();
    $('peers').textContent = Array.isArray(data) ? data.length : (data.count || '--');
  } catch {
    $('peers').textContent = '--';
  }
}

document.addEventListener('DOMContentLoaded', init);
window.addEventListener('unload', () => { if (pollInterval) clearInterval(pollInterval); });
