/**
 * ClawFeel Browser Entropy — Light Node for Browsers
 *
 * Collects 5 browser-available entropy sources and computes a Feel score.
 * Browsers can't access hardware sensors directly, but can measure:
 *   1. Timing jitter (performance.now variance)
 *   2. Crypto entropy (OS entropy pool via Web Crypto API)
 *   3. Network jitter (fetch timing variance)
 *   4. Memory pressure (navigator.deviceMemory)
 *   5. Hardware concurrency (CPU core count)
 *
 * Usage:
 *   const entropy = new BrowserEntropy('https://api.clawfeel.ai');
 *   const result = await entropy.computeFeel();
 *   await entropy.reportToRelay();
 */

class BrowserEntropy {
  constructor(relayUrl = 'https://api.clawfeel.ai') {
    this.relayUrl = relayUrl.replace(/\/+$/, '');
    this.clawId = this._getOrCreateId();
    this.seq = 0;
  }

  // ── Generate persistent browser clawId ──

  _getOrCreateId() {
    let id = localStorage.getItem('clawfeel_browser_id');
    if (!id) {
      const arr = new Uint8Array(6);
      crypto.getRandomValues(arr);
      id = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
      localStorage.setItem('clawfeel_browser_id', id);
    }
    return id;
  }

  // ── Sensor 1: Timing Jitter ──

  getTimingJitter() {
    const samples = [];
    for (let i = 0; i < 100; i++) {
      const t0 = performance.now();
      // Tight loop to measure scheduler jitter
      let x = 0;
      for (let j = 0; j < 1000; j++) x += j;
      samples.push(performance.now() - t0);
    }
    const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
    const variance = samples.reduce((a, b) => a + (b - mean) ** 2, 0) / samples.length;
    return { value: Math.sqrt(variance), authentic: true };
  }

  // ── Sensor 2: Crypto Entropy ──

  getCryptoEntropy() {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    const hex = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    // Use first 4 bytes as numeric value
    const value = new DataView(arr.buffer).getUint32(0) / 0xFFFFFFFF * 4096;
    return { value, hex, authentic: true };
  }

  // ── Sensor 3: Network Jitter ──

  async getNetworkJitter() {
    const times = [];
    for (let i = 0; i < 3; i++) {
      try {
        const t0 = performance.now();
        await fetch(this.relayUrl + '/', { mode: 'cors', cache: 'no-store' });
        times.push(performance.now() - t0);
      } catch {
        times.push(Math.random() * 100); // fallback
      }
    }
    const mean = times.reduce((a, b) => a + b, 0) / times.length;
    const variance = times.reduce((a, b) => a + (b - mean) ** 2, 0) / times.length;
    return { value: Math.sqrt(variance), authentic: times.length >= 2 };
  }

  // ── Sensor 4: Memory Pressure ──

  getMemoryPressure() {
    // navigator.deviceMemory: approximate RAM in GB (Chrome only)
    const mem = navigator.deviceMemory || 4; // default 4GB
    return { value: mem, authentic: !!navigator.deviceMemory };
  }

  // ── Sensor 5: Hardware Concurrency ──

  getHardwareConcurrency() {
    const cores = navigator.hardwareConcurrency || 4;
    return { value: cores, authentic: !!navigator.hardwareConcurrency };
  }

  // ── Collect All Sensors ──

  async collectSensors() {
    const timing = this.getTimingJitter();
    const cryptoEnt = this.getCryptoEntropy();
    const network = await this.getNetworkJitter();
    const memory = this.getMemoryPressure();
    const concurrency = this.getHardwareConcurrency();

    return {
      timingJitter: timing,
      cryptoEntropy: cryptoEnt,
      networkJitter: network,
      memoryPressure: memory,
      hardwareConcurrency: concurrency,
    };
  }

  // ── Compute Feel (SHA-256) ──

  async computeFeel() {
    const sensors = await this.collectSensors();
    this.seq++;

    // Build entropy string (same principle as Node.js version)
    const parts = [
      `timing:${sensors.timingJitter.value.toFixed(12)}`,
      `crypto:${sensors.cryptoEntropy.hex}`,
      `network:${sensors.networkJitter.value.toFixed(12)}`,
      `memory:${sensors.memoryPressure.value}`,
      `cores:${sensors.hardwareConcurrency.value}`,
      `ts:${Date.now()}`,
      `perf:${performance.now()}`,
      `seq:${this.seq}`,
      `id:${this.clawId}`,
    ];

    const entropyStr = parts.join('|');

    // SHA-256 hash
    const encoded = new TextEncoder().encode(entropyStr);
    const hashBuf = await crypto.subtle.digest('SHA-256', encoded);
    const hashArr = new Uint8Array(hashBuf);
    const hash = Array.from(hashArr).map(b => b.toString(16).padStart(2, '0')).join('');

    // Feel score: first 8 hex chars → integer → mod 101
    const feel = parseInt(hash.substring(0, 8), 16) % 101;
    const era = feel <= 30 ? 'Chaos' : feel <= 70 ? 'Transition' : 'Eternal';

    // Authenticity: count real sensors
    let authentic = 0;
    for (const [, s] of Object.entries(sensors)) {
      if (s.authentic) authentic++;
    }

    // Entropy quality (simplified for browser)
    const quality = Math.round((authentic / 5) * 60 + 20); // 20-80 range

    return {
      feel,
      era,
      hash: hash.substring(0, 16),
      entropy: hash,
      seq: this.seq,
      timestamp: new Date().toISOString(),
      clawId: this.clawId,
      alias: 'Browser-' + this.clawId.substring(0, 8),
      type: 'browser',
      authenticity: authentic,
      sensorCount: 5,
      entropyQuality: quality,
      sensorFlags: Object.values(sensors).map(s => s.authentic ? '1' : '0').join(''),
    };
  }

  // ── Report to Relay ──

  async reportToRelay() {
    const result = await this.computeFeel();
    try {
      const res = await fetch(this.relayUrl + '/api/report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Claw-Id': this.clawId,
        },
        body: JSON.stringify(result),
      });
      const data = await res.json();
      return { ...result, reported: data.ok || false };
    } catch (err) {
      return { ...result, reported: false, error: err.message };
    }
  }

  // ── Start continuous reporting ──

  startDaemon(intervalMs = 30_000) {
    this._daemonInterval = setInterval(() => {
      this.reportToRelay().catch(() => {});
    }, intervalMs);
    // Report immediately on start
    this.reportToRelay().catch(() => {});
    return () => this.stopDaemon();
  }

  stopDaemon() {
    if (this._daemonInterval) {
      clearInterval(this._daemonInterval);
      this._daemonInterval = null;
    }
  }
}

// Export for module usage, also attach to window for script tag usage
if (typeof window !== 'undefined') {
  window.BrowserEntropy = BrowserEntropy;
}
