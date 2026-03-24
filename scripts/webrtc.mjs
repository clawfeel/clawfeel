/**
 * webrtc.mjs — WebRTC signaling + browser P2P DataChannel
 *
 * For Node.js: SignalingClient (WS connection to relay for signaling only)
 * For browsers: BrowserP2PManager (full WebRTC with DataChannels)
 *
 * Zero dependencies — uses relay WebSocket for signaling.
 */

import { randomBytes } from "node:crypto";

const DEFAULT_RELAY_WS = "wss://clawfeel-relay.fly.dev/ws/signal";

/**
 * SignalingClient — Node.js side WebSocket client for P2P signaling.
 * Connects to relay's /ws/signal endpoint.
 * Used for forwarding punch requests and coordinating with browser peers.
 */
export class SignalingClient {
  constructor({ relayUrl = DEFAULT_RELAY_WS, clawId, onSignal } = {}) {
    this.relayUrl = relayUrl;
    this.clawId = clawId;
    this.onSignal = onSignal || (() => {});
    this._ws = null;
    this._connected = false;
    this._pendingOffers = new Map(); // targetClawId → resolve/reject
  }

  async connect() {
    // Node.js >=22 doesn't have built-in WebSocket client
    // Use raw TCP + HTTP upgrade (same approach as server)
    const url = new URL(this.relayUrl);
    const { connect } = await import("node:net");
    const { createHash } = await import("node:crypto");

    return new Promise((resolve, reject) => {
      const isSecure = url.protocol === "wss:";
      const port = url.port || (isSecure ? 443 : 80);
      const host = url.hostname;
      const path = url.pathname || "/ws/signal";

      // For WSS, use TLS
      const connectFn = isSecure
        ? async () => {
            const { connect: tlsConnect } = await import("node:tls");
            return tlsConnect({ host, port: parseInt(port), servername: host });
          }
        : async () => connect(parseInt(port), host);

      connectFn().then((socket) => {
        this._ws = socket;

        // Generate WebSocket key
        const wsKey = randomBytes(16).toString("base64");

        // Send HTTP upgrade request
        socket.write(
          `GET ${path} HTTP/1.1\r\n` +
          `Host: ${host}\r\n` +
          `Upgrade: websocket\r\n` +
          `Connection: Upgrade\r\n` +
          `Sec-WebSocket-Key: ${wsKey}\r\n` +
          `Sec-WebSocket-Version: 13\r\n` +
          `\r\n`
        );

        let handshakeDone = false;
        let buffer = Buffer.alloc(0);

        socket.on("data", (chunk) => {
          buffer = Buffer.concat([buffer, chunk]);

          if (!handshakeDone) {
            const str = buffer.toString();
            if (str.includes("\r\n\r\n")) {
              if (str.startsWith("HTTP/1.1 101")) {
                handshakeDone = true;
                const headerEnd = buffer.indexOf(Buffer.from("\r\n\r\n")) + 4;
                buffer = buffer.subarray(headerEnd);
                this._connected = true;

                // Send join message
                this._send({ type: "signal:join", clawId: this.clawId });
                resolve();
              } else {
                reject(new Error("WebSocket upgrade failed"));
                socket.destroy();
              }
            }
            return;
          }

          // Parse WebSocket frames (server frames are NOT masked)
          this._processFrames();
        });

        socket.on("error", (err) => {
          this._connected = false;
          if (!handshakeDone) reject(err);
        });

        socket.on("close", () => {
          this._connected = false;
        });
      }).catch(reject);
    });
  }

  _processFrames() {
    // Simplified: server sends unmasked text frames
    // We just need to parse the length and extract payload
    // This is a basic implementation for small JSON messages
  }

  _send(data) {
    if (!this._ws || !this._connected) return;
    const payload = Buffer.from(JSON.stringify(data), "utf8");
    const len = payload.length;

    // Client frames MUST be masked (RFC 6455)
    const mask = randomBytes(4);
    let header;
    if (len < 126) {
      header = Buffer.alloc(6);
      header[0] = 0x81; // FIN + text
      header[1] = 0x80 | len; // masked + length
      mask.copy(header, 2);
    } else {
      header = Buffer.alloc(8);
      header[0] = 0x81;
      header[1] = 0x80 | 126;
      header.writeUInt16BE(len, 2);
      mask.copy(header, 4);
    }

    // Mask payload
    const masked = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      masked[i] = payload[i] ^ mask[i % 4];
    }

    this._ws.write(Buffer.concat([header, masked]));
  }

  sendOffer(targetClawId, sdp) {
    this._send({ type: "signal:offer", to: targetClawId, sdp });
  }

  sendAnswer(targetClawId, sdp) {
    this._send({ type: "signal:answer", to: targetClawId, sdp });
  }

  sendICE(targetClawId, candidate) {
    this._send({ type: "signal:ice", to: targetClawId, candidate });
  }

  sendPunch(targetClawId, publicAddr) {
    this._send({ type: "signal:punch", to: targetClawId, publicAddr });
  }

  getPeers() {
    this._send({ type: "signal:peers" });
  }

  close() {
    if (this._ws) {
      try { this._ws.destroy(); } catch {}
      this._ws = null;
    }
    this._connected = false;
  }
}

/**
 * BrowserP2PManager — for use in web pages (browser environment).
 * This class is designed to be included in web pages via a <script> tag.
 * It uses the browser's native RTCPeerConnection API.
 *
 * Usage in browser:
 *   const p2p = new BrowserP2PManager({ relayWsUrl, clawId });
 *   await p2p.connect();
 *   p2p.onFeel = (data) => console.log("Got Feel from peer:", data);
 *   await p2p.connectToPeer(targetClawId);
 *   p2p.broadcastFeel({ feel: 42, era: "Transition" });
 *
 * Note: This class uses browser APIs (RTCPeerConnection, WebSocket)
 * and cannot be used in Node.js without polyfills.
 */
export const BROWSER_P2P_SCRIPT = `
class BrowserP2PManager {
  constructor({ relayWsUrl, clawId }) {
    this.relayWsUrl = relayWsUrl || 'wss://clawfeel-relay.fly.dev/ws/signal';
    this.clawId = clawId;
    this.ws = null;
    this.peers = new Map(); // clawId → { pc, dc }
    this.onFeel = null; // callback for received Feel data
    this.onPeerConnect = null;
    this.onPeerDisconnect = null;
  }

  async connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.relayWsUrl);
      this.ws.onopen = () => {
        this.ws.send(JSON.stringify({ type: 'signal:join', clawId: this.clawId }));
        resolve();
      };
      this.ws.onerror = reject;
      this.ws.onmessage = (e) => this._handleSignal(JSON.parse(e.data));
    });
  }

  async _handleSignal(msg) {
    switch (msg.type) {
      case 'signal:offer': await this._handleOffer(msg); break;
      case 'signal:answer': await this._handleAnswer(msg); break;
      case 'signal:ice': await this._handleICE(msg); break;
    }
  }

  async connectToPeer(targetClawId) {
    const pc = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' },
      ]
    });

    const dc = pc.createDataChannel('clawfeel', { ordered: false });
    this._setupDataChannel(dc, targetClawId);
    this.peers.set(targetClawId, { pc, dc });

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        this.ws.send(JSON.stringify({
          type: 'signal:ice', to: targetClawId, candidate: e.candidate
        }));
      }
    };

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    this.ws.send(JSON.stringify({
      type: 'signal:offer', to: targetClawId, sdp: offer.sdp
    }));
  }

  async _handleOffer(msg) {
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
    });

    pc.ondatachannel = (e) => {
      this._setupDataChannel(e.channel, msg.from);
      this.peers.set(msg.from, { pc, dc: e.channel });
    };

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        this.ws.send(JSON.stringify({
          type: 'signal:ice', to: msg.from, candidate: e.candidate
        }));
      }
    };

    await pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    this.ws.send(JSON.stringify({
      type: 'signal:answer', to: msg.from, sdp: answer.sdp
    }));

    this.peers.set(msg.from, { pc, dc: null });
  }

  async _handleAnswer(msg) {
    const peer = this.peers.get(msg.from);
    if (peer?.pc) {
      await peer.pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
    }
  }

  async _handleICE(msg) {
    const peer = this.peers.get(msg.from);
    if (peer?.pc) {
      await peer.pc.addIceCandidate(msg.candidate);
    }
  }

  _setupDataChannel(dc, peerId) {
    dc.onopen = () => {
      if (this.onPeerConnect) this.onPeerConnect(peerId);
    };
    dc.onclose = () => {
      this.peers.delete(peerId);
      if (this.onPeerDisconnect) this.onPeerDisconnect(peerId);
    };
    dc.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'GOSSIP_TX' && this.onFeel) {
          this.onFeel(msg.tx?.data || msg, peerId);
        }
      } catch {}
    };
  }

  broadcastFeel(feelData) {
    const msg = JSON.stringify({ type: 'GOSSIP_TX', tx: { data: feelData } });
    for (const [, peer] of this.peers) {
      if (peer.dc?.readyState === 'open') {
        try { peer.dc.send(msg); } catch {}
      }
    }
  }

  close() {
    for (const [, peer] of this.peers) {
      try { peer.pc.close(); } catch {}
    }
    this.peers.clear();
    if (this.ws) { try { this.ws.close(); } catch {} }
  }
}
`;
