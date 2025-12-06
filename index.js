import WebSocket from 'ws';
import tls from 'tls';
import net from 'net';
import axios from 'axios';
import fs from 'fs';
import { HttpsProxyAgent } from 'https-proxy-agent';

const USER_TOKEN = process.env.USER_TOKEN || '';
const TARGET_GUILD_ID = process.env.TARGET_GUILD_ID || '';
const USER_PASSWORD = process.env.USER_PASSWORD || '';
const WEBHOOK = process.env.WEBHOOK || '';

const PROXY_ENABLED = process.env.PROXY_ENABLED === 'true';
const PROXY_URL = (process.env.PROXY_URL || '').trim();
const WEBSHARE_API_KEY = (process.env.WEBSHARE_API_KEY || '').trim();

let mfaAuthToken = null;
let latestSequence = null;
let heartbeatTimer = null;
let tlsSocket = null;
const vanityMap = new Map();

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const X_SUPER_PROPERTIES = 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzMS4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTMxLjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiJodHRwczovL3d3dy5nb29nbGUuY29tLyIsInJlZmVycmluZ19kb21haW4iOiJ3d3cuZ29vZ2xlLmNvbSIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNTgyOTUsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGwsImRlc2lnbl9pZCI6MH0=';

async function fetchWebshareProxies() {
  if (!WEBSHARE_API_KEY) {
    console.log('No Webshare API key configured');
    return null;
  }
  
  const cleanApiKey = WEBSHARE_API_KEY.replace(/\s+/g, '').replace(/[\r\n]/g, '');
  
  try {
    const response = await axios.get('https://proxy.webshare.io/api/v2/proxy/list/', {
      params: {
        mode: 'backbone',
        page: 1,
        page_size: 25
      },
      headers: {
        'Authorization': `Token ${cleanApiKey}`
      }
    });
    
    if (response.data.results && response.data.results.length > 0) {
      const proxy = response.data.results[0];
      const proxyUrl = `http://${proxy.username}:${proxy.password}@${proxy.proxy_address}:${proxy.port}`;
      console.log(`Loaded proxy: ${proxy.proxy_address}:${proxy.port}`);
      return proxyUrl;
    } else {
      console.log('No proxies found in Webshare account');
    }
  } catch (err) {
    const errorDetail = err.response?.data?.detail || err.response?.data || err.message;
    console.error('Failed to fetch Webshare proxies:', JSON.stringify(errorDetail));
  }
  return null;
}

async function getProxyUrl() {
  if (!PROXY_ENABLED) return null;
  if (PROXY_URL) return PROXY_URL;
  return await fetchWebshareProxies();
}

function parseProxyUrl(proxyUrl) {
  const url = new URL(proxyUrl);
  return {
    host: url.hostname,
    port: parseInt(url.port) || 80,
    auth: url.username && url.password ? `${url.username}:${url.password}` : null
  };
}

function createTlsSocketThroughProxy(proxyUrl) {
  return new Promise((resolve, reject) => {
    const proxy = parseProxyUrl(proxyUrl);
    const targetHost = 'canary.discord.com';
    const targetPort = 443;
    
    const socket = net.connect(proxy.port, proxy.host, () => {
      let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
      connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;
      
      if (proxy.auth) {
        const authBase64 = Buffer.from(proxy.auth).toString('base64');
        connectRequest += `Proxy-Authorization: Basic ${authBase64}\r\n`;
      }
      
      connectRequest += '\r\n';
      socket.write(connectRequest);
    });
    
    socket.once('data', (data) => {
      const response = data.toString();
      if (response.includes('200')) {
        const tlsSock = tls.connect({
          socket: socket,
          host: targetHost,
          rejectUnauthorized: true,
          minVersion: 'TLSv1.2',
          maxVersion: 'TLSv1.3'
        }, () => {
          resolve(tlsSock);
        });
        
        tlsSock.on('error', reject);
      } else {
        reject(new Error(`Proxy CONNECT failed: ${response.split('\r\n')[0]}`));
      }
    });
    
    socket.on('error', reject);
  });
}

function createDirectTlsSocket() {
  return tls.connect({
    host: 'canary.discord.com',
    port: 443,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3'
  });
}

const loadMfaToken = () => {
  fs.readFile("mfa.txt", "utf8", (err, data) => {
    if (!err && data.trim()) {
      mfaAuthToken = data.trim();
      console.log('MFA token loaded');
    }
  });
};

loadMfaToken();

fs.watch("mfa.txt", (eventType) => {
  if (eventType === "change") {
    loadMfaToken();
  }
});

function sendWebhook(vanityUrl) {
  axios.post(WEBHOOK, {
    content: `Target URL claimed: **${vanityUrl}** @everyone @here`
  }).catch(() => {});
}

async function createTlsSocket() {
  const proxyUrl = await getProxyUrl();
  if (proxyUrl) {
    console.log('Using proxy for TLS connection');
    return await createTlsSocketThroughProxy(proxyUrl);
  }
  console.log('Using direct TLS connection');
  return createDirectTlsSocket();
}

async function sendHttpRequest(method, path, body = null, extraHeaders = {}, closeConnection = false) {
  return new Promise(async (resolve) => {
    const payload = body ? JSON.stringify(body) : '';
    
    if (!tlsSocket || tlsSocket.destroyed || closeConnection) {
      try {
        tlsSocket = await createTlsSocket();
        tlsSocket.setNoDelay(true);
      } catch (err) {
        console.error('Failed to create TLS socket:', err.message);
        return resolve('{}');
      }
    }
    
    const socket = tlsSocket;
    
    const headers = [
      `${method} ${path} HTTP/1.1`,
      'Host: canary.discord.com',
      `Connection: ${closeConnection ? 'close' : 'keep-alive'}`,
      'Content-Type: application/json',
      `Content-Length: ${Buffer.byteLength(payload)}`,
      `User-Agent: ${USER_AGENT}`,
      `Authorization: ${USER_TOKEN}`,
      `X-Super-Properties: ${X_SUPER_PROPERTIES}`,
      'X-Discord-Locale: en-US',
      'X-Discord-Timezone: America/New_York',
      'Accept: */*',
      'Accept-Language: en-US,en;q=0.9',
      'Referer: https://canary.discord.com/channels/@me',
      'Origin: https://canary.discord.com'
    ];
    
    if (extraHeaders['X-Discord-MFA-Authorization']) {
      headers.push(`X-Discord-MFA-Authorization: ${extraHeaders['X-Discord-MFA-Authorization']}`);
    }
    
    headers.push('', payload);
    
    let responseData = '';
    socket.write(headers.join('\r\n'));
    
    socket.once('error', () => resolve('{}'));
    
    socket.on('data', (chunk) => {
      responseData += chunk.toString();
    });
    
    socket.once('end', () => {
      try {
        const separatorIndex = responseData.indexOf('\r\n\r\n');
        if (separatorIndex === -1) return resolve('{}');
        
        let bodyData = responseData.slice(separatorIndex + 4);
        
        if (responseData.toLowerCase().includes('transfer-encoding: chunked')) {
          let decoded = '';
          let pos = 0;
          while (pos < bodyData.length) {
            const sizeEnd = bodyData.indexOf('\r\n', pos);
            if (sizeEnd === -1) break;
            const size = parseInt(bodyData.substring(pos, sizeEnd), 16);
            if (size === 0) break;
            decoded += bodyData.substr(sizeEnd + 2, size);
            pos = sizeEnd + 2 + size + 2;
          }
          resolve(decoded || '{}');
        } else {
          resolve(bodyData || '{}');
        }
      } catch {
        resolve('{}');
      } finally {
        if (closeConnection) socket.destroy();
      }
    });
  });
}

async function authenticateMfa() {
  try {
    const patchResp = await sendHttpRequest('PATCH', `/api/v7/guilds/${TARGET_GUILD_ID}/vanity-url`, null, {}, true);
    const patchData = JSON.parse(patchResp);
    
    if (patchData.code === 60003) {
      const finishResp = await sendHttpRequest('POST', '/api/v9/mfa/finish', {
        ticket: patchData.mfa.ticket,
        mfa_type: 'password',
        data: USER_PASSWORD
      }, {}, true);
      
      const finishData = JSON.parse(finishResp);
      if (finishData.token) {
        return finishData.token;
      }
    }
  } catch {}
  return null;
}

async function establishGatewayConnection() {
  const proxyUrl = await getProxyUrl();
  
  let wsOptions = {};
  if (proxyUrl) {
    console.log('Using proxy for WebSocket connection');
    wsOptions.agent = new HttpsProxyAgent(proxyUrl);
  }
  
  const ws = new WebSocket('wss://gateway-us-east1-b.discord.gg', wsOptions);
  
  ws.on('open', () => {
    ws.send(JSON.stringify({
      op: 2,
      d: {
        token: USER_TOKEN,
        intents: 513,
        properties: {
          os: 'Windows',
          browser: 'Chrome',
          device: '',
          system_locale: 'en-US',
          browser_user_agent: USER_AGENT,
          browser_version: '131.0.0.0',
          os_version: '10',
          referrer: 'https://www.google.com/',
          referring_domain: 'www.google.com',
          referrer_current: '',
          referring_domain_current: '',
          release_channel: 'stable',
          client_build_number: 358295,
          client_event_source: null
        }
      }
    }));
  });
  
  ws.on('message', async (msg) => {
    const packet = JSON.parse(msg);
    
    if (packet.s) latestSequence = packet.s;
    
    if (packet.op === 10) {
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(() => {
        ws.send(JSON.stringify({ op: 1, d: latestSequence }));
      }, packet.d.heartbeat_interval);
    } else if (packet.op === 0) {
      if (packet.t === 'GUILD_UPDATE') {
        const oldCode = vanityMap.get(packet.d.guild_id);
        if (oldCode && oldCode !== packet.d.vanity_url_code) {
          console.log(`Vanity changed: ${oldCode}`);
          
          let success = false;
          for (let i = 0; i < 3; i++) {
            const snipeResp = await sendHttpRequest('PATCH', `/api/v7/guilds/${TARGET_GUILD_ID}/vanity-url`, {
              code: oldCode
            }, { 'X-Discord-MFA-Authorization': mfaAuthToken });
            
            try {
              const snipeData = JSON.parse(snipeResp);
              if (snipeData.code === oldCode || snipeData.vanity_url_code === oldCode || (!snipeData.code && !snipeData.message)) {
                console.log(`URL claimed: ${oldCode}`);
                sendWebhook(oldCode);
                success = true;
                break;
              }
            } catch {}
          }
          
          if (!success) {
            console.log(`Failed to claim URL: ${oldCode}`);
          }
        }
      } else if (packet.t === 'READY') {
        console.log('[CONNECTION] Gateway connection successful');
        packet.d.guilds.forEach(g => {
          if (g.vanity_url_code) {
            vanityMap.set(g.id, g.vanity_url_code);
          }
        });
        console.log(`Monitoring ${vanityMap.size} vanity URLs`);
      }
    }
  });
  
  ws.on('close', () => {
    console.log('[ERROR] Connection lost, reconnecting...');
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    setTimeout(establishGatewayConnection, 5000);
  });
  
  ws.on('error', (err) => {
    console.error('WebSocket error:', err.message);
    ws.close();
  });
}

async function main() {
  console.log('Starting program...');
  console.log('Proxy support: ' + (PROXY_ENABLED ? 'Enabled' : 'Disabled'));
  
  if (!mfaAuthToken) {
    console.log('Fetching token...');
    mfaAuthToken = await authenticateMfa();
    if (mfaAuthToken) {
      console.log('Token successfully retrieved');
    }
  }
  
  setInterval(async () => {
    const refreshedToken = await authenticateMfa();
    if (refreshedToken) mfaAuthToken = refreshedToken;
  }, 4 * 60 * 1000);
  
  establishGatewayConnection();
}

main();
