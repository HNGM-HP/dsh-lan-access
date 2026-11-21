import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

export const name = 'lan-access';
export const inject = ['webServer'];

const ADMIN_PREFIX = '/lan-access';
const DEVICE_COOKIE = 'dsh-lan-device';
const CANDIDATE_COOKIE = 'dsh-lan-candidate';
const DEVICE_MAX_AGE = 10 * 365 * 24 * 60 * 60;
const CANDIDATE_MAX_AGE = 24 * 60 * 60;

function b64url(value) {
    return Buffer.from(value).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function decodeB64Url(value) {
    if (!/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) return undefined;
    const padding = '='.repeat((4 - value.length % 4) % 4);
    return Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/') + padding, 'base64');
}

function cookieMap(header) {
    const map = new Map();
    if (!header) return map;
    for (const segment of String(header).split(';')) {
        const at = segment.indexOf('=');
        if (at < 0) continue;
        map.set(segment.slice(0, at).trim(), segment.slice(at + 1).trim());
    }
    return map;
}

function cookieHeader(name, value, maxAge) {
    return `${name}=${value}; Max-Age=${String(maxAge)}; Path=/; HttpOnly; SameSite=Lax`;
}

function sendJson(res, status, value) {
    const body = JSON.stringify(value);
    res.writeHead(status, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'content-length': Buffer.byteLength(body)
    });
    res.end(body);
}

function readBody(req, limit = 64 * 1024) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', (chunk) => {
            size += chunk.length;
            if (size > limit) {
                reject(new Error('request body too large'));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        req.on('error', reject);
    });
}

function hashFingerprint(value) {
    return b64url(crypto.createHash('sha256').update(String(value ?? '')).digest());
}

function timingEqual(a, b) {
    const left = Buffer.from(a, 'utf8');
    const right = Buffer.from(b, 'utf8');
    return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function randomId() {
    return b64url(crypto.randomBytes(18));
}

function safeLabel(value, fallback) {
    const text = String(value ?? '').replace(/\s+/gu, ' ').trim();
    return (text === '' ? fallback : text).slice(0, 80);
}

function describeUserAgent(value) {
    const ua = String(value ?? '');
    const browser = /Edg\//u.test(ua) ? 'Edge' : /Chrome\//u.test(ua) ? 'Chrome' : /Firefox\//u.test(ua) ? 'Firefox' : /Safari\//u.test(ua) ? 'Safari' : '浏览器';
    const system = /Android/u.test(ua) ? 'Android' : /iPhone|iPad|iPod/u.test(ua) ? 'iOS' : /Windows/u.test(ua) ? 'Windows' : /Mac OS X/u.test(ua) ? 'macOS' : /Linux/u.test(ua) ? 'Linux' : '';
    return system === '' ? browser : `${browser} · ${system}`;
}

export function apply(ctx, config = {}) {
    const bind = typeof config.bind === 'string' && config.bind !== '' ? config.bind : '0.0.0.0';
    const port = Number(config.port ?? 8097);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('lan-access: invalid port');
    const tlsConfig = config.tls;
    const dshHome = process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh');
    const registryDir = path.join(dshHome, 'lan-access');
    const registryFile = path.join(registryDir, 'devices.json');

    const origin = new URL(ctx.webServer.getOrigin());
    const upstreamPort = origin.port === '' ? (origin.protocol === 'https:' ? 443 : 80) : Number(origin.port);

    let registry = loadRegistry();
    let saveChain = Promise.resolve();

    function defaultRegistry() {
        return { version: 1, secret: b64url(crypto.randomBytes(32)), devices: {}, pending: {} };
    }

    function loadRegistry() {
        try {
            const parsed = JSON.parse(fs.readFileSync(registryFile, 'utf8'));
            if (parsed === null || typeof parsed !== 'object' || typeof parsed.secret !== 'string' || parsed.devices === null || typeof parsed.devices !== 'object' || parsed.pending === null || typeof parsed.pending !== 'object') {
                throw new Error('lan-access: invalid device registry');
            }
            return {
                version: 1,
                secret: parsed.secret,
                devices: parsed.devices,
                pending: parsed.pending
            };
        } catch (error) {
            if (error?.code !== 'ENOENT') throw error;
            const created = defaultRegistry();
            fs.mkdirSync(registryDir, { recursive: true, mode: 0o700 });
            fs.writeFileSync(registryFile, `${JSON.stringify(created, null, 2)}\n`, { mode: 0o600 });
            return created;
        }
    }

    function saveRegistry() {
        saveChain = saveChain.then(async () => {
            fs.mkdirSync(registryDir, { recursive: true, mode: 0o700 });
            const temp = `${registryFile}.${process.pid}.${Date.now()}.tmp`;
            await fs.promises.writeFile(temp, `${JSON.stringify(registry, null, 2)}\n`, { mode: 0o600 });
            await fs.promises.rename(temp, registryFile);
            try {
                fs.chmodSync(registryFile, 0o600);
            } catch {}
        }).catch((error) => {
            ctx.logger?.warn?.(error);
        });
        return saveChain;
    }

    const secret = decodeB64Url(registry.secret) ?? crypto.randomBytes(32);
    function sign(text) {
        return b64url(crypto.createHmac('sha256', secret).update(text).digest());
    }

    function deviceCookieFor(id) {
        return `${id}.${sign(`device:${id}`)}`;
    }

    function candidateCookieFor(id) {
        return `${id}.${sign(`candidate:${id}`)}`;
    }

    function verifyDevice(req) {
        const raw = cookieMap(req.headers.cookie).get(DEVICE_COOKIE);
        if (!raw) return undefined;
        const at = raw.lastIndexOf('.');
        if (at < 0) return undefined;
        const id = raw.slice(0, at);
        const signature = raw.slice(at + 1);
        if (!timingEqual(signature, sign(`device:${id}`))) return undefined;
        const record = registry.devices[id];
        if (record === undefined) return undefined;
        return record;
    }

    function candidateId(req) {
        const raw = cookieMap(req.headers.cookie).get(CANDIDATE_COOKIE);
        if (!raw) return undefined;
        const at = raw.lastIndexOf('.');
        if (at < 0) return undefined;
        const id = raw.slice(0, at);
        const signature = raw.slice(at + 1);
        if (!timingEqual(signature, sign(`candidate:${id}`))) return undefined;
        return id;
    }

    function verifyCandidate(req) {
        const id = candidateId(req);
        return id === undefined ? undefined : registry.pending[id];
    }

    let browserSecretCache;
    let browserSecretAt = 0;
    function browserSecret() {
        const now = Date.now();
        if (browserSecretCache !== undefined && now - browserSecretAt < 10_000) return browserSecretCache;
        browserSecretAt = now;
        try {
            const text = fs.readFileSync(path.join(dshHome, '.credentials.yaml'), 'utf8');
            const match = text.match(/client-connection\/browser-session:[\s\S]*?secret:\s*(\S+)/u);
            const decoded = match === null ? undefined : decodeB64Url(match[1]);
            browserSecretCache = decoded?.length === 32 ? decoded : undefined;
        } catch {
            browserSecretCache = undefined;
        }
        return browserSecretCache;
    }

    function requestAuthority(req) {
        try {
            return new URL(`http://${String(req.headers.host ?? '')}`).host;
        } catch {
            return undefined;
        }
    }

    function verifyOwner(req) {
        const authority = requestAuthority(req);
        const secretBytes = browserSecret();
        if (authority === undefined || secretBytes === undefined) return false;
        const name = 'dsh-auth-' + b64url(crypto.createHash('sha256').update(authority).digest());
        const raw = cookieMap(req.headers.cookie).get(name);
        if (!raw) return false;
        const parts = raw.split('.');
        if (parts.length !== 3) return false;
        const [version, body, encodedSignature] = parts;
        const actual = decodeB64Url(encodedSignature);
        if (actual === undefined) return false;
        const expected = crypto.createHmac('sha256', secretBytes).update(body).digest();
        if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return false;
        let payload;
        try {
            const bytes = decodeB64Url(body);
            if (bytes === undefined) return false;
            payload = JSON.parse(bytes.toString('utf8'));
        } catch {
            return false;
        }
        if (payload === null || typeof payload !== 'object' || (version !== 'v1' && version !== 'v2')) return false;
        if (version !== `v${payload.version}`) return false;
        if (payload.authority !== authority) return false;
        if (!Number.isSafeInteger(payload.issuedAt) || !Number.isSafeInteger(payload.expiresAt)) return false;
        const now = Date.now();
        return payload.issuedAt <= now && payload.expiresAt > now;
    }

    let internalCookieCache;
    let internalCookieAt = 0;
    function internalCookie() {
        const now = Date.now();
        if (internalCookieCache !== undefined && now - internalCookieAt < 10 * 60 * 1000) return internalCookieCache;
        const secretBytes = browserSecret();
        if (secretBytes === undefined) throw new Error('lan-access: browser-session credential is unavailable');
        const authority = origin.host;
        const name = 'dsh-auth-' + b64url(crypto.createHash('sha256').update(authority).digest());
        const issuedAt = now;
        const expiresAt = now + 30 * 24 * 60 * 60 * 1000 - 60 * 60 * 1000;
        const payload = { version: 1, authority, issuedAt, expiresAt };
        const body = b64url(Buffer.from(JSON.stringify(payload), 'utf8'));
        const signature = b64url(crypto.createHmac('sha256', secretBytes).update(body).digest());
        internalCookieCache = `${name}=v1.${body}.${signature}`;
        internalCookieAt = now;
        return internalCookieCache;
    }

    function deviceLabel(record) {
        return safeLabel(record?.label ?? record?.fingerprint, '未命名设备');
    }

    function publicPending() {
        return Object.values(registry.pending)
            .sort((a, b) => a.createdAt - b.createdAt)
            .map((record) => ({
                id: record.id,
                label: deviceLabel(record),
                fingerprint: record.fingerprint ?? '',
                userAgent: record.userAgent ?? '',
                address: record.address ?? '',
                createdAt: record.createdAt,
                lastSeen: record.lastSeen
            }));
    }

    function publicDevices() {
        return Object.values(registry.devices)
            .sort((a, b) => b.approvedAt - a.approvedAt)
            .map((record) => ({
                id: record.id,
                label: deviceLabel(record),
                fingerprint: record.fingerprint ?? '',
                userAgent: record.userAgent ?? '',
                address: record.address ?? '',
                approvedAt: record.approvedAt,
                lastSeen: record.lastSeen
            }));
    }

    function csrfAllowed(req) {
        if (req.method === 'GET' || req.method === 'HEAD') return true;
        // A caller able to set this custom header has already passed the DSH
        // owner-cookie check above; browsers never add it from another origin.
        if (req.headers['x-dsh-lan-admin'] === '1') return true;
        const authority = requestAuthority(req);
        if (authority === undefined) return false;
        const originHeader = req.headers.origin;
        if (typeof originHeader === 'string') {
            return originHeader === `http://${authority}`
                || originHeader === `https://${authority}`
                || originHeader === 'dsh-app://app'
                || originHeader.startsWith('dsh-app://');
        }
        const site = req.headers['sec-fetch-site'];
        return site === 'same-origin' || site === 'same-site' || site === 'none';
    }

    function state() {
        return {
            listening: server.listening,
            bind,
            port,
            upstream: origin.origin,
            pending: publicPending(),
            devices: publicDevices()
        };
    }

    async function applyDeviceAction(action, id) {
        if (action === 'approve') {
            const record = registry.pending[id];
            if (record === undefined) return { ok: false, error: 'pending-not-found' };
            delete registry.pending[id];
            registry.devices[id] = {
                ...record,
                approvedAt: Date.now()
            };
        } else if (action === 'reject') {
            delete registry.pending[id];
        } else if (action === 'remove') {
            delete registry.devices[id];
            delete registry.pending[id];
        } else {
            return { ok: false, error: 'unknown-action' };
        }
        await saveRegistry();
        return { ok: true };
    }

    async function handleAdmin(req, res) {
        if (req.method !== 'GET' && req.method !== 'POST') {
            sendJson(res, 405, { error: 'method-not-allowed' });
            return;
        }
        if (!verifyOwner(req)) {
            sendJson(res, 401, { error: 'owner-required', message: '请通过 owner 的 DSH Web 登录后管理设备。' });
            return;
        }
        if (!csrfAllowed(req)) {
            sendJson(res, 403, { error: 'csrf' });
            return;
        }
        let url;
        try {
            url = new URL(req.url ?? '/', 'http://x');
        } catch {
            sendJson(res, 400, { error: 'bad-url' });
            return;
        }
        const sub = url.pathname.slice(ADMIN_PREFIX.length); // keep leading /
        if (req.method === 'GET' && sub === '/api/state') {
            sendJson(res, 200, state());
            return;
        }
        if (req.method === 'POST' && (sub === '/api/approve' || sub === '/api/reject' || sub === '/api/remove')) {
            let body;
            try {
                body = JSON.parse(await readBody(req));
            } catch {
                sendJson(res, 400, { error: 'invalid-body' });
                return;
            }
            const id = typeof body?.id === 'string' ? body.id : '';
            if (id === '') {
                sendJson(res, 400, { error: 'missing-id' });
                return;
            }
            const result = await applyDeviceAction(sub.slice('/api/'.length), id);
            if (!result.ok) {
                sendJson(res, 404, { error: result.error });
                return;
            }
            sendJson(res, 200, { pending: publicPending(), devices: publicDevices() });
            return;
        }
        sendJson(res, 404, { error: 'not-found' });
    }

    function pendingFor(req, candidate) {
        if (candidate !== undefined) return candidate;
        const id = randomId();
        const now = Date.now();
        const userAgent = String(req.headers['user-agent'] ?? '').slice(0, 400);
        const record = {
            id,
            label: describeUserAgent(userAgent),
            createdAt: now,
            lastSeen: now,
            userAgent,
            address: String(req.socket?.remoteAddress ?? '').slice(0, 80),
            fingerprint: ''
        };
        registry.pending[id] = record;
        void saveRegistry();
        return record;
    }

    function waitingPage(candidate) {
        return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DSH 设备授权</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f6f8; color: #1c1c1e; }
  .card { width: min(420px, calc(100vw - 48px)); background: #fff; border-radius: 16px; padding: 28px; box-shadow: 0 12px 40px rgba(0,0,0,.12); }
  h1 { font-size: 20px; margin: 0 0 8px; }
  p { color: #555; line-height: 1.6; margin: 0 0 12px; }
  .code { font-family: ui-monospace, monospace; background: #f0f1f4; border-radius: 8px; padding: 10px 12px; word-break: break-all; }
  .hint { font-size: 13px; color: #777; }
  button { margin-top: 14px; border: 0; border-radius: 8px; padding: 10px 16px; background: #247bbf; color: #fff; font-size: 14px; cursor: pointer; }
  button:disabled { opacity: .5; cursor: default; }
  @media (prefers-color-scheme: dark) { body { background: #16171a; color: #f2f2f2; } .card { background: #23252a; } p, .hint { color: #b8b9bd; } .code { background: #2c2f36; } }
</style>
</head>
<body>
<main class="card">
  <h1>等待批准</h1>
  <p>这台设备还没有获准访问。请在电脑上打开 DSH 的「设置 → 局域网访问」，确认并允许本次请求。</p>
  <div class="code">设备请求：${candidate.id}</div>
  <p class="hint" id="status">正在等待批准…</p>
  <button id="retry" type="button" hidden>重新申请</button>
</main>
<script>
(() => {
  const status = document.getElementById('status');
  const retry = document.getElementById('retry');
  const fingerprint = () => {
    try {
      return JSON.stringify({ ua: navigator.userAgent, language: navigator.language, platform: navigator.platform, width: screen.width, height: screen.height, dpr: window.devicePixelRatio || 1, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone });
    } catch { return navigator.userAgent || ''; }
  };
  const report = () => fetch('/__lan/enroll', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ fingerprint: fingerprint() }) }).catch(() => {});
  report();
  let stopped = false;
  const poll = async () => {
    if (stopped) return;
    try {
      const response = await fetch('/__lan/status', { cache: 'no-store' });
      const value = await response.json();
      if (value.state === 'approved') { status.textContent = '已批准，正在进入…'; location.replace('/'); return; }
      if (value.state === 'rejected') { status.textContent = '本次请求已被拒绝。'; retry.hidden = false; return; }
      status.textContent = '正在等待批准…';
    } catch { status.textContent = '连接暂时中断，正在重试…'; }
    setTimeout(poll, 2000);
  };
  retry.addEventListener('click', () => location.reload());
  poll();
})();
</script>
</body>
</html>`;
    }

    function serveWaiting(req, res) {
        const candidate = verifyCandidate(req) ?? pendingFor(req);
        const html = waitingPage(candidate);
        const headers = {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-store',
            'content-length': Buffer.byteLength(html)
        };
        const cookie = cookieHeader(CANDIDATE_COOKIE, candidateCookieFor(candidate.id), CANDIDATE_MAX_AGE);
        res.writeHead(200, { ...headers, 'set-cookie': cookie });
        res.end(html);
    }

    async function handleEnroll(req, res) {
        const id = candidateId(req);
        const candidate = id === undefined ? undefined : registry.pending[id];
        if (candidate === undefined) {
            sendJson(res, 404, { state: registry.devices[id] !== undefined ? 'approved' : 'unknown' });
            return;
        }
        let body;
        try {
            body = JSON.parse(await readBody(req));
        } catch {
            body = {};
        }
        const fingerprint = typeof body?.fingerprint === 'string' ? body.fingerprint.slice(0, 1200) : '';
        candidate.fingerprint = fingerprint === '' ? candidate.fingerprint : hashFingerprint(fingerprint);
        candidate.lastSeen = Date.now();
        await saveRegistry();
        sendJson(res, 200, { ok: true });
    }

    function handleStatus(req, res) {
        const id = candidateId(req);
        if (id === undefined) {
            sendJson(res, 200, { state: 'unknown' });
            return;
        }
        const device = registry.devices[id];
        if (device !== undefined) {
            res.writeHead(200, {
                'content-type': 'application/json; charset=utf-8',
                'cache-control': 'no-store',
                'set-cookie': cookieHeader(DEVICE_COOKIE, deviceCookieFor(id), DEVICE_MAX_AGE)
            });
            res.end(JSON.stringify({ state: 'approved' }));
            return;
        }
        const candidate = registry.pending[id];
        if (candidate === undefined) {
            sendJson(res, 200, { state: 'unknown' });
            return;
        }
        candidate.lastSeen = Date.now();
        void saveRegistry();
        sendJson(res, 200, { state: 'pending' });
    }

    function proxyHttp(req, res) {
        let cookie;
        try {
            cookie = internalCookie();
        } catch (error) {
            sendJson(res, 503, { error: 'upstream-auth-unavailable' });
            return;
        }
        const headers = { ...req.headers };
        delete headers.cookie;
        delete headers.host;
        headers.host = origin.host;
        if (headers.origin !== undefined) headers.origin = origin.origin;
        headers.cookie = cookie;
        const client = origin.protocol === 'https:' ? https : http;
        const upstream = client.request({
            hostname: origin.hostname,
            port: upstreamPort,
            path: req.url,
            method: req.method,
            headers,
            rejectUnauthorized: false
        }, (upstreamResponse) => {
            const responseHeaders = { ...upstreamResponse.headers };
            delete responseHeaders['set-cookie'];
            delete responseHeaders['transfer-encoding'];
            delete responseHeaders.connection;
            delete responseHeaders['keep-alive'];
            res.writeHead(upstreamResponse.statusCode ?? 502, responseHeaders);
            upstreamResponse.pipe(res);
        });
        upstream.on('error', (error) => {
            ctx.logger?.warn?.(error);
            if (!res.headersSent) {
                res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
                res.end('DSH upstream unavailable\n');
            } else {
                res.destroy();
            }
        });
        req.pipe(upstream);
    }

    function proxyUpgrade(req, socket, head) {
        const cookie = internalCookie();
        const headers = { ...req.headers };
        delete headers.cookie;
        delete headers.host;
        headers.host = origin.host;
        if (headers.origin !== undefined) headers.origin = origin.origin;
        headers.cookie = cookie;
        const useTls = origin.protocol === 'https:';
        const upstream = useTls
            ? tls.connect({ host: origin.hostname, port: upstreamPort, rejectUnauthorized: false }, () => handshake())
            : net.connect(upstreamPort, origin.hostname, () => handshake());
        function handshake() {
            const lines = [`${req.method} ${req.url} HTTP/1.1`];
            for (const [key, value] of Object.entries(headers)) {
                if (value === undefined) continue;
                if (Array.isArray(value)) {
                    for (const item of value) lines.push(`${key}: ${item}`);
                } else {
                    lines.push(`${key}: ${value}`);
                }
            }
            lines.push('', '');
            upstream.write(lines.join('\r\n'));
            if (head.length > 0) upstream.write(head);
            upstream.pipe(socket);
            socket.pipe(upstream);
        }
        upstream.on('error', () => socket.destroy());
        socket.on('error', () => upstream.destroy());
        upstream.on('close', () => { try { socket.destroy(); } catch {} });
        socket.on('close', () => { try { upstream.destroy(); } catch {} });
    }

    function isLoopback(req) {
        const address = String(req.socket?.remoteAddress ?? '');
        return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
    }

    function managePage() {
        return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DSH 局域网设备管理</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 0; background: #f5f6f8; color: #1c1c1e; }
  main { max-width: 760px; margin: 32px auto; padding: 0 20px; }
  h1 { font-size: 20px; margin: 0 0 6px; }
  p { color: #666; line-height: 1.6; }
  h2 { font-size: 14px; margin: 22px 0 8px; }
  .row { display: flex; align-items: center; justify-content: space-between; gap: 12px; background: #fff; border-radius: 10px; padding: 10px 12px; margin: 8px 0; box-shadow: 0 2px 8px rgba(0,0,0,.05); }
  .main { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
  .title { font-weight: 600; }
  .sub { color: #777; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  button { border: 1px solid #ccc; background: #f7f7f7; border-radius: 7px; padding: 6px 12px; font-size: 13px; cursor: pointer; }
  .primary { border-color: #247bbf; background: #247bbf; color: #fff; }
  .empty { color: #999; font-size: 13px; }
  .status { color: #666; font-size: 13px; margin-bottom: 8px; }
  .error { color: #c0392b; }
  @media (prefers-color-scheme: dark) { body { background: #16171a; color: #f2f2f2; } p, .sub, .status, .empty { color: #b8b9bd; } .row { background: #23252a; } button:not(.primary) { background: #2c2f36; color: #eee; border-color: #444; } }
</style>
</head>
<body>
<main>
  <h1>局域网设备管理</h1>
  <p>这是本机回环管理页（只有本机可以打开）。手机/其它设备第一次访问 8097 会进入等待；在下面允许后，该设备会进入原生 DSH Web。</p>
  <div class="status" id="status">正在读取…</div>
  <div id="error" class="error"></div>
  <h2>待批准</h2>
  <div id="pending"></div>
  <h2>已批准</h2>
  <div id="devices"></div>
</main>
<script>
(() => {
  const fmt = (v) => { try { return new Date(v).toLocaleString(); } catch { return ''; } };
  const esc = (v) => String(v).replace(/[&<>"]/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
  const statusEl = document.getElementById('status');
  const errorEl = document.getElementById('error');
  const pendingEl = document.getElementById('pending');
  const devicesEl = document.getElementById('devices');
  let busy = false;
  async function request(path, options) {
    const response = await fetch(path, { cache: 'no-store', ...options });
    const text = await response.text();
    let value = null;
    try { value = JSON.parse(text); } catch { value = null; }
    if (!response.ok) throw new Error(value?.message ?? value?.error ?? text.slice(0, 200));
    return value;
  }
  function row(item, actions) {
    const div = document.createElement('div'); div.className = 'row';
    const main = document.createElement('div'); main.className = 'main';
    const title = document.createElement('div'); title.className = 'title'; title.textContent = item.label || '未命名设备';
    const sub = document.createElement('div'); sub.className = 'sub';
    sub.textContent = (item.approvedAt ? '批准于 ' + fmt(item.approvedAt) : fmt(item.createdAt)) + (item.fingerprint ? ' · 指纹 ' + item.fingerprint.slice(0, 16) : '') + (item.address ? ' · ' + item.address : '');
    main.append(title, sub); div.append(main);
    const box = document.createElement('div');
    for (const [label, action, primary] of actions) {
      const b = document.createElement('button'); b.type = 'button'; b.textContent = label;
      if (primary) b.className = 'primary';
      b.onclick = async () => { if (busy) return; busy = true; try { await request('/__manage/api/' + action, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: item.id }) }); await refresh(); } catch (e) { errorEl.textContent = String(e.message || e); } finally { busy = false; } };
      box.append(b);
    }
    div.append(box);
    return div;
  }
  async function refresh() {
    try {
      const value = await request('/__manage/api/state');
      statusEl.textContent = '监听：' + value.bind + ':' + value.port + ' · 待批准 ' + value.pending.length + ' · 已批准 ' + value.devices.length;
      errorEl.textContent = '';
      pendingEl.replaceChildren();
      if (value.pending.length === 0) { const e = document.createElement('div'); e.className = 'empty'; e.textContent = '没有待批准的设备。'; pendingEl.append(e); }
      for (const item of value.pending) pendingEl.append(row(item, [['允许', 'approve', true], ['拒绝', 'reject', false]]));
      devicesEl.replaceChildren();
      if (value.devices.length === 0) { const e = document.createElement('div'); e.className = 'empty'; e.textContent = '还没有已批准的设备。'; devicesEl.append(e); }
      for (const item of value.devices) devicesEl.append(row(item, [['移除', 'remove', false]]));
    } catch (e) { errorEl.textContent = String(e.message || e); }
  }
  refresh();
  setInterval(refresh, 2500);
})();
</script>
</body>
</html>`;
    }

    async function handleManage(req, res) {
        if (!isLoopback(req)) {
            res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
            res.end('management page is loopback-only\n');
            return;
        }
        let url;
        try {
            url = new URL(req.url ?? '/', 'http://x');
        } catch {
            res.writeHead(400);
            res.end();
            return;
        }
        if (req.method === 'GET' && (url.pathname === '/__manage' || url.pathname === '/__manage/')) {
            const html = managePage();
            res.writeHead(200, {
                'content-type': 'text/html; charset=utf-8',
                'cache-control': 'no-store',
                'content-length': Buffer.byteLength(html)
            });
            res.end(html);
            return;
        }
        if (req.method === 'GET' && url.pathname === '/__manage/api/state') {
            sendJson(res, 200, state());
            return;
        }
        if (req.method === 'POST' && (url.pathname === '/__manage/api/approve' || url.pathname === '/__manage/api/reject' || url.pathname === '/__manage/api/remove')) {
            let body;
            try {
                body = JSON.parse(await readBody(req));
            } catch {
                sendJson(res, 400, { error: 'invalid-body' });
                return;
            }
            const id = typeof body?.id === 'string' ? body.id : '';
            if (id === '') {
                sendJson(res, 400, { error: 'missing-id' });
                return;
            }
            const result = await applyDeviceAction(url.pathname.slice('/__manage/api/'.length), id);
            if (!result.ok) {
                sendJson(res, 404, { error: result.error });
                return;
            }
            sendJson(res, 200, { pending: publicPending(), devices: publicDevices() });
            return;
        }
        sendJson(res, 404, { error: 'not-found' });
    }

    function requestHandler(req, res) {
        let url;
        try {
            url = new URL(req.url ?? '/', 'http://x');
        } catch {
            res.writeHead(400);
            res.end();
            return;
        }
        const pathname = url.pathname;
        if (pathname === '/__manage' || pathname.startsWith('/__manage/')) {
            void handleManage(req, res);
            return;
        }
        if (pathname === '/favicon.ico' || pathname === '/apple-touch-icon.png') {
            res.writeHead(204);
            res.end();
            return;
        }
        if (pathname.startsWith('/__lan/')) {
            if (req.method === 'POST' && pathname === '/__lan/enroll') {
                void handleEnroll(req, res);
                return;
            }
            if (req.method === 'GET' && pathname === '/__lan/status') {
                handleStatus(req, res);
                return;
            }
            sendJson(res, 404, { error: 'not-found' });
            return;
        }
        if (pathname.startsWith('/lan-access')) {
            res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
            res.end('forbidden\n');
            return;
        }
        // Requests originating on this machine are already inside the owner's
        // trust boundary; do not make the local browser pair itself as a device.
        if (isLoopback(req)) {
            proxyHttp(req, res);
            return;
        }
        const device = verifyDevice(req);
        if (device !== undefined) {
            device.lastSeen = Date.now();
            proxyHttp(req, res);
            return;
        }
        if (req.method !== 'GET') {
            res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
            res.end('device approval required\n');
            return;
        }
        serveWaiting(req, res);
    }

    const server = tlsConfig?.certFile && tlsConfig?.keyFile
        ? https.createServer({
            cert: fs.readFileSync(path.resolve(tlsConfig.certFile)),
            key: fs.readFileSync(path.resolve(tlsConfig.keyFile))
        }, requestHandler)
        : http.createServer(requestHandler);
    server.on('upgrade', (req, socket, head) => {
        if (!isLoopback(req) && verifyDevice(req) === undefined) {
            socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
            socket.destroy();
            return;
        }
        try {
            proxyUpgrade(req, socket, head);
        } catch (error) {
            ctx.logger?.warn?.(error);
            socket.destroy();
        }
    });

    return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, bind, () => {
            server.off('error', reject);
            server.on('error', (error) => ctx.logger?.warn?.(error));
            const disposeRoute = ctx.webServer.register({ kind: 'prefix', path: ADMIN_PREFIX, handler: handleAdmin });
            ctx.effect(() => () => {
                try { disposeRoute(); } catch {}
                server.closeAllConnections?.();
                server.close();
            });
            ctx.logger?.info?.(`lan-access: listening on ${bind}:${String(port)} -> ${origin.origin}`);
            resolve();
        });
    });
}
