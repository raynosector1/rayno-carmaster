'use strict';
/**
 * 레이노 카마스터 - NICE 통합인증(표준창) 연동 서버
 *
 * 흐름
 *   1) 프론트 → POST /v1/verify/start        : 인증 시작, auth_url 발급
 *   2) 사용자 → NICE 표준창에서 휴대폰 인증
 *   3) NICE  → GET  /return/:attemptId       : web_transaction_id 수신 → 결과조회·복호화
 *   4) 프론트 → GET  /v1/verify/result       : 폴링, 완료 시 서명된 토큰 수령
 *
 * 원칙
 *   - 비밀값은 코드에 없음 (AWS SSM Parameter Store에서 기동 시 1회 로드)
 *   - 개인정보는 로그에 남기지 않음
 *   - 인증 진행상태는 메모리에만 10분 보관 (디스크·DB 저장 없음)
 *   - CI는 사용하지 않음. DI만 HMAC 해시로 변환하여 전달
 */

const http = require('http');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

// ─────────────────────────────────────────────
// 설정
// ─────────────────────────────────────────────
const REGION = 'ap-northeast-2';
const NICE_BASE = 'https://auth.niceid.co.kr';
const SELF_BASE = 'https://carmaster-auth.raynofilm.co.kr';
const ALLOWED_ORIGINS = ['https://carmaster.raynofilm.co.kr'];
const PORT = 3000;

const ATTEMPT_TTL_MS = 10 * 60 * 1000;   // 인증 시도 유효시간 10분
const TOKEN_TTL_SEC = 600;               // 발급 토큰 유효시간 10분
const RATE_PER_MIN = 5;                  // IP당 분당 인증 시작 횟수
const RATE_PER_10MIN = 20;               // IP당 10분당 인증 시작 횟수

// ─────────────────────────────────────────────
// 비밀값 로드 (SSM)
// ─────────────────────────────────────────────
function ssmGet(name) {
  return execFileSync('aws', [
    'ssm', 'get-parameter',
    '--name', name,
    '--with-decryption',
    '--region', REGION,
    '--query', 'Parameter.Value',
    '--output', 'text'
  ], { encoding: 'utf8', timeout: 15000 }).trim();
}

let SECRETS;
try {
  SECRETS = {
    clientId: ssmGet('/rayno/carmaster/nice/client-id'),
    clientSecret: ssmGet('/rayno/carmaster/nice/client-secret'),
    signKey: ssmGet('/rayno/carmaster/verify-sign-key'),
    diKey: ssmGet('/rayno/carmaster/di-hmac-key')
  };
} catch (e) {
  console.error('[FATAL] SSM 비밀값 로드 실패. IAM 권한과 파라미터 이름을 확인하세요.');
  process.exit(1);
}
for (const [k, v] of Object.entries(SECRETS)) {
  if (!v || v === 'None') {
    console.error(`[FATAL] 비밀값이 비어 있습니다: ${k}`);
    process.exit(1);
  }
}

// ─────────────────────────────────────────────
// 유틸
// ─────────────────────────────────────────────
const b64url = (buf) =>
  Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const b64urlDecode = (str) =>
  Buffer.from(String(str).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

function newRequestNo() {
  // NICE 규격: 최소 20byte ~ 최대 50byte
  return 'RCM' + Date.now() + crypto.randomBytes(6).toString('hex');
}

function log(event, extra) {
  // 개인정보는 절대 넣지 않는다
  console.log(JSON.stringify({ t: new Date().toISOString(), event, ...(extra || {}) }));
}

// ─────────────────────────────────────────────
// 인증 시도 저장소 (메모리)
// ─────────────────────────────────────────────
const attempts = new Map();
const usedWebTx = new Map();   // web_transaction_id 재사용 차단

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of attempts) if (v.expiresAt < now) attempts.delete(k);
  for (const [k, v] of usedWebTx) if (v < now) usedWebTx.delete(k);
}, 60 * 1000).unref();

// ─────────────────────────────────────────────
// 요청 제한
// ─────────────────────────────────────────────
const rateLog = new Map();
function rateAllow(ip) {
  const now = Date.now();
  const arr = (rateLog.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
  const lastMin = arr.filter((t) => now - t < 60 * 1000).length;
  if (lastMin >= RATE_PER_MIN || arr.length >= RATE_PER_10MIN) {
    rateLog.set(ip, arr);
    return false;
  }
  arr.push(now);
  rateLog.set(ip, arr);
  return true;
}

// ─────────────────────────────────────────────
// NICE API
// ─────────────────────────────────────────────
let tokenCache = null;   // { accessToken, ticket, iterators, expiresAt }

async function niceFetch(path, headers, body) {
  const res = await fetch(NICE_BASE + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'charset': 'UTF-8',
      'X-Intc-DevLang': 'Linux/Node.js',
      ...headers
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000)
  });
  if (!res.ok) throw new Error('NICE_HTTP_' + res.status);
  return res.json();
}

async function getAccessToken() {
  if (tokenCache && tokenCache.expiresAt > Date.now() + 60000) return tokenCache;

  const basic = b64url(SECRETS.clientId + ':' + SECRETS.clientSecret);
  const out = await niceFetch(
    '/ido/intc/v1.0/auth/token',
    { Authorization: 'Basic ' + basic },
    { grant_type: 'client_credentials', request_no: newRequestNo() }
  );

  if (out.result_code !== '0000') {
    log('nice_token_failed', { code: out.result_code });
    throw new Error('NICE_TOKEN_' + out.result_code);
  }

  tokenCache = {
    accessToken: out.access_token,
    ticket: out.ticket,
    iterators: out.iterators,
    expiresAt: Date.now() + 12 * 60 * 60 * 1000
  };
  log('nice_token_issued');
  return tokenCache;
}

async function requestAuthUrl(attemptId) {
  const tk = await getAccessToken();
  const requestNo = newRequestNo();

  const out = await niceFetch(
    '/ido/intc/v1.0/auth/url',
    { Authorization: 'Bearer ' + tk.accessToken },
    {
      request_no: requestNo,
      return_url: `${SELF_BASE}/return/${attemptId}`,
      close_url: `${SELF_BASE}/close`,
      svc_types: ['M'],
      method_type: 'GET'
    }
  );

  if (out.result_code !== '0000') {
    log('nice_url_failed', { code: out.result_code });
    throw new Error('NICE_URL_' + out.result_code);
  }
  return { authUrl: out.auth_url, transactionId: out.transaction_id, requestNo };
}

async function requestAuthResult(attempt, webTransactionId) {
  const tk = await getAccessToken();

  const out = await niceFetch(
    '/ido/intc/v1.0/auth/result',
    { Authorization: 'Bearer ' + tk.accessToken },
    {
      request_no: attempt.requestNo,
      transaction_id: attempt.transactionId,
      web_transaction_id: webTransactionId
    }
  );

  if (out.result_code !== '0000') {
    log('nice_result_failed', { code: out.result_code });
    throw new Error('NICE_RESULT_' + out.result_code);
  }

  // 키 유도 (PBKDF2-HMAC-SHA256, 64byte → base64url 문자열)
  const keyString = b64url(
    crypto.pbkdf2Sync(tk.ticket, attempt.transactionId, tk.iterators, 64, 'sha256')
  );
  const symKey = keyString.substring(0, 32);
  const hmacKey = keyString.substring(48, 80);

  // 무결성 검증
  const calc = b64url(crypto.createHmac('sha256', hmacKey).update(out.enc_data).digest());
  if (calc !== out.integrity_value) {
    log('integrity_mismatch');
    throw new Error('INTEGRITY_MISMATCH');
  }

  // 복호화 (AES-256-GCM, 앞 16byte가 IV, 뒤 16byte가 인증태그)
  const raw = b64urlDecode(out.enc_data);
  const iv = raw.subarray(0, 16);
  const tag = raw.subarray(raw.length - 16);
  const cipherText = raw.subarray(16, raw.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(symKey, 'utf8'), iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(cipherText), decipher.final()]).toString('utf8');

  return JSON.parse(plain);
}

// ─────────────────────────────────────────────
// 서명 토큰 (HS256)
// ─────────────────────────────────────────────
function signToken(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const sig = b64url(
    crypto.createHmac('sha256', SECRETS.signKey).update(header + '.' + body).digest()
  );
  return `${header}.${body}.${sig}`;
}

function hashDi(di) {
  return crypto.createHmac('sha256', SECRETS.diKey).update(di).digest('hex');
}

// ─────────────────────────────────────────────
// HTTP 응답 헬퍼
// ─────────────────────────────────────────────
function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
}

function sendJson(res, status, obj) {
  const s = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(s);
}

function sendHtml(res, status, html) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(html);
}

function popupPage(title, message, ok) {
  return `<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
font-family:-apple-system,BlinkMacSystemFont,"Malgun Gothic",sans-serif;background:#f7f8fa}
.box{text-align:center;padding:24px}
.ico{font-size:44px;margin-bottom:12px}
h1{font-size:17px;margin:0 0 6px;color:#111}
p{font-size:13px;color:#666;margin:0}
</style></head><body>
<div class="box">
  <div class="ico">${ok ? '&#10004;' : '&#10005;'}</div>
  <h1>${title}</h1><p>${message}</p>
</div>
<script>setTimeout(function(){try{window.close();}catch(e){}},1200);</script>
</body></html>`;
}

// ─────────────────────────────────────────────
// 라우팅
// ─────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, SELF_BASE);
  const path = url.pathname;
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress || 'unknown';

  cors(req, res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  try {
    // 상태 확인
    if (path === '/health') {
      return sendJson(res, 200, { ok: true, attempts: attempts.size });
    }

    // 1) 인증 시작
    if (path === '/v1/verify/start' && req.method === 'POST') {
      if (!rateAllow(ip)) {
        log('rate_limited');
        return sendJson(res, 429, { error: 'TOO_MANY_REQUESTS' });
      }

      const attemptId = crypto.randomUUID();
      const { authUrl, transactionId, requestNo } = await requestAuthUrl(attemptId);

      attempts.set(attemptId, {
        state: 'url_issued',
        transactionId,
        requestNo,
        expiresAt: Date.now() + ATTEMPT_TTL_MS,
        result: null,
        failCode: null
      });

      log('verify_started', { attempt: attemptId.slice(0, 8) });
      return sendJson(res, 200, {
        attempt_id: attemptId,
        auth_url: authUrl,
        expires_in: ATTEMPT_TTL_MS / 1000
      });
    }

    // 3) NICE 리턴
    if (path.startsWith('/return/') && (req.method === 'GET' || req.method === 'POST')) {
      const attemptId = path.slice('/return/'.length);
      const attempt = attempts.get(attemptId);

      if (!attempt || attempt.expiresAt < Date.now()) {
        log('return_expired');
        return sendHtml(res, 200, popupPage('인증 시간이 만료되었습니다', '처음부터 다시 시도해 주세요.', false));
      }
      if (attempt.state !== 'url_issued') {
        log('return_duplicate');
        return sendHtml(res, 200, popupPage('이미 처리된 요청입니다', '창을 닫아 주세요.', false));
      }

      let webTx = url.searchParams.get('web_transaction_id');
      if (!webTx && req.method === 'POST') {
        const chunks = [];
        for await (const c of req) chunks.push(c);
        webTx = new URLSearchParams(Buffer.concat(chunks).toString('utf8')).get('web_transaction_id');
      }
      if (!webTx) {
        attempt.state = 'failed';
        attempt.failCode = 'NO_WEB_TX';
        log('return_no_webtx');
        return sendHtml(res, 200, popupPage('인증이 완료되지 않았습니다', '다시 시도해 주세요.', false));
      }
      if (usedWebTx.has(webTx)) {
        log('webtx_reused');
        return sendHtml(res, 200, popupPage('이미 처리된 요청입니다', '창을 닫아 주세요.', false));
      }
      usedWebTx.set(webTx, Date.now() + ATTEMPT_TTL_MS);

      attempt.state = 'result_pending';

      let info;
      try {
        info = await requestAuthResult(attempt, webTx);
      } catch (err) {
        attempt.state = 'failed';
        attempt.failCode = err.message;
        log('result_error', { code: err.message });
        return sendHtml(res, 200, popupPage('인증 처리 중 오류가 발생했습니다', '잠시 후 다시 시도해 주세요.', false));
      }

      const mobile = String(info.mobile_no || '').replace(/[^0-9]/g, '');
      const now = new Date().toISOString();

      attempt.state = 'verified';
      attempt.result = {
        name: info.name || '',
        phone: mobile,
        phone_last4: mobile.slice(-4),
        di_hash: hashDi(String(info.di || '')),
        verified_at: now
      };

      log('verify_succeeded', { attempt: attemptId.slice(0, 8) });
      return sendHtml(res, 200, popupPage('본인인증이 완료되었습니다', '잠시 후 창이 닫힙니다.', true));
    }

    // 표준창 닫기
    if (path === '/close') {
      return sendHtml(res, 200, popupPage('인증이 취소되었습니다', '창을 닫아 주세요.', false));
    }

    // 4) 결과 폴링
    if (path === '/v1/verify/result' && req.method === 'GET') {
      const attemptId = url.searchParams.get('attempt_id') || '';
      const attempt = attempts.get(attemptId);

      if (!attempt) return sendJson(res, 200, { status: 'expired' });
      if (attempt.expiresAt < Date.now()) {
        attempts.delete(attemptId);
        return sendJson(res, 200, { status: 'expired' });
      }
      if (attempt.state === 'failed') return sendJson(res, 200, { status: 'failed' });
      if (attempt.state !== 'verified') return sendJson(res, 200, { status: 'pending' });

      const r = attempt.result;
      const token = signToken({
        iss: 'rayno-carmaster-auth',
        aid: attemptId,
        name: r.name,
        phone: r.phone,
        phone_last4: r.phone_last4,
        di_hash: r.di_hash,
        verified_at: r.verified_at,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC
      });

      attempts.delete(attemptId);   // 1회성 — 즉시 폐기

      return sendJson(res, 200, {
        status: 'verified',
        token,
        name: r.name,
        phone_last4: r.phone_last4
      });
    }

    return sendJson(res, 404, { error: 'NOT_FOUND' });

  } catch (err) {
    log('unhandled_error', { code: err && err.message ? err.message : 'UNKNOWN' });
    return sendJson(res, 500, { error: 'INTERNAL_ERROR' });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  log('server_started', { port: PORT });
});
