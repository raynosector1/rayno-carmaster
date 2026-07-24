'use strict';
/**
 * 레이노 카마스터 — 백엔드 API 서버
 *
 * 구성
 *   [NICE 본인인증]  POST /v1/verify/start → 표준창 → /return/:id → GET /v1/verify/result
 *   [계정]           POST /v1/auth/check-id, /signup, /login   GET /v1/auth/me
 *   [기준정보]       GET  /v1/offices, /v1/notices, /v1/promotions
 *
 * 원칙
 *   - 비밀값은 코드에 없음 (AWS SSM Parameter Store에서 기동 시 1회 로드)
 *   - MySQL 직접 연결, 모든 쿼리는 파라미터 바인딩
 *   - 개인정보(phone)는 레이노 본 DB와 동일한 AES 방식으로 저장
 *   - 개인정보·키는 로그에 남기지 않음
 *   - 인증 진행상태는 메모리에만 10분 보관
 */

const http = require('http');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const db = require('./db');
const auth = require('./auth');

// ─────────────────────────────────────────────
// 설정
// ─────────────────────────────────────────────
const REGION = 'ap-northeast-2';
const NICE_BASE = 'https://auth.niceid.co.kr';
const SELF_BASE = 'https://carmaster-auth.raynofilm.co.kr';
const ALLOWED_ORIGINS = [
  'https://carmaster.raynofilm.co.kr',
  'https://raynosector1.github.io'
];
const PORT = 3000;

const ATTEMPT_TTL_MS = 10 * 60 * 1000;
const NICE_TOKEN_TTL_SEC = 600;
const RATE_VERIFY_MIN = 5;
const RATE_VERIFY_10MIN = 20;
const RATE_LOGIN_MIN = 10;

// ─────────────────────────────────────────────
// 비밀값 로드
// ─────────────────────────────────────────────
function ssmGet(name) {
  return execFileSync('aws', [
    'ssm', 'get-parameter', '--name', name, '--with-decryption',
    '--region', REGION, '--query', 'Parameter.Value', '--output', 'text'
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
  if (!v || v === 'None') { console.error(`[FATAL] 비밀값이 비어 있습니다: ${k}`); process.exit(1); }
}

// ─────────────────────────────────────────────
// 유틸
// ─────────────────────────────────────────────
const b64url = (buf) => Buffer.from(buf).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlDecode = (s) =>
  Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

const newRequestNo = () => 'RCM' + Date.now() + crypto.randomBytes(6).toString('hex');
const log = (event, extra) => db.log(event, extra);

// ─────────────────────────────────────────────
// 인증 시도 저장소 (메모리)
// ─────────────────────────────────────────────
const attempts = new Map();
const usedWebTx = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of attempts) if (v.expiresAt < now) attempts.delete(k);
  for (const [k, v] of usedWebTx) if (v < now) usedWebTx.delete(k);
}, 60 * 1000).unref();

// ─────────────────────────────────────────────
// 요청 제한
// ─────────────────────────────────────────────
const rateLog = new Map();
function rateAllow(key, perMin, per10Min) {
  const now = Date.now();
  const arr = (rateLog.get(key) || []).filter(t => now - t < 10 * 60 * 1000);
  const lastMin = arr.filter(t => now - t < 60 * 1000).length;
  if (lastMin >= perMin || (per10Min && arr.length >= per10Min)) {
    rateLog.set(key, arr);
    return false;
  }
  arr.push(now);
  rateLog.set(key, arr);
  return true;
}

// ─────────────────────────────────────────────
// NICE API
// ─────────────────────────────────────────────
let tokenCache = null;

async function niceFetch(path, headers, body) {
  const res = await fetch(NICE_BASE + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json', 'charset': 'UTF-8',
      'X-Intc-DevLang': 'Linux/Node.js', ...headers
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
  const out = await niceFetch('/ido/intc/v1.0/auth/token',
    { Authorization: 'Basic ' + basic },
    { grant_type: 'client_credentials', request_no: newRequestNo() });
  if (out.result_code !== '0000') {
    log('nice_token_failed', { code: out.result_code });
    throw new Error('NICE_TOKEN_' + out.result_code);
  }
  tokenCache = {
    accessToken: out.access_token, ticket: out.ticket, iterators: out.iterators,
    expiresAt: Date.now() + 12 * 60 * 60 * 1000
  };
  log('nice_token_issued');
  return tokenCache;
}

async function requestAuthUrl(attemptId) {
  const tk = await getAccessToken();
  const requestNo = newRequestNo();
  const out = await niceFetch('/ido/intc/v1.0/auth/url',
    { Authorization: 'Bearer ' + tk.accessToken },
    {
      request_no: requestNo,
      return_url: `${SELF_BASE}/return/${attemptId}`,
      close_url: `${SELF_BASE}/close`,
      svc_types: ['M'], method_type: 'GET'
    });
  if (out.result_code !== '0000') {
    log('nice_url_failed', { code: out.result_code });
    throw new Error('NICE_URL_' + out.result_code);
  }
  return { authUrl: out.auth_url, transactionId: out.transaction_id, requestNo };
}

async function requestAuthResult(attempt, webTransactionId) {
  const tk = await getAccessToken();
  const out = await niceFetch('/ido/intc/v1.0/auth/result',
    { Authorization: 'Bearer ' + tk.accessToken },
    {
      request_no: attempt.requestNo,
      transaction_id: attempt.transactionId,
      web_transaction_id: webTransactionId
    });
  if (out.result_code !== '0000') {
    log('nice_result_failed', { code: out.result_code });
    throw new Error('NICE_RESULT_' + out.result_code);
  }

  const keyString = b64url(
    crypto.pbkdf2Sync(tk.ticket, attempt.transactionId, tk.iterators, 64, 'sha256'));
  const symKey = keyString.substring(0, 32);
  const hmacKey = keyString.substring(48, 80);

  const calc = b64url(crypto.createHmac('sha256', hmacKey).update(out.enc_data).digest());
  if (calc !== out.integrity_value) {
    log('integrity_mismatch');
    throw new Error('INTEGRITY_MISMATCH');
  }

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
// 본인인증 결과 토큰 (가입 화면으로 전달)
// ─────────────────────────────────────────────
function signNiceToken(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const sig = b64url(crypto.createHmac('sha256', SECRETS.signKey)
    .update(header + '.' + body).digest());
  return `${header}.${body}.${sig}`;
}

function verifyNiceToken(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('본인인증을 다시 진행해 주세요.');
  const [h, b, sig] = parts;
  const calc = b64url(crypto.createHmac('sha256', SECRETS.signKey)
    .update(`${h}.${b}`).digest());
  if (calc.length !== sig.length ||
      !crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(sig))) {
    throw new Error('본인인증 정보가 올바르지 않습니다.');
  }
  const p = JSON.parse(b64urlDecode(b).toString('utf8'));
  if (p.iss !== 'rayno-carmaster-auth') throw new Error('본인인증 정보가 올바르지 않습니다.');
  if (Math.floor(Date.now() / 1000) > Number(p.exp || 0)) {
    throw new Error('본인인증 유효시간이 만료되었습니다. 다시 인증해 주세요.');
  }
  if (!p.di_hash || !p.name) throw new Error('본인인증 정보가 올바르지 않습니다.');
  return p;
}

const hashDi = (di) => crypto.createHmac('sha256', SECRETS.diKey).update(di).digest('hex');

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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '600');
}

function sendJson(res, status, obj) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(JSON.stringify(obj));
}

function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(html);
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 64 * 1024) throw new Error('요청이 너무 큽니다.');
    chunks.push(c);
  }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch (_) { throw new Error('요청 형식이 올바르지 않습니다.'); }
}

function popupPage(title, message, ok) {
  return `<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
font-family:-apple-system,BlinkMacSystemFont,"Malgun Gothic",sans-serif;background:#f7f8fa}
.box{text-align:center;padding:24px}.ico{font-size:44px;margin-bottom:12px}
h1{font-size:17px;margin:0 0 6px;color:#111}p{font-size:13px;color:#666;margin:0}</style></head><body>
<div class="box"><div class="ico">${ok ? '&#10004;' : '&#10005;'}</div>
<h1>${title}</h1><p>${message}</p></div>
<script>setTimeout(function(){try{window.close();}catch(e){}},1200);</script></body></html>`;
}

// ─────────────────────────────────────────────
// 가입 처리
// ─────────────────────────────────────────────
async function doSignup(body) {
  const v = verifyNiceToken(body.nice_token);

  const loginId = String(body.login_id || '').trim();
  auth.checkLoginIdFormat(loginId);
  auth.checkPasswordFormat(body.password);

  if (!body.agree_privacy || !body.agree_outsourcing) {
    throw new Error('필수 약관에 동의해 주세요.');
  }
  if (!body.brand || !body.region || !body.office) {
    throw new Error('소속 정보를 입력해 주세요.');
  }

  // 중복가입 확인 (계정을 만들기 전에)
  const dup = await db.query(
    'SELECT login_id FROM ?? WHERE di_hash = ? LIMIT 1',
    [db.T.CARMASTERS, v.di_hash]);
  if (dup.length) {
    const err = new Error(`이미 가입된 회원입니다. (아이디: ${dup[0].login_id})`);
    err.status = 409;
    throw err;
  }

  if (!(await auth.isLoginIdAvailable(loginId))) {
    throw new Error('이미 사용 중인 아이디입니다.');
  }

  const phone = String(v.phone || '').replace(/\D/g, '');
  const encPhone = db.encParam(phone);
  const carmasterId = crypto.randomUUID();

  await db.withTransaction(async (tx) => {
    const userId = await auth.createAccount(
      { loginId, password: body.password, role: 'carmaster' }, tx);

    // code 는 트리거가 채운다. phone_last4 는 평문 기준으로 직접 넣는다.
    // code 는 빈 값으로 넣는다. 트리거가 CM-n 형태로 채번한다.
    // (MySQL 5.6은 NOT NULL·기본값 없는 칸을 생략하면 트리거 실행 전에 거부한다)
    await tx.query(
      `INSERT INTO ?? (id, user_id, login_id, code, status, name, phone, phone_last4, di_hash,
                       verified_at, brand, brand_etc, region, office, office_etc,
                       agree_privacy, agree_outsourcing, agree_marketing, agreed_at)
       VALUES (?, ?, ?, '', 'verified', ?, ${encPhone.sql}, ?, ?,
               UTC_TIMESTAMP(), ?, ?, ?, ?, ?, 1, 1, ?, UTC_TIMESTAMP())`,
      [db.T.CARMASTERS, carmasterId, userId, loginId, v.name,
       ...encPhone.params, phone.slice(-4), v.di_hash,
       body.brand, body.brand_etc || null, body.region,
       body.office, body.office_etc || null,
       body.agree_marketing ? 1 : 0]);

    // 웰컴기프트 지급 대기 등록 (uk_welcome 은 트리거가 채운다)
    await tx.query(
      `INSERT INTO ?? (carmaster_id, type, item_name, amount, status)
       VALUES (?, 'welcome', ?, 5000, 'pending')`,
      [db.T.REWARDS, carmasterId, 'SK 주유/아이파킹 전기충전권 5,000원']);
  });

  log('signup_succeeded');

  const r = await auth.login(loginId, body.password);
  const me = await auth.getMyProfile(r.user.id);
  return { ok: true, token: r.token, user: r.user, carmaster: me };
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
    // ───── 상태 확인 ─────
    if (path === '/health') {
      return sendJson(res, 200, { ok: true, attempts: attempts.size });
    }

    // ───── NICE 본인인증 시작 ─────
    if (path === '/v1/verify/start' && req.method === 'POST') {
      if (!rateAllow('v:' + ip, RATE_VERIFY_MIN, RATE_VERIFY_10MIN)) {
        log('rate_limited', { kind: 'verify' });
        return sendJson(res, 429, { ok: false, message: '요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.' });
      }
      const attemptId = crypto.randomUUID();
      const { authUrl, transactionId, requestNo } = await requestAuthUrl(attemptId);
      attempts.set(attemptId, {
        state: 'url_issued', transactionId, requestNo,
        expiresAt: Date.now() + ATTEMPT_TTL_MS, result: null
      });
      log('verify_started', { attempt: attemptId.slice(0, 8) });
      return sendJson(res, 200, {
        attempt_id: attemptId, auth_url: authUrl, expires_in: ATTEMPT_TTL_MS / 1000
      });
    }

    // ───── NICE 리턴 ─────
    if (path.startsWith('/return/')) {
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
        log('result_error', { code: err.message });
        return sendHtml(res, 200, popupPage('인증 처리 중 오류가 발생했습니다', '잠시 후 다시 시도해 주세요.', false));
      }

      const mobile = String(info.mobile_no || '').replace(/\D/g, '');
      attempt.state = 'verified';
      attempt.result = {
        name: info.name || '', phone: mobile, phone_last4: mobile.slice(-4),
        di_hash: hashDi(String(info.di || '')), verified_at: new Date().toISOString()
      };
      log('verify_succeeded', { attempt: attemptId.slice(0, 8) });
      return sendHtml(res, 200, popupPage('본인인증이 완료되었습니다', '잠시 후 창이 닫힙니다.', true));
    }

    if (path === '/close') {
      return sendHtml(res, 200, popupPage('인증이 취소되었습니다', '창을 닫아 주세요.', false));
    }

    // ───── NICE 결과 폴링 ─────
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
      const now = Math.floor(Date.now() / 1000);
      const token = signNiceToken({
        iss: 'rayno-carmaster-auth', aid: attemptId,
        name: r.name, phone: r.phone, phone_last4: r.phone_last4,
        di_hash: r.di_hash, verified_at: r.verified_at,
        iat: now, exp: now + NICE_TOKEN_TTL_SEC
      });
      attempts.delete(attemptId);
      return sendJson(res, 200, {
        status: 'verified', token, name: r.name, phone_last4: r.phone_last4
      });
    }

    // ───── 아이디 중복확인 ─────
    if (path === '/v1/auth/check-id' && req.method === 'POST') {
      const body = await readJsonBody(req);
      const id = String(body.login_id || '').trim();
      try { auth.checkLoginIdFormat(id); }
      catch (e) { return sendJson(res, 200, { ok: false, message: e.message }); }
      const free = await auth.isLoginIdAvailable(id);
      return sendJson(res, 200, {
        ok: free,
        message: free ? '사용 가능한 아이디입니다.' : '이미 사용 중인 아이디입니다.'
      });
    }

    // ───── 회원가입 ─────
    if (path === '/v1/auth/signup' && req.method === 'POST') {
      log('signup_requested');
      const body = await readJsonBody(req);
      const out = await doSignup(body);
      return sendJson(res, 200, out);
    }

    // ───── 로그인 ─────
    if (path === '/v1/auth/login' && req.method === 'POST') {
      if (!rateAllow('l:' + ip, RATE_LOGIN_MIN, 40)) {
        log('rate_limited', { kind: 'login' });
        return sendJson(res, 429, { ok: false, message: '로그인 시도가 너무 많습니다. 잠시 후 다시 시도해 주세요.' });
      }
      const body = await readJsonBody(req);
      const r = await auth.login(body.login_id, body.password);
      const me = await auth.getMyProfile(r.user.id);
      log('login_succeeded');
      return sendJson(res, 200, { ok: true, token: r.token, user: r.user, carmaster: me });
    }

    // ───── 내 정보 ─────
    if (path === '/v1/auth/me' && req.method === 'GET') {
      const p = auth.authFromHeader(req);
      const me = await auth.getMyProfile(p.sub);
      const isAdm = await auth.isAdmin(p.sub);
      return sendJson(res, 200, {
        ok: true,
        user: { id: p.sub, role: p.role, is_admin: isAdm },
        carmaster: me
      });
    }

    // ───── 아이디 찾기 (NICE 인증 필요) ─────
    if (path === '/v1/auth/find-id' && req.method === 'POST') {
      if (!rateAllow('f:' + ip, 5, 20)) {
        return sendJson(res, 429, { ok: false, message: '요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.' });
      }
      const body = await readJsonBody(req);
      const v = verifyNiceToken(body.nice_token);
      const rows = await db.query(
        'SELECT login_id FROM ?? WHERE di_hash = ? LIMIT 1',
        [db.T.CARMASTERS, v.di_hash]);
      if (!rows.length) {
        return sendJson(res, 404, { ok: false, message: '가입 정보를 찾을 수 없습니다.' });
      }
      const lid = rows[0].login_id || '';
      log('find_id_succeeded');
      return sendJson(res, 200, {
        ok: true,
        loginId: lid.slice(0, 3) + '*'.repeat(Math.max(lid.length - 3, 1))
      });
    }

    // ───── 비밀번호 재설정 (NICE 인증 필요) ─────
    if (path === '/v1/auth/reset-pw' && req.method === 'POST') {
      if (!rateAllow('r:' + ip, 5, 20)) {
        return sendJson(res, 429, { ok: false, message: '요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.' });
      }
      const body = await readJsonBody(req);
      const v = verifyNiceToken(body.nice_token);
      auth.checkPasswordFormat(body.password);

      const rows = await db.query(
        'SELECT user_id, login_id FROM ?? WHERE di_hash = ? LIMIT 1',
        [db.T.CARMASTERS, v.di_hash]);
      if (!rows.length) {
        return sendJson(res, 404, { ok: false, message: '가입 정보를 찾을 수 없습니다.' });
      }
      const inputId = String(body.login_id || '').trim();
      if (inputId && inputId !== rows[0].login_id) {
        return sendJson(res, 400, { ok: false, message: '아이디가 일치하지 않습니다.' });
      }
      await auth.changePassword(rows[0].user_id, body.password);
      log('reset_pw_succeeded');
      return sendJson(res, 200, { ok: true });
    }

    // ───── 마이페이지 요약 ─────
    if (path === '/v1/me/summary' && req.method === 'GET') {
      const p = auth.authFromHeader(req);
      const d = db.decExpr('c.phone', 'phone');
      const rows = await db.query(
        `SELECT c.id, c.code, c.login_id, c.name, c.status, c.brand, c.region, c.office,
                c.phone_last4, ${d.sql}
           FROM ?? c WHERE c.user_id = ? LIMIT 1`,
        [...d.params, db.T.CARMASTERS, p.sub]);
      if (!rows.length) return sendJson(res, 404, { ok: false, message: '회원 정보를 찾을 수 없습니다.' });
      const me = rows[0];

      const [stat] = await db.query(
        `SELECT
           COUNT(CASE WHEN status='valid'
                       AND DATE_FORMAT(installed_at,'%Y-%m') = DATE_FORMAT(UTC_DATE(),'%Y-%m')
                      THEN 1 END) AS month_count,
           COUNT(CASE WHEN status='valid' THEN 1 END) AS total_count
         FROM ?? WHERE carmaster_id = ? AND link_type = 'linked'`,
        [db.T.WARRANTY_MATCHES, me.id]);

      const [cp] = await db.query(
        `SELECT COUNT(*) AS n FROM ?? WHERE carmaster_id = ? AND status = 'issued'`,
        [db.T.COUPONS, me.id]);

      const rules = await db.query(
        `SELECT min_count, item_name FROM ?? WHERE active = 1 ORDER BY min_count ASC`,
        [db.T.REWARD_RULES]);
      const total = Number(stat.total_count || 0);
      const next = rules.find(r => Number(r.min_count) > total) || rules[rules.length - 1] || null;

      const phone = String(me.phone || '').replace(/\D/g, '');
      const masked = phone.length >= 7
        ? phone.slice(0, 3) + '-****-' + phone.slice(-4)
        : (me.phone_last4 ? '010-****-' + me.phone_last4 : '—');

      return sendJson(res, 200, {
        ok: true,
        code: me.code, login_id: me.login_id, name: me.name, status: me.status,
        brand: me.brand, region: me.region, office: me.office,
        phone_masked: masked,
        month_count: Number(stat.month_count || 0),
        total_count: total,
        coupons: Number(cp.n || 0),
        goal: next ? Number(next.min_count) : 10,
        goal_name: next ? next.item_name : ''
      });
    }

    // ───── 내 리워드 내역 ─────
    if (path === '/v1/me/rewards' && req.method === 'GET') {
      const p = auth.authFromHeader(req);
      const rows = await db.query(
        `SELECT r.item_name, r.status, r.type, r.created_at
           FROM ?? r JOIN ?? c ON c.id = r.carmaster_id
          WHERE c.user_id = ? ORDER BY r.created_at DESC LIMIT 100`,
        [db.T.REWARDS, db.T.CARMASTERS, p.sub]);
      return sendJson(res, 200, { ok: true, items: rows });
    }

    // ───── 내 시공 내역 ─────
    if (path === '/v1/me/records' && req.method === 'GET') {
      const p = auth.authFromHeader(req);
      const rows = await db.query(
        `SELECT w.car_model, w.dealer_name, w.installed_at, w.matched_at AS created_at,
                w.status, w.link_type
           FROM ?? w JOIN ?? c ON c.id = w.carmaster_id
          WHERE c.user_id = ? ORDER BY w.installed_at DESC LIMIT 200`,
        [db.T.WARRANTY_MATCHES, db.T.CARMASTERS, p.sub]);
      return sendJson(res, 200, { ok: true, items: rows });
    }

    // ───── 소속 정보 수정 ─────
    if (path === '/v1/me/profile' && req.method === 'POST') {
      const p = auth.authFromHeader(req);
      const body = await readJsonBody(req);
      if (!body.brand || !body.region || !body.office) {
        throw new Error('소속 정보를 모두 선택해 주세요.');
      }
      const r = await db.execute(
        `UPDATE ?? SET brand = ?, region = ?, office = ? WHERE user_id = ?`,
        [db.T.CARMASTERS, body.brand, body.region, body.office, p.sub]);
      if (!r.affectedRows) throw new Error('회원 정보를 찾을 수 없습니다.');
      log('profile_updated');
      return sendJson(res, 200, { ok: true });
    }

    // ───── 소속 지점 목록 ─────
    if (path === '/v1/offices' && req.method === 'GET') {
      const rows = await db.query(
        'SELECT brand, region, name FROM ?? WHERE active = 1 ORDER BY brand, region, name',
        [db.T.OFFICES]);
      const tree = {};
      for (const r of rows) {
        tree[r.brand] = tree[r.brand] || {};
        tree[r.brand][r.region] = tree[r.brand][r.region] || [];
        tree[r.brand][r.region].push(r.name);
      }
      return sendJson(res, 200, { ok: true, tree, count: rows.length });
    }

    // ───── 공지사항 ─────
    if (path === '/v1/notices' && req.method === 'GET') {
      const rows = await db.query(
        'SELECT id, title, body, target, created_at FROM ?? WHERE published = 1 ORDER BY created_at DESC LIMIT 50',
        [db.T.NOTICES]);
      return sendJson(res, 200, { ok: true, items: rows });
    }

    // ───── 프로모션 ─────
    if (path === '/v1/promotions' && req.method === 'GET') {
      const rows = await db.query(
        'SELECT id, name, cond, threshold_n, reward, period, achieved FROM ?? WHERE active = 1 ORDER BY created_at DESC',
        [db.T.PROMOTIONS]);
      return sendJson(res, 200, { ok: true, items: rows });
    }

    return sendJson(res, 404, { ok: false, message: '알 수 없는 요청입니다.' });

  } catch (err) {
    const status = err.status || 400;
    // 어느 창구에서 왜 거절됐는지 기록한다 (개인정보는 담지 않는다)
    db.log('api_error', {
      path: path,
      status: status,
      msg: String((err && err.message) || '').slice(0, 120)
    });
    // DB 내부 오류 문구는 사용자에게 그대로 보여주지 않는다 (로그에는 남는다)
    const isDbError = !!(err && typeof err.code === 'string' && err.code.startsWith('ER_'));
    return sendJson(res, status, {
      ok: false,
      message: isDbError
        ? '처리 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.'
        : (err.message || '처리 중 오류가 발생했습니다.')
    });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  log('server_started', { port: PORT });
});
