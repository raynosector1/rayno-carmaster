'use strict';
/**
 * 레이노 카마스터 — 로그인 / 세션 모듈  (Supabase Auth 대체)
 *
 * 설계
 *   - 비밀번호는 scrypt 로 해시하여 저장. 되돌릴 수 없음(AES 암호화 대상 아님)
 *   - 로그인 성공 시 서버만 서명할 수 있는 출입증(토큰)을 발급
 *   - 토큰에는 개인정보를 담지 않는다 (계정 ID와 권한만)
 *   - 서명 키는 SSM Parameter Store 에서 로드
 *
 * 외부 라이브러리를 쓰지 않습니다. Node 내장 crypto 만 사용합니다.
 */

const crypto = require('crypto');
const { execFileSync } = require('child_process');
const db = require('./db');

const REGION = 'ap-northeast-2';
const TOKEN_TTL_SEC = 12 * 60 * 60;   // 출입증 유효시간 12시간
const ISS = 'rayno-carmaster';

// ─────────────────────────────────────────────
// 서명 키 (SSM)
// ─────────────────────────────────────────────
let SESSION_KEY = null;
function sessionKey() {
  if (SESSION_KEY) return SESSION_KEY;
  SESSION_KEY = execFileSync('aws', [
    'ssm', 'get-parameter',
    '--name', '/rayno/carmaster/session-key',
    '--with-decryption',
    '--region', REGION,
    '--query', 'Parameter.Value',
    '--output', 'text'
  ], { encoding: 'utf8', timeout: 15000 }).trim();
  if (!SESSION_KEY || SESSION_KEY === 'None') {
    throw new Error('세션 서명 키를 읽지 못했습니다.');
  }
  return SESSION_KEY;
}

const b64u = (buf) =>
  Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uDecode = (s) =>
  Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

// ─────────────────────────────────────────────
// 비밀번호 해시  (scrypt)
//   저장 형식: scrypt$N$r$p$salt$hash   (모두 base64url)
// ─────────────────────────────────────────────
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };

function hashPassword(plain) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(plain), salt, SCRYPT.keylen, {
    N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 64 * 1024 * 1024
  });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, b64u(salt), b64u(hash)].join('$');
}

function verifyPassword(plain, stored) {
  try {
    const parts = String(stored || '').split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const [, N, r, p, saltB64, hashB64] = parts;
    const salt = b64uDecode(saltB64);
    const expected = b64uDecode(hashB64);
    const actual = crypto.scryptSync(String(plain), salt, expected.length, {
      N: Number(N), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024
    });
    // 타이밍 공격 방지를 위해 길이 비교 후 상수시간 비교
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch (_) {
    return false;
  }
}

// ─────────────────────────────────────────────
// 출입증 (HS256 서명 토큰)
// ─────────────────────────────────────────────
function issueToken(payload) {
  const header = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const body = b64u(JSON.stringify({
    ...payload, iss: ISS, iat: now, exp: now + TOKEN_TTL_SEC
  }));
  const sig = b64u(crypto.createHmac('sha256', sessionKey())
    .update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('로그인이 필요합니다.');
  const [h, b, sig] = parts;

  const calc = b64u(crypto.createHmac('sha256', sessionKey())
    .update(`${h}.${b}`).digest());
  if (calc.length !== sig.length ||
      !crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(sig))) {
    throw new Error('로그인 정보가 올바르지 않습니다.');
  }

  const p = JSON.parse(b64uDecode(b).toString('utf8'));
  if (p.iss !== ISS) throw new Error('로그인 정보가 올바르지 않습니다.');
  if (Math.floor(Date.now() / 1000) > Number(p.exp || 0)) {
    throw new Error('로그인이 만료되었습니다. 다시 로그인해 주세요.');
  }
  return p;
}

/** HTTP 요청 헤더에서 출입증을 꺼내 검증 */
function authFromHeader(req) {
  const raw = req.headers['authorization'] || '';
  const m = raw.match(/^Bearer\s+(.+)$/i);
  if (!m) throw new Error('로그인이 필요합니다.');
  return verifyToken(m[1]);
}

// ─────────────────────────────────────────────
// 아이디 규칙
// ─────────────────────────────────────────────
const LOGIN_ID_RE = /^(?=.*[a-z])(?=.*\d)[a-z0-9_]{4,20}$/;
const PASSWORD_MIN = 6;

function checkLoginIdFormat(id) {
  if (!LOGIN_ID_RE.test(String(id || ''))) {
    throw new Error('아이디는 영문 소문자와 숫자를 조합해 4~20자로 입력해 주세요.');
  }
}
function checkPasswordFormat(pw) {
  const s = String(pw || '');
  if (s.length < PASSWORD_MIN) throw new Error('비밀번호는 6자 이상이어야 합니다.');
  if (!/[a-zA-Z]/.test(s) || !/\d/.test(s) || !/[^a-zA-Z0-9]/.test(s)) {
    throw new Error('비밀번호는 영문·숫자·특수문자를 모두 포함해야 합니다.');
  }
}

// ─────────────────────────────────────────────
// 계정 조회 / 생성
// ─────────────────────────────────────────────

/** 아이디 사용 가능 여부 */
async function isLoginIdAvailable(loginId) {
  const rows = await db.query(
    'SELECT id FROM ?? WHERE login_id = ? LIMIT 1',
    [db.T.APP_USERS, String(loginId).trim()]
  );
  return rows.length === 0;
}

/**
 * 계정 생성. 이미 열린 트랜잭션 안에서 쓰려면 tx 를 넘긴다.
 * 반환값: 새 계정의 id (UUID)
 */
async function createAccount({ loginId, password, role = 'carmaster' }, tx = null) {
  checkLoginIdFormat(loginId);
  checkPasswordFormat(password);

  const id = crypto.randomUUID();
  const sql = 'INSERT INTO ?? (id, login_id, password_hash, role) VALUES (?, ?, ?, ?)';
  const params = [db.T.APP_USERS, id, String(loginId).trim(), hashPassword(password), role];

  if (tx) await tx.query(sql, params);
  else await db.execute(sql, params);

  return id;
}

/** 비밀번호 변경 */
async function changePassword(userId, newPassword) {
  checkPasswordFormat(newPassword);
  const r = await db.execute(
    'UPDATE ?? SET password_hash = ? WHERE id = ?',
    [db.T.APP_USERS, hashPassword(newPassword), userId]
  );
  if (!r.affectedRows) throw new Error('계정을 찾을 수 없습니다.');
}

/**
 * 로그인.
 * 성공하면 { token, user } 반환. 실패 사유는 구분해서 알려주지 않는다
 * (아이디가 있는지 없는지 노출하지 않기 위함).
 */
async function login(loginId, password) {
  const rows = await db.query(
    'SELECT id, login_id, password_hash, role, banned_at FROM ?? WHERE login_id = ? LIMIT 1',
    [db.T.APP_USERS, String(loginId || '').trim()]
  );

  const u = rows[0];
  const ok = u && verifyPassword(password, u.password_hash);
  if (!ok) throw new Error('아이디 또는 비밀번호가 올바르지 않습니다.');
  if (u.banned_at) throw new Error('정지된 계정입니다. 관리자에게 문의해 주세요.');

  // 마지막 로그인 시각 기록 (실패해도 로그인은 막지 않는다)
  try {
    await db.execute('UPDATE ?? SET last_login_at = UTC_TIMESTAMP() WHERE id = ?',
      [db.T.APP_USERS, u.id]);
  } catch (e) {
    db.logError('last_login_update_failed', e);
  }

  const isAdminUser = await isAdmin(u.id);

  return {
    token: issueToken({ sub: u.id, role: u.role, adm: isAdminUser ? 1 : 0 }),
    user: { id: u.id, login_id: u.login_id, role: u.role, is_admin: isAdminUser }
  };
}

/** 관리자 여부 — 토큰만 믿지 않고 매 요청마다 DB로 재확인할 때 사용 */
async function isAdmin(userId) {
  const rows = await db.query('SELECT user_id FROM ?? WHERE user_id = ? LIMIT 1',
    [db.T.ADMINS, userId]);
  return rows.length > 0;
}

/** 관리자 전용 API 앞에서 호출. 아니면 오류를 던진다. */
async function requireAdmin(req) {
  const p = authFromHeader(req);
  if (!(await isAdmin(p.sub))) throw new Error('권한이 없습니다.');
  return p;
}

/** 로그인한 카마스터 본인 정보 (개인정보는 복호화해서 반환) */
async function getMyProfile(userId) {
  const d = db.decExpr('c.phone', 'phone');
  const rows = await db.query(
    `SELECT c.id, c.code, c.login_id, c.name, ${d.sql}, c.phone_last4,
            c.status, c.brand, c.region, c.office,
            c.agree_marketing, c.sms_optout, c.verified_at, c.created_at
       FROM ?? c
      WHERE c.user_id = ? LIMIT 1`,
    [...d.params, db.T.CARMASTERS, userId]
  );
  return rows[0] || null;
}

module.exports = {
  hashPassword, verifyPassword,
  issueToken, verifyToken, authFromHeader,
  checkLoginIdFormat, checkPasswordFormat,
  isLoginIdAvailable, createAccount, changePassword,
  login, isAdmin, requireAdmin, getMyProfile
};
