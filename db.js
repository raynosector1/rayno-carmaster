'use strict';
/**
 * 레이노 카마스터 — MySQL 연결 및 개인정보 암복호화 공용 모듈
 *
 * 설계 원칙 (박인준 팀장 마이그레이션 문서 준수)
 *   - 가비아 MySQL 5.6에 직접 연결 (PHP API 경유하지 않음)
 *   - 접속 정보·암호화 키는 코드에 없음 (AWS SSM Parameter Store에서 기동 시 1회 로드)
 *   - 모든 쿼리는 Prepared Statement / 파라미터 바인딩 (SQL Injection 방지)
 *   - 개인정보(phone·email)는 레이노 본 DB와 동일한 MySQL AES 방식으로 저장
 *       저장: HEX(AES_ENCRYPT(?, ?))
 *       조회: CAST(AES_DECRYPT(UNHEX(컬럼), ?) AS CHAR)
 *   - 비밀번호는 AES 대상 아님 (해시 유지)
 *   - 암호화 키·평문 개인정보는 로그에 남기지 않음
 *   - 시각은 UTC 기준으로 저장 (MySQL DATETIME은 시간대 정보 없음)
 */

const mysql = require('mysql2/promise');
const { execFileSync } = require('child_process');

const REGION = 'ap-northeast-2';
const SSM_PREFIX = '/rayno/carmaster/db';

// ─────────────────────────────────────────────
// 테이블명 상수  ★코드 전체에서 이 상수만 사용할 것★
//   문자열을 직접 쓰지 않으면 나중에 이름이 바뀌어도 여기만 고치면 됩니다.
// ─────────────────────────────────────────────
const T = Object.freeze({
  APP_USERS:        'rk_carmaster_app_users',
  DEALERS:          'rk_carmaster_dealers',
  OFFICES:          'rk_carmaster_offices',
  REWARD_RULES:     'rk_carmaster_reward_rules',
  NOTICES:          'rk_carmaster_notices',
  PROMOTIONS:       'rk_carmaster_promotions',
  ADMINS:           'rk_carmaster_admins',
  CODE_SEQ:         'rk_carmaster_code_seq',
  CARMASTERS:       'rk_carmaster_carmasters',
  REWARDS:          'rk_carmaster_rewards',
  COUPONS:          'rk_carmaster_coupons',
  WARRANTY_MATCHES: 'rk_carmaster_warranty_matches'
});

// ─────────────────────────────────────────────
// SSM에서 비밀값 로드
// ─────────────────────────────────────────────
function ssmGet(name, optional = false) {
  try {
    const v = execFileSync('aws', [
      'ssm', 'get-parameter',
      '--name', name,
      '--with-decryption',
      '--region', REGION,
      '--query', 'Parameter.Value',
      '--output', 'text'
    ], { encoding: 'utf8', timeout: 15000 }).trim();
    return (v && v !== 'None') ? v : null;
  } catch (e) {
    if (optional) return null;
    throw new Error(`SSM 파라미터를 읽지 못했습니다: ${name}`);
  }
}

let CONFIG = null;
function loadConfig() {
  if (CONFIG) return CONFIG;
  CONFIG = {
    host:     ssmGet(`${SSM_PREFIX}/host`),
    port:     Number(ssmGet(`${SSM_PREFIX}/port`, true) || 3306),
    user:     ssmGet(`${SSM_PREFIX}/user`),
    password: ssmGet(`${SSM_PREFIX}/password`),
    database: ssmGet(`${SSM_PREFIX}/name`, true),   // 접속 후 확인되면 등록
    encKey:   ssmGet(`${SSM_PREFIX}/encrypt-key`)
  };
  for (const k of ['host', 'user', 'password', 'encKey']) {
    if (!CONFIG[k]) throw new Error(`필수 설정값이 비어 있습니다: ${k}`);
  }
  return CONFIG;
}

// ─────────────────────────────────────────────
// 커넥션 풀
// ─────────────────────────────────────────────
let pool = null;
function getPool() {
  if (pool) return pool;
  const c = loadConfig();
  pool = mysql.createPool({
    host: c.host,
    port: c.port,
    user: c.user,
    password: c.password,
    database: c.database || undefined,
    charset: 'utf8mb4_unicode_ci',
    timezone: 'Z',              // UTC 기준 저장·조회
    connectionLimit: 10,
    waitForConnections: true,
    queueLimit: 0,
    dateStrings: false,
    connectTimeout: 10000,
    // MySQL 5.6 호환: 서버가 지원하지 않는 신규 인증 플러그인 협상 방지
    insecureAuth: false
  });
  return pool;
}

/** 암호화 키 (SQL 파라미터로만 전달, 로그 금지) */
function encKey() {
  return loadConfig().encKey;
}

// ─────────────────────────────────────────────
// 쿼리 실행
// ─────────────────────────────────────────────

/**
 * SELECT 실행. 항상 파라미터 바인딩을 사용합니다.
 *   const rows = await query('SELECT * FROM ?? WHERE id = ?', [T.CARMASTERS, id]);
 *   ?? = 식별자(테이블·컬럼명),  ? = 값
 */
async function query(sql, params = []) {
  const [rows] = await getPool().query(sql, params);
  return rows;
}

/** INSERT / UPDATE / DELETE 실행. affectedRows, insertId 등을 반환 */
async function execute(sql, params = []) {
  const [result] = await getPool().query(sql, params);
  return result;
}

/**
 * 트랜잭션. 콜백 안에서 오류가 나면 자동 롤백됩니다.
 *
 *   await withTransaction(async (tx) => {
 *     await tx.query('INSERT ...', [...]);
 *     await tx.query('UPDATE ...', [...]);
 *   });
 */
async function withTransaction(fn) {
  const conn = await getPool().getConnection();
  try {
    await conn.beginTransaction();
    const result = await fn({
      query: async (sql, params = []) => {
        const [rows] = await conn.query(sql, params);
        return rows;
      }
    });
    await conn.commit();
    return result;
  } catch (err) {
    try { await conn.rollback(); } catch (_) { /* 롤백 실패는 원 오류를 가리지 않는다 */ }
    throw err;
  } finally {
    conn.release();
  }
}

// ─────────────────────────────────────────────
// 개인정보 암복호화 (레이노 본 DB 방식)
// ─────────────────────────────────────────────

/**
 * 저장·수정용 SQL 조각.
 *   const p = encParam('01012345678');
 *   sql: `INSERT INTO ?? (phone) VALUES (${p.sql})`
 *   params: [T.CARMASTERS, ...p.params]
 *
 * 값이 null이거나 빈 문자열이면 NULL을 저장합니다(빈 값을 암호화하지 않음).
 */
function encParam(plainValue) {
  if (plainValue === null || plainValue === undefined || plainValue === '') {
    return { sql: 'NULL', params: [] };
  }
  return { sql: 'HEX(AES_ENCRYPT(?, ?))', params: [String(plainValue), encKey()] };
}

/**
 * 조회용 SQL 조각. 복호화된 평문을 반환합니다.
 *   const d = decExpr('c.phone', 'phone');
 *   sql: `SELECT ${d.sql} FROM ...`
 *   params: [...d.params, ...]
 */
function decExpr(columnExpr, alias) {
  return {
    sql: `CAST(AES_DECRYPT(UNHEX(${columnExpr}), ?) AS CHAR)` + (alias ? ` AS ${alias}` : ''),
    params: [encKey()]
  };
}

/**
 * 정확히 일치하는 값으로 검색할 때 쓰는 SQL 조각.
 * MySQL AES_ENCRYPT는 같은 평문·같은 키면 항상 같은 결과가 나오므로
 * 복호화하지 않고 암호문끼리 비교할 수 있습니다(인덱스 사용 가능).
 *
 *   const w = encMatch('phone', '01012345678');
 *   sql: `SELECT ... WHERE ${w.sql}`
 */
function encMatch(columnExpr, plainValue) {
  return {
    sql: `${columnExpr} = HEX(AES_ENCRYPT(?, ?))`,
    params: [String(plainValue), encKey()]
  };
}

/**
 * 휴대폰 뒤 4자리로 검색할 때 쓰는 SQL 조각.
 *
 * ※ 암호문의 뒤 4자리는 의미가 없으므로 복호화 후 비교해야 합니다.
 *   인덱스를 사용할 수 없어 전체 행을 훑습니다(카마스터 수천 명 규모에서는 문제없음).
 *   팀장님 문서상 평문 보조 컬럼 추가가 금지되어 이 방식으로 처리합니다.
 */
function phoneLast4Match(columnExpr, last4) {
  return {
    sql: `RIGHT(CAST(AES_DECRYPT(UNHEX(${columnExpr}), ?) AS CHAR), 4) = ?`,
    params: [encKey(), String(last4)]
  };
}

// ─────────────────────────────────────────────
// 안전한 로그 (개인정보·키 절대 금지)
// ─────────────────────────────────────────────
function log(event, extra) {
  console.log(JSON.stringify({
    t: new Date().toISOString(),
    event,
    ...(extra || {})
  }));
}

/** 오류를 로그에 남길 때는 메시지만. 응답 본문·쿼리값은 남기지 않는다. */
function logError(event, err) {
  console.error(JSON.stringify({
    t: new Date().toISOString(),
    event,
    code: (err && err.code) ? err.code : 'UNKNOWN',
    msg: (err && err.message) ? String(err.message).slice(0, 200) : ''
  }));
}

async function close() {
  if (pool) { await pool.end(); pool = null; }
}

module.exports = {
  T,
  query, execute, withTransaction,
  encParam, decExpr, encMatch, phoneLast4Match,
  log, logError, close,
  loadConfig, getPool
};
