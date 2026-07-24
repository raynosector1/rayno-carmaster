'use strict';
/**
 * 레이노 본 DB 암복호화 방식 판별 도구  (읽기 전용 — DB를 변경하지 않습니다)
 *
 * 하는 일
 *   1) 우리 계정이 읽을 수 있는 레이노 테이블 중 개인정보로 보이는 컬럼을 찾는다
 *   2) 그 값에 대해 AES 키 가공 방식 후보를 전부 대입해 복호화를 시도한다
 *   3) 사람이 읽히는 값(전화번호·이메일·한글 이름)이 나오는 방식을 정답으로 보고한다
 *
 * 사용법
 *   node find-aes.js
 *   node find-aes.js <테이블명> <컬럼명>        ← 특정 컬럼만 확인
 *   node find-aes.js --hex <암호문HEX> <평문>   ← 팀장님이 샘플값을 주신 경우
 */

const db = require('./db');

/* 키 가공 방식 후보 — MySQL 표현식 */
const DERIVATIONS = [
  { id: 'raw',        sql: '?',                 desc: "키 문자열 그대로  (현재 카마스터 방식)" },
  { id: 'sha2-512',   sql: 'SHA2(?,512)',       desc: "SHA2(키,512) 문자열" },
  { id: 'sha2-512-u', sql: 'UNHEX(SHA2(?,512))',desc: "UNHEX(SHA2(키,512)) 바이너리" },
  { id: 'sha2-256',   sql: 'SHA2(?,256)',       desc: "SHA2(키,256) 문자열" },
  { id: 'sha2-256-u', sql: 'UNHEX(SHA2(?,256))',desc: "UNHEX(SHA2(키,256)) 바이너리" },
  { id: 'sha2-384',   sql: 'SHA2(?,384)',       desc: "SHA2(키,384) 문자열" },
  { id: 'sha2-224',   sql: 'SHA2(?,224)',       desc: "SHA2(키,224) 문자열" },
  { id: 'md5',        sql: 'MD5(?)',            desc: "MD5(키) 문자열" },
  { id: 'md5-u',      sql: 'UNHEX(MD5(?))',     desc: "UNHEX(MD5(키)) 바이너리" },
  { id: 'sha1',       sql: 'SHA1(?)',           desc: "SHA1(키) 문자열" },
  { id: 'sha1-u',     sql: 'UNHEX(SHA1(?))',    desc: "UNHEX(SHA1(키)) 바이너리" }
];

/* 저장 형태 후보 */
const STORAGE = [
  { id: 'hex',  wrap: (c) => `UNHEX(${c})`, desc: 'HEX 문자열로 저장' },
  { id: 'blob', wrap: (c) => c,             desc: '바이너리 그대로 저장' }
];

const line = (s) => console.log(s);
const head = (s) => { console.log(''); console.log('── ' + s + ' ' + '─'.repeat(Math.max(0, 56 - s.length))); };

/* 복호화 결과가 "사람이 읽히는 값"인지 판정 */
function looksReal(v) {
  if (v === null || v === undefined) return false;
  const s = String(v).trim();
  if (s.length < 4 || s.length > 200) return false;
  if (/^0\d{1,2}-?\d{3,4}-?\d{4}$/.test(s)) return { kind: '전화번호', s };
  if (/^[\w.+-]+@[\w-]+\.[\w.]+$/.test(s)) return { kind: '이메일', s };
  if (/^[가-힣]{2,6}$/.test(s)) return { kind: '한글 이름', s };
  if (/^[\x20-\x7E가-힣]+$/.test(s)) return { kind: '읽히는 문자열', s };
  return false;
}

/* 마스킹해서 출력 (원문 그대로 찍지 않음) */
function mask(s) {
  s = String(s);
  if (s.length <= 4) return s[0] + '*'.repeat(s.length - 1);
  return s.slice(0, 3) + '*'.repeat(Math.max(1, s.length - 7)) + s.slice(-4);
}

async function tryAll(colExpr, params) {
  const hits = [];
  const key = db.loadConfig().encKey;
  for (const st of STORAGE) {
    for (const d of DERIVATIONS) {
      const sql = `SELECT CAST(AES_DECRYPT(${st.wrap(colExpr)}, ${d.sql}) AS CHAR) AS v`;
      try {
        const rows = await db.query(sql, [...params, key]);
        const hit = looksReal(rows[0] && rows[0].v);
        if (hit) hits.push({ storage: st, deriv: d, kind: hit.kind, sample: hit.s });
      } catch (e) { /* 복호화 실패는 정상 — 다음 후보로 */ }
    }
  }
  return hits;
}

(async () => {
  line('레이노 본 DB 암복호화 방식 판별  (읽기 전용)');

  const args = process.argv.slice(2);

  /* ── 모드 A: 팀장님이 샘플값을 주신 경우 ── */
  if (args[0] === '--hex') {
    const cipherHex = args[1], plain = args[2];
    if (!cipherHex || !plain) { line('사용법: node find-aes.js --hex <암호문HEX> <평문>'); process.exit(1); }
    head('샘플값 대조');
    const key = db.loadConfig().encKey;
    let found = null;
    for (const d of DERIVATIONS) {
      try {
        const rows = await db.query(`SELECT HEX(AES_ENCRYPT(?, ${d.sql})) AS enc`, [plain, key]);
        const ok = String(rows[0].enc).toUpperCase() === String(cipherHex).toUpperCase();
        line(`   ${ok ? '★ 일치' : '  불일치'}  ${d.id.padEnd(11)} ${d.desc}`);
        if (ok) found = d;
      } catch (e) { line(`   오류    ${d.id.padEnd(11)} ${e.message}`); }
    }
    head('결과');
    line(found ? `   정답: ${found.id}  →  AES_ENCRYPT(값, ${found.sql.replace('?', '키')})`
               : '   일치하는 방식이 없습니다. 키 값이 서로 다르거나 다른 가공을 씁니다.');
    await db.close();
    return;
  }

  /* ── 모드 B: 특정 컬럼 지정 ── */
  let targets = [];
  if (args.length >= 2) {
    targets = [{ table: args[0], column: args[1] }];
  } else {
    /* ── 모드 C: 읽을 수 있는 레이노 테이블에서 자동 탐색 ── */
    head('1. 우리 계정이 읽을 수 있는 개인정보 컬럼 찾기');
    const rows = await db.query(
      `SELECT TABLE_NAME AS t, COLUMN_NAME AS c
         FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME NOT LIKE 'rk\\_carmaster\\_%'
          AND ( COLUMN_NAME LIKE '%phone%' OR COLUMN_NAME LIKE '%mobile%'
             OR COLUMN_NAME LIKE '%hp%'    OR COLUMN_NAME LIKE '%tel%'
             OR COLUMN_NAME LIKE '%email%' OR COLUMN_NAME LIKE '%name%' )
          AND DATA_TYPE IN ('varchar','char','text','blob','varbinary','tinyblob')
        ORDER BY TABLE_NAME, COLUMN_NAME
        LIMIT 60`, []);
    if (!rows.length) {
      line('   후보 없음 — 레이노 테이블에 대한 조회 권한이 아직 없습니다.');
      line('   → 팀장님께 샘플값을 받아 --hex 모드로 확인하세요.');
      await db.close();
      return;
    }
    rows.forEach(r => line(`   - ${r.t}.${r.c}`));
    targets = rows.map(r => ({ table: r.t, column: r.c }));
  }

  head('2. 후보 방식 대입');
  let answer = null;
  for (const t of targets) {
    let vals = [];
    try {
      vals = await db.query(
        `SELECT \`${t.column}\` AS v FROM \`${t.table}\`
          WHERE \`${t.column}\` IS NOT NULL AND \`${t.column}\` <> '' LIMIT 1`, []);
    } catch (e) { continue; }
    if (!vals.length) continue;

    const hits = await tryAll('?', [vals[0].v]);
    if (hits.length) {
      line(`   ${t.table}.${t.column}`);
      for (const h of hits) {
        line(`      ★ ${h.deriv.id.padEnd(11)} ${h.storage.desc.padEnd(16)} → ${h.kind}: ${mask(h.sample)}`);
        if (!answer) answer = h;
      }
    }
  }

  head('3. 결과');
  if (answer) {
    const k = answer.deriv.sql.replace('?', '키');
    line(`   판별 완료`);
    line(`   저장: HEX(AES_ENCRYPT(값, ${k}))`);
    line(`   조회: CAST(AES_DECRYPT(UNHEX(컬럼), ${k}) AS CHAR)`);
    line(`   저장 형태: ${answer.storage.desc}`);
  } else {
    line('   판별 실패 — 읽을 수 있는 암호화 컬럼이 없거나, 후보 밖의 방식입니다.');
    line('   → 팀장님께 샘플값을 받아 --hex 모드로 확인하세요.');
  }

  await db.close();
})().catch(async (e) => {
  console.error('오류:', e.message);
  try { await db.close(); } catch (_) {}
  process.exit(1);
});
