'use strict';
/**
 * 레이노 카마스터 — DB 접속 및 스키마 진단 스크립트
 *
 * 실행:  node check-db.js
 *
 * 확인 내용
 *   1. 가비아 MySQL 접속 가능 여부
 *   2. MySQL 서버 버전 (5.6 / 5.7 / 8.0)
 *   3. DB 이름과 우리 테이블 12개 + 뷰 2개 존재 여부
 *   4. ★생성컬럼 3종이 실제로 만들어졌는지★
 *      (MySQL 5.6은 생성컬럼 미지원 → 쿠폰 중복지급 차단 장치 유무 판별)
 *   5. phone / email 컬럼 길이 (암호화 시 잘림 여부)
 *   6. AES 암복호화 왕복 테스트
 *
 * ※ 개인정보는 출력하지 않습니다. 구조와 개수만 확인합니다.
 */

const db = require('./db');

const line = (s = '') => console.log(s);
const head = (s) => { line(); line('─'.repeat(64)); line(s); line('─'.repeat(64)); };

(async () => {
  let cfg;
  try {
    cfg = db.loadConfig();
  } catch (e) {
    line(`[실패] 설정값 로드 오류: ${e.message}`);
    line('       → AWS Parameter Store에 /rayno/carmaster/db/* 5개가 있는지 확인하세요.');
    process.exit(1);
  }

  head('1. 접속 테스트');
  line(`   대상: ${cfg.host}:${cfg.port}`);
  line(`   DB명: ${cfg.database || '(미지정 — 아래에서 탐색)'}`);

  try {
    await db.query('SELECT 1');
    line('   결과: 접속 성공');
  } catch (e) {
    line(`   결과: 접속 실패 — ${e.code || ''} ${e.message}`);
    line();
    line('   [원인별 대응]');
    line('   ETIMEDOUT / ECONNREFUSED → 3306 포트 방화벽 미개방. 팀장님께 요청 필요');
    line('   ER_ACCESS_DENIED_ERROR   → 계정·비밀번호 오류 또는 원격 접속 권한 없음');
    line('   ER_BAD_DB_ERROR          → DB 이름이 잘못됨');
    await db.close();
    process.exit(1);
  }

  head('2. 서버 버전');
  const [ver] = await db.query('SELECT VERSION() AS v');
  line(`   ${ver.v}`);
  const major = parseFloat(ver.v);
  if (major < 5.7) {
    line('   ※ 5.7 미만 → 생성컬럼(Generated Column) 미지원. 아래 4번 확인 필요');
  } else {
    line('   ※ 5.7 이상 → 생성컬럼 지원됨');
  }

  head('3. DB 및 우리 테이블 확인');
  let dbName = cfg.database;
  if (!dbName) {
    const dbs = await db.query('SHOW DATABASES');
    const names = dbs.map(r => Object.values(r)[0])
      .filter(n => !['information_schema', 'performance_schema', 'mysql', 'sys'].includes(n));
    line(`   접근 가능한 DB: ${names.join(', ') || '(없음)'}`);
    for (const n of names) {
      const cnt = await db.query(
        `SELECT COUNT(*) c FROM information_schema.tables
          WHERE table_schema = ? AND table_name LIKE 'rk_carmaster%'`, [n]);
      if (cnt[0].c > 0) { dbName = n; break; }
    }
    if (dbName) {
      line(`   → 카마스터 테이블이 있는 DB: ${dbName}`);
      line(`   → Parameter Store에 /rayno/carmaster/db/name = ${dbName} 로 추가하세요.`);
    }
  }
  if (!dbName) {
    line('   [실패] 카마스터 테이블을 찾지 못했습니다.');
    await db.close();
    process.exit(1);
  }

  const objs = await db.query(
    `SELECT table_name AS n, table_type AS t
       FROM information_schema.tables
      WHERE table_schema = ? AND table_name LIKE '%carmaster%'
      ORDER BY table_type, table_name`, [dbName]);

  const tables = objs.filter(o => o.t === 'BASE TABLE');
  const views  = objs.filter(o => o.t === 'VIEW');
  line(`   테이블 ${tables.length}개 / 뷰 ${views.length}개`);
  tables.forEach(o => line(`     [표] ${o.n}`));
  views.forEach(o  => line(`     [뷰] ${o.n}`));

  const expected = Object.values(db.T);
  const missing = expected.filter(t => !tables.some(o => o.n === t));
  if (missing.length) {
    line();
    line('   ※ 코드가 기대하는 이름과 다른 테이블:');
    missing.forEach(m => line(`     - ${m}  (없음)`));
    line('     → db.js 의 테이블명 상수(T)를 실제 이름에 맞춰야 합니다.');
  } else {
    line('   ※ 12개 테이블명 전부 일치');
  }

  head('4. 생성컬럼 3종 확인  ★중요★');
  const gen = await db.query(
    `SELECT table_name AS tbl, column_name AS col
       FROM information_schema.columns
      WHERE table_schema = ?
        AND column_name IN ('phone_last4','uk_welcome','uk_install')`, [dbName]);

  const checks = [
    ['phone_last4', '휴대폰 뒤 4자리 자동 계산'],
    ['uk_welcome',  '웰컴기프트 1인 1회 차단'],
    ['uk_install',  '시공 리워드 규칙별 1회 차단']
  ];
  for (const [col, desc] of checks) {
    const found = gen.some(g => g.col === col);
    line(`   ${found ? '있음' : '없음'}  ${col.padEnd(12)} — ${desc}`);
  }
  if (!gen.length) {
    line();
    line('   ※ 셋 다 없음 → MySQL 5.6이라 생성되지 않은 것으로 보입니다.');
    line('     쿠폰·리워드 중복 지급 차단이 DB에 없으므로 백엔드에서 처리해야 합니다.');
  }

  head('5. 개인정보 컬럼 길이 (암호화 시 잘림 여부)');
  const cols = await db.query(
    `SELECT table_name AS tbl, column_name AS col,
            data_type AS type, character_maximum_length AS len
       FROM information_schema.columns
      WHERE table_schema = ?
        AND column_name IN ('phone','email')
      ORDER BY table_name`, [dbName]);

  for (const c of cols) {
    // 암호문 길이 = ceil((평문바이트+1)/16)*16*2  (HEX 이므로 2배)
    const needForPhone = 32;    // 11자리 휴대폰 → 32자
    const needForEmail = 320;   // 150자 이메일 → 최대 320자
    const need = c.col === 'phone' ? needForPhone : needForEmail;
    const ok = (c.len || 0) >= need;
    line(`   ${c.tbl}.${c.col}  ${c.type}(${c.len})  필요 ${need}자  → ${ok ? '충분' : '★부족 — ALTER 필요★'}`);
  }

  head('6. AES 암복호화 왕복 테스트');
  try {
    const sample = '01000000000';
    const e = db.encParam(sample);
    const rows = await db.query(
      `SELECT CAST(AES_DECRYPT(UNHEX(${e.sql}), ?) AS CHAR) AS back`,
      [...e.params, db.loadConfig().encKey]
    );
    const ok = rows[0].back === sample;
    line(`   결과: ${ok ? '성공 — 암호화·복호화가 정상 동작합니다' : '실패 — 값이 일치하지 않습니다'}`);
    if (!ok) line('     → 암호화 키가 레이노 본 DB와 다를 수 있습니다.');
  } catch (e) {
    line(`   결과: 오류 — ${e.message}`);
  }

  head('진단 완료');
  await db.close();
})().catch(async (e) => {
  console.error('예기치 못한 오류:', e.message);
  try { await db.close(); } catch (_) {}
  process.exit(1);
});
