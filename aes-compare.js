'use strict';
/**
 * 레이노 방식 대조 진단  (읽기 전용 — DB를 변경하지 않습니다)
 *
 * 확인하는 것
 *   1) SSM 키의 길이와 지문(fingerprint) — 키 원문은 출력하지 않습니다
 *   2) 파라미터 바인딩 방식 vs PHP처럼 문자열에 직접 이어붙이는 방식의 결과 비교
 *   3) 현재 저장된 회원 데이터가 우리 키로 제대로 복호화되는지
 *   4) 팀장님과 대조할 기준값 생성
 *
 * 사용법:  node aes-compare.js
 */

const crypto = require('crypto');
const db = require('./db');

const TEST_PLAIN = '01012345678';
const line = (s) => console.log(s);
const head = (s) => { console.log(''); console.log('── ' + s + ' ' + '─'.repeat(Math.max(0, 54 - s.length))); };

function maskPhone(v) {
  if (v === null || v === undefined) return '(복호화 실패 / NULL)';
  const s = String(v);
  if (!s) return '(빈 값)';
  if (s.length < 6) return s[0] + '*'.repeat(s.length - 1);
  return s.slice(0, 3) + '*'.repeat(s.length - 7) + s.slice(-4);
}

(async () => {
  line('레이노 방식 대조 진단  (읽기 전용)');

  const key = db.loadConfig().encKey;

  /* ── 1. 키 상태 ── */
  head('1. SSM 암호화 키 상태');
  const fp = crypto.createHash('sha256').update(key, 'utf8').digest('hex').slice(0, 16);
  line(`   길이        : ${key.length}자`);
  line(`   앞뒤 공백   : ${key !== key.trim() ? '★있음 — 이게 원인일 수 있습니다★' : '없음'}`);
  line(`   특수문자    : ${/[\\'"`]/.test(key) ? "★있음(\\ ' \" ` 중 하나) — PHP 이어붙이기와 결과가 달라질 수 있습니다★" : '없음'}`);
  line(`   지문(SHA256 앞16자리): ${fp}`);
  line('   → 이 지문을 팀장님께 보내 같은 값이 나오는지 대조하면 키 일치 여부를 확인할 수 있습니다.');
  line("      팀장님 확인 방법: PHP에서  echo substr(hash('sha256', $key), 0, 16);");

  /* ── 2. 두 방식 비교 ── */
  head('2. 바인딩 방식 vs PHP 이어붙이기 방식');
  let bound = null, phpStyle = null;
  try {
    const r = await db.query(`SELECT HEX(AES_ENCRYPT(?, ?)) AS v`, [TEST_PLAIN, key]);
    bound = r[0].v;
    line(`   바인딩   : ${bound}`);
  } catch (e) { line(`   바인딩   : 오류 — ${e.message}`); }

  try {
    /* PHP 코드를 그대로 흉내냅니다. 이스케이프를 일부러 하지 않습니다. */
    const r = await db.query(`SELECT HEX(AES_ENCRYPT('${TEST_PLAIN}', '${key}')) AS v`, []);
    phpStyle = r[0].v;
    line(`   PHP 방식 : ${phpStyle}`);
  } catch (e) { line(`   PHP 방식 : 오류 — ${e.message}`); }

  if (bound && phpStyle) {
    line(bound === phpStyle
      ? '   → 두 방식 결과가 같습니다. 키 전달 방식은 원인이 아닙니다.'
      : '   → ★두 방식 결과가 다릅니다. 이게 원인입니다 (키의 특수문자 이스케이프 차이)★');
  }

  head('3. 팀장님께 보낼 대조 기준값');
  line(`   평문   : ${TEST_PLAIN}`);
  line(`   암호문 : ${bound || '(생성 실패)'}`);
  line('   → 팀장님이 레이노에서 encodeData(\'01012345678\') 한 결과와 같으면 방식 일치입니다.');

  /* ── 4. 저장된 데이터 상태 ── */
  head('4. 현재 저장된 회원 데이터');
  try {
    const rows = await db.query(
      `SELECT id, code, phone_last4,
              LENGTH(phone) AS hexlen,
              LEFT(phone, 8) AS head8, phone AS fullhex,
              CAST(AES_DECRYPT(UNHEX(phone), ?) AS CHAR) AS plainval
         FROM rk_carmaster_carmasters
        ORDER BY id LIMIT 10`, [key]);
    if (!rows.length) line('   회원 없음');
    for (const r of rows) {
      line(`   [${r.code}] 암호문 ${r.hexlen}자 (${r.head8}...)  뒤4자리 ${r.phone_last4}`);
      line(`        암호문 전체 : ${r.fullhex}`);
      line(`        복호화 결과 : ${maskPhone(r.plainval)}`);
      if (r.plainval) {
        line(`        평문 형식   : 길이 ${String(r.plainval).length}자, 하이픈 ${String(r.plainval).includes('-') ? '있음' : '없음'}`);
      }
    }
  } catch (e) { line(`   조회 오류 — ${e.message}`); }

  head('5. 관리자 이메일');
  try {
    const rows = await db.query(
      `SELECT id, LENGTH(email) AS hexlen,
              CAST(AES_DECRYPT(UNHEX(email), ?) AS CHAR) AS plainval
         FROM rk_carmaster_admins ORDER BY id LIMIT 5`, [key]);
    for (const r of rows) {
      const d = r.plainval ? String(r.plainval) : null;
      line(`   [id ${r.id}] 암호문 ${r.hexlen}자 → 복호화 ${d ? d.replace(/^(.{2}).*(@.*)$/, '$1***$2') : '실패 / NULL'}`);
    }
  } catch (e) { line(`   조회 오류 — ${e.message}`); }

  head('진단 완료');
  await db.close();
})().catch(async (e) => {
  console.error('오류:', e.message);
  try { await db.close(); } catch (_) {}
  process.exit(1);
});
