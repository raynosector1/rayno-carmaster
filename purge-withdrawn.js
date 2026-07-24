'use strict';
/**
 * 탈퇴 회원 7일 경과분 정리 배치
 *
 *   기본 동작은 미리보기입니다. 아무것도 바꾸지 않습니다.
 *     node purge-withdrawn.js          → 누가 정리 대상인지 보여주기만 함
 *     node purge-withdrawn.js --run    → 실제 정리 실행
 *
 *   하는 일 (status='withdrawn' 이고 withdrawn_at 이 7일 지난 회원)
 *     1) 쿠폰·리워드 삭제
 *     2) 카마스터 행의 개인정보 컬럼을 비움 (행 자체는 남김)
 *        - 남기는 값: id, user_id, code, status, withdrawn_at, di_hash, 동의이력, 생성일
 *        - di_hash 를 남기는 이유: 재가입 어뷰징(가입→리워드 수령→탈퇴→재가입 반복) 차단
 *     3) 로그인 계정(app_users) 행 삭제
 *     4) 전체를 트랜잭션으로 묶어 하나라도 실패하면 전부 되돌림
 */

const fs = require('fs');
const path = require('path');
const db = require('./db');

const KEEP_DAYS = 7;
const DO_RUN = process.argv.includes('--run');
const LOG_PATH = path.join(__dirname, 'purge-withdrawn.log');

const line = (s) => console.log(s);
const head = (s) => { console.log(''); console.log('── ' + s + ' ' + '─'.repeat(Math.max(0, 50 - s.length))); };

function writeLog(msg) {
  const stamp = new Date().toISOString();
  try { fs.appendFileSync(LOG_PATH, `[${stamp}] ${msg}\n`, 'utf8'); }
  catch (e) { console.error('로그 기록 실패:', e.message); }
}

/* 개인정보를 비우는 UPDATE.
   NULL 허용 컬럼은 NULL, NOT NULL 컬럼은 빈 문자열로 처리합니다. */
const ANONYMIZE_SQL = `
  UPDATE rk_carmaster_carmasters SET
    name = NULL, birth_date = NULL, gender = NULL,
    phone = NULL, phone_last4 = NULL, carrier = NULL,
    ci_hash = NULL, verified_at = NULL, login_id = NULL,
    office_etc = NULL, suspend_reason = NULL, suspended_at = NULL,
    sms_optout_at = NULL, last_login_at = NULL, last_sms_at = NULL,
    brand = '', brand_etc = '', region = '', office = '',
    updated_at = NOW()
  WHERE id = ?`;

(async () => {
  line(`탈퇴 회원 정리 배치  —  ${DO_RUN ? '★실행 모드★' : '미리보기 모드 (아무것도 바꾸지 않습니다)'}`);
  line(`기준: 탈퇴 후 ${KEEP_DAYS}일 경과`);

  /* ── 사전 확인: 외래키와 트리거 ── */
  if (!DO_RUN) {
    head('사전 확인 · 외래키 제약');
    try {
      const fks = await db.query(
        `SELECT TABLE_NAME AS t, COLUMN_NAME AS c,
                REFERENCED_TABLE_NAME AS rt, REFERENCED_COLUMN_NAME AS rc
           FROM information_schema.KEY_COLUMN_USAGE
          WHERE TABLE_SCHEMA = DATABASE()
            AND REFERENCED_TABLE_NAME LIKE 'rk\\_carmaster\\_%'`, []);
      if (!fks.length) line('   외래키 없음 — 삭제 순서 제약 없습니다');
      else fks.forEach(f => line(`   ${f.t}.${f.c} → ${f.rt}.${f.rc}`));
    } catch (e) { line(`   확인 실패 — ${e.message}`); }

    head('사전 확인 · carmasters UPDATE 트리거 내용');
    try {
      const trs = await db.query(
        `SELECT TRIGGER_NAME AS nm, ACTION_STATEMENT AS body
           FROM information_schema.TRIGGERS
          WHERE TRIGGER_SCHEMA = DATABASE()
            AND EVENT_OBJECT_TABLE = 'rk_carmaster_carmasters'
            AND EVENT_MANIPULATION = 'UPDATE'`, []);
      for (const t of trs) {
        line(`   [${t.nm}]`);
        String(t.body).split('\n').forEach(l => line('     ' + l.trim()));
      }
    } catch (e) { line(`   확인 실패 — ${e.message}`); }
  }

  /* ── 대상 조회 ── */
  head('정리 대상');
  let targets = [];
  try {
    targets = await db.query(
      `SELECT id, user_id, code, withdrawn_at,
              DATEDIFF(NOW(), withdrawn_at) AS days
         FROM rk_carmaster_carmasters
        WHERE status = 'withdrawn'
          AND withdrawn_at IS NOT NULL
          AND withdrawn_at < DATE_SUB(NOW(), INTERVAL ? DAY)
          AND name IS NOT NULL
        ORDER BY withdrawn_at`, [KEEP_DAYS]);
  } catch (e) {
    line(`   조회 실패 — ${e.message}`);
    await db.close();
    process.exit(1);
  }

  /* withdrawn_at 이 비어 있는 이상 데이터 경고 */
  try {
    const bad = await db.query(
      `SELECT COUNT(*) AS n FROM rk_carmaster_carmasters
        WHERE status = 'withdrawn' AND withdrawn_at IS NULL`, []);
    if (bad[0].n > 0) line(`   ⚠ 탈퇴 상태인데 탈퇴일시가 없는 회원 ${bad[0].n}건 — 자동 정리 대상에서 제외됩니다`);
  } catch (e) { /* 무시 */ }

  if (!targets.length) {
    line('   대상 없음 — 정리할 회원이 없습니다');
    head('완료');
    await db.close();
    return;
  }

  targets.forEach(t => line(`   ${t.code}  탈퇴 ${t.days}일 경과`));
  line(`   총 ${targets.length}건`);

  /* ── 미리보기면 여기서 종료 ── */
  if (!DO_RUN) {
    head('미리보기 종료');
    line('   실제로 정리하려면 뒤에 --run 을 붙여 다시 실행하세요.');
    line('   예)  node purge-withdrawn.js --run');
    await db.close();
    return;
  }

  /* ── 실행 ── */
  head('정리 실행');
  let done = 0, failed = 0;

  for (const t of targets) {
    try {
      await db.withTransaction(async (conn) => {
        const run = (sql, params) => conn.execute ? conn.execute(sql, params) : conn.query(sql, params);
        await run(`DELETE FROM rk_carmaster_coupons WHERE carmaster_id = ?`, [t.id]);
        await run(`DELETE FROM rk_carmaster_rewards WHERE carmaster_id = ?`, [t.id]);
        await run(ANONYMIZE_SQL, [t.id]);
        await run(`DELETE FROM rk_carmaster_app_users WHERE id = ?`, [t.user_id]);
      });
      done++;
      line(`   ${t.code}  정리 완료`);
      writeLog(`purged code=${t.code} withdrawn_days=${t.days}`);
    } catch (e) {
      failed++;
      line(`   ${t.code}  실패 — ${e.message} (이 회원은 되돌려졌습니다)`);
      writeLog(`FAILED code=${t.code} reason=${e.message}`);
    }
  }

  head('결과');
  line(`   정리 ${done}건 / 실패 ${failed}건`);
  line(`   기록 위치: ${LOG_PATH}`);
  writeLog(`run finished: purged=${done} failed=${failed}`);

  await db.close();
})().catch(async (e) => {
  console.error('오류:', e.message);
  writeLog(`ERROR ${e.message}`);
  try { await db.close(); } catch (_) {}
  process.exit(1);
});
