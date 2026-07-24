'use strict';
/**
 * 탈퇴 정리 배치를 만들기 위한 테이블 구조 확인  (읽기 전용)
 *
 * 사용법:  node schema-dump.js
 */

const db = require('./db');

const TABLES = [
  'rk_carmaster_carmasters',
  'rk_carmaster_app_users',
  'rk_carmaster_rewards',
  'rk_carmaster_coupons',
  'rk_carmaster_admins'
];

const line = (s) => console.log(s);
const head = (s) => { console.log(''); console.log('── ' + s + ' ' + '─'.repeat(Math.max(0, 50 - s.length))); };

(async () => {
  line('탈퇴 정리 배치용 구조 확인  (읽기 전용)');

  for (const t of TABLES) {
    head(t);
    try {
      const cols = await db.query(
        `SELECT COLUMN_NAME AS name, COLUMN_TYPE AS type, IS_NULLABLE AS nullable,
                COLUMN_KEY AS ky, COLUMN_DEFAULT AS dflt
           FROM information_schema.COLUMNS
          WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
          ORDER BY ORDINAL_POSITION`, [t]);
      if (!cols.length) { line('   테이블 없음 또는 권한 없음'); continue; }
      for (const c of cols) {
        const tag = c.ky === 'PRI' ? ' [PK]' : (c.ky === 'UNI' ? ' [UQ]' : '');
        line(`   ${String(c.name).padEnd(20)} ${String(c.type).padEnd(18)} ${c.nullable === 'YES' ? 'NULL허용' : 'NOT NULL'}${tag}`);
      }
      const cnt = await db.query(`SELECT COUNT(*) AS n FROM \`${t}\``, []);
      line(`   → 총 ${cnt[0].n}건`);
    } catch (e) { line(`   오류 — ${e.message}`); }
  }

  head('탈퇴 상태 회원 현황');
  try {
    const rows = await db.query(
      `SELECT status, COUNT(*) AS n FROM rk_carmaster_carmasters GROUP BY status`, []);
    if (!rows.length) line('   없음');
    for (const r of rows) line(`   ${String(r.status).padEnd(12)} ${r.n}건`);
  } catch (e) { line(`   오류 — ${e.message}`); }

  head('carmasters 테이블에 걸린 트리거');
  try {
    const rows = await db.query(
      `SELECT TRIGGER_NAME AS nm, ACTION_TIMING AS tm, EVENT_MANIPULATION AS ev
         FROM information_schema.TRIGGERS
        WHERE TRIGGER_SCHEMA = DATABASE()
          AND EVENT_OBJECT_TABLE LIKE 'rk\\_carmaster\\_%'
        ORDER BY EVENT_OBJECT_TABLE, TRIGGER_NAME`, []);
    for (const r of rows) line(`   ${r.nm}  (${r.tm} ${r.ev})`);
  } catch (e) { line(`   오류 — ${e.message}`); }

  head('확인 완료');
  await db.close();
})().catch(async (e) => {
  console.error('오류:', e.message);
  try { await db.close(); } catch (_) {}
  process.exit(1);
});
