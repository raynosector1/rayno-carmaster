'use strict';
/**
 * 재가입 결과 확인  (읽기 전용 — DB를 변경하지 않습니다)
 *
 * 확인하는 것
 *   - 회원 수가 늘지 않았는지 (재가입이 새 행을 만들지 않았는지)
 *   - 웰컴기프트가 1건뿐인지 (두 번 지급되지 않았는지)
 *   - 리워드가 언제 만들어졌고, 회원이 언제 다시 인증했는지
 *
 * 사용법:  node check-rejoin.js
 */

const db = require('./db');

const line = (s) => console.log(s);
const head = (s) => { console.log(''); console.log('── ' + s + ' ' + '─'.repeat(Math.max(0, 50 - s.length))); };
const t = (v) => v ? new Date(v).toISOString().replace('T', ' ').slice(0, 19) : '-';

(async () => {
  line('재가입 결과 확인  (읽기 전용)');

  head('1. 회원 현황');
  let members = [];
  try {
    members = await db.query(
      `SELECT id, code, status, created_at, verified_at, withdrawn_at, updated_at,
              (di_hash IS NOT NULL) AS has_di
         FROM rk_carmaster_carmasters ORDER BY code`, []);
    line(`   총 ${members.length}명`);
    for (const m of members) {
      line(`   [${m.code}] ${m.status}  가입 ${t(m.created_at)}  인증 ${t(m.verified_at)}  탈퇴 ${t(m.withdrawn_at)}`);
    }
  } catch (e) { line(`   조회 오류 — ${e.message}`); }

  head('2. 웰컴기프트 지급 건수');
  try {
    const rows = await db.query(
      `SELECT c.code, r.id, r.type, r.status, r.item_name, r.created_at, r.sent_at
         FROM rk_carmaster_rewards r
         JOIN rk_carmaster_carmasters c ON c.id = r.carmaster_id
        WHERE r.type = 'welcome'
        ORDER BY c.code, r.created_at`, []);
    if (!rows.length) line('   없음');
    const byCode = {};
    for (const r of rows) {
      byCode[r.code] = (byCode[r.code] || 0) + 1;
      line(`   [${r.code}] 리워드번호 ${r.id}  ${r.status}  생성 ${t(r.created_at)}  지급 ${t(r.sent_at)}`);
    }
    line('');
    for (const code of Object.keys(byCode)) {
      const n = byCode[code];
      line(`   ${code} → 웰컴기프트 ${n}건  ${n > 1 ? '★중복 지급됨 — 문제★' : '정상 (1건)'}`);
    }
  } catch (e) { line(`   조회 오류 — ${e.message}`); }

  head('3. 쿠폰 현황 (실제 사용 가능한 것)');
  try {
    const rows = await db.query(
      `SELECT c.code, cp.status, cp.issued_at, cp.expires_at
         FROM rk_carmaster_coupons cp
         JOIN rk_carmaster_carmasters c ON c.id = cp.carmaster_id
        ORDER BY c.code`, []);
    if (!rows.length) line('   쿠폰 없음 — 실제로 쓸 수 있는 혜택은 없습니다');
    for (const r of rows) line(`   [${r.code}] ${r.status}  발급 ${t(r.issued_at)}`);
  } catch (e) { line(`   조회 오류 — ${e.message}`); }

  head('4. 로그인 계정');
  try {
    const rows = await db.query(
      `SELECT u.login_id, u.banned_at, u.created_at, c.code
         FROM rk_carmaster_app_users u
         LEFT JOIN rk_carmaster_carmasters c ON c.user_id = u.id
        ORDER BY u.created_at`, []);
    for (const r of rows) {
      line(`   ${String(r.login_id).padEnd(22)} ${r.code || '(카마스터 아님)'}  ${r.banned_at ? '차단됨' : '정상'}  생성 ${t(r.created_at)}`);
    }
  } catch (e) { line(`   조회 오류 — ${e.message}`); }

  head('판정');
  line('   2번에서 모든 회원이 "정상 (1건)" 이면 재지급은 일어나지 않은 것입니다.');
  line('   화면에 보이는 리워드는 탈퇴 전에 받았던 기록이 따라온 것입니다.');

  await db.close();
})().catch(async (e) => {
  console.error('오류:', e.message);
  try { await db.close(); } catch (_) {}
  process.exit(1);
});
