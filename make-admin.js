'use strict';
/**
 * 레이노 카마스터 — 관리자 계정 생성 및 로그인 동작 확인
 *
 * 사용법
 *   node make-admin.js <아이디> <비밀번호> <이름>
 *
 *   예) node make-admin.js rayno01 Rayno!2026 관리자
 *
 * 하는 일
 *   1. rk_carmaster_app_users 에 계정 생성 (비밀번호는 scrypt 해시로 저장)
 *   2. rk_carmaster_admins 에 관리자로 등록
 *   3. 방금 만든 계정으로 로그인이 되는지 즉시 확인
 *
 * ※ 두 작업은 하나의 트랜잭션으로 처리되어, 중간에 실패하면 아무것도 남지 않습니다.
 * ※ 비밀번호는 화면에 출력하지 않습니다.
 */

const db = require('./db');
const auth = require('./auth');

const [, , loginId, password, name] = process.argv;

if (!loginId || !password) {
  console.log('사용법: node make-admin.js <아이디> <비밀번호> <이름>');
  console.log('  예 : node make-admin.js rayno01 Rayno!2026 관리자');
  process.exit(1);
}

(async () => {
  try {
    // 형식 검사 먼저 (DB를 건드리기 전에)
    auth.checkLoginIdFormat(loginId);
    auth.checkPasswordFormat(password);

    if (!(await auth.isLoginIdAvailable(loginId))) {
      console.log(`[중단] 이미 사용 중인 아이디입니다: ${loginId}`);
      await db.close();
      process.exit(1);
    }

    const userId = await db.withTransaction(async (tx) => {
      const id = await auth.createAccount(
        { loginId, password, role: 'admin' }, tx);
      await tx.query('INSERT INTO ?? (user_id, name) VALUES (?, ?)',
        [db.T.ADMINS, id, name || '관리자']);
      return id;
    });

    console.log('계정 생성 완료');
    console.log(`  아이디 : ${loginId}`);
    console.log(`  권한   : 관리자`);

    // 실제로 로그인이 되는지 확인
    const r = await auth.login(loginId, password);
    console.log();
    console.log('로그인 확인');
    console.log(`  결과       : 성공`);
    console.log(`  관리자 여부 : ${r.user.is_admin ? '예' : '아니오'}`);
    console.log(`  출입증 길이 : ${r.token.length}자 (내용은 출력하지 않음)`);

    // 잘못된 비밀번호는 거부되는지 확인
    try {
      await auth.login(loginId, password + 'X');
      console.log('  [경고] 잘못된 비밀번호가 통과했습니다. 확인이 필요합니다.');
    } catch (_) {
      console.log('  오답 차단   : 정상 (잘못된 비밀번호는 거부됨)');
    }

    console.log();
    console.log('완료되었습니다.');
    await db.close();
  } catch (e) {
    console.error('실패:', e.message);
    try { await db.close(); } catch (_) {}
    process.exit(1);
  }
})();
