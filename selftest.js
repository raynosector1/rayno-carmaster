'use strict';
/**
 * 레이노 카마스터 — 백엔드 전체 점검 스크립트
 *
 * 사용법
 *   cd /opt/rayno-auth && node selftest.js <관리자아이디> '<비밀번호>'
 *   예) cd /opt/rayno-auth && node selftest.js rayno01 'Rayno!2026'
 *
 * 하는 일
 *   서버의 모든 창구를 순서대로 두드려보고 결과를 표로 보여줍니다.
 *   읽기(조회)만 수행하며 데이터를 바꾸지 않습니다.
 *   ※ 비밀번호는 화면에 출력하지 않습니다.
 */

const API = 'https://carmaster-auth.raynofilm.co.kr';
const [, , LOGIN_ID, PASSWORD] = process.argv;

if (!LOGIN_ID || !PASSWORD) {
  console.log("사용법: node selftest.js <관리자아이디> '<비밀번호>'");
  process.exit(1);
}

const results = [];
function mark(name, ok, note) { results.push({ name, ok, note: note || '' }); }

async function call(path, opt) {
  opt = opt || {};
  const headers = { 'Content-Type': 'application/json' };
  if (opt.token) headers.Authorization = 'Bearer ' + opt.token;
  try {
    const r = await fetch(API + path, {
      method: opt.method || 'GET',
      headers,
      body: opt.body ? JSON.stringify(opt.body) : undefined,
      signal: AbortSignal.timeout(15000)
    });
    let d = null;
    try { d = await r.json(); } catch (_) {}
    return { status: r.status, data: d };
  } catch (e) {
    return { status: 0, data: null, err: e.message };
  }
}

(async () => {
  console.log('레이노 카마스터 백엔드 점검');
  console.log('대상:', API);
  console.log('─'.repeat(60));

  // 1. 서버 상태
  let r = await call('/health');
  mark('서버 살아있음', r.data && r.data.ok === true,
       r.status ? '' : '연결 실패: ' + (r.err || ''));

  // 2. 로그인 없이 볼 수 있는 것
  r = await call('/v1/offices');
  mark('지점 목록', !!(r.data && r.data.ok),
       r.data && r.data.count ? r.data.count + '개' : '');

  r = await call('/v1/notices');
  mark('공지 목록', !!(r.data && r.data.ok),
       r.data && r.data.items ? r.data.items.length + '건' : '');

  r = await call('/v1/promotions');
  mark('프로모션 목록', !!(r.data && r.data.ok),
       r.data && r.data.items ? r.data.items.length + '건' : '');

  // 3. 아이디 중복확인
  r = await call('/v1/auth/check-id', { method: 'POST', body: { login_id: 'zzz9testzzz' } });
  mark('아이디 중복확인', r.data && typeof r.data.ok === 'boolean');

  // 4. 로그인
  r = await call('/v1/auth/login', {
    method: 'POST', body: { login_id: LOGIN_ID, password: PASSWORD }
  });
  const token = (r.data && r.data.token) || null;
  mark('로그인', !!token, r.data && r.data.message ? r.data.message : '');
  const isAdmin = !!(r.data && r.data.user && r.data.user.is_admin);
  mark('관리자 권한', isAdmin, isAdmin ? '' : '관리자 계정이 아닙니다');

  // 5. 잘못된 비밀번호는 막히는지
  r = await call('/v1/auth/login', {
    method: 'POST', body: { login_id: LOGIN_ID, password: PASSWORD + 'X' }
  });
  mark('오답 차단', !(r.data && r.data.ok));

  // 6. 출입증 없이 접근하면 막히는지
  r = await call('/v1/me/summary');
  mark('비로그인 차단', !(r.data && r.data.ok));

  if (!token) {
    print();
    console.log('로그인이 안 되어 이후 점검을 건너뜁니다.');
    return;
  }

  // 7. 내 정보 (관리자 계정은 회원 정보가 없을 수 있음)
  r = await call('/v1/auth/me', { token });
  mark('내 정보 조회', !!(r.data && r.data.ok));

  r = await call('/v1/me/summary', { token });
  mark('마이페이지 요약', r.status === 200 || r.status === 404,
       r.status === 404 ? '관리자 계정이라 회원 정보 없음 (정상)' : '');

  r = await call('/v1/me/rewards', { token });
  mark('내 리워드', !!(r.data && r.data.ok));

  r = await call('/v1/me/records', { token });
  mark('내 시공내역', !!(r.data && r.data.ok));

  // 8. 관리자 창구
  if (isAdmin) {
    const admChecks = [
      ['관리자 정보', '/v1/admin/me'],
      ['회원 목록', '/v1/admin/members'],
      ['리워드 목록', '/v1/admin/rewards'],
      ['시공 목록', '/v1/admin/warranty'],
      ['공지 목록(관리)', '/v1/admin/notices'],
      ['프로모션 목록(관리)', '/v1/admin/promotions']
    ];
    for (const [name, p] of admChecks) {
      r = await call(p, { token });
      const n = (r.data && r.data.items) ? r.data.items.length : null;
      mark(name, !!(r.data && r.data.ok), n === null ? '' : n + '건');
    }

    // 회원 데이터 무결성 (첫 회원 기준)
    r = await call('/v1/admin/members', { token });
    const m = (r.data && r.data.items && r.data.items[0]) || null;
    if (m) {
      mark('회원코드 채번', /^CM-\d+$/.test(m.code || ''), m.code || '없음');
      mark('휴대폰 복호화', !!(m.phone && /^\d{10,11}$/.test(String(m.phone).replace(/\D/g, ''))),
           m.phone ? '정상' : '복호화 실패 — 암호화 키 확인 필요');
      mark('뒤 4자리 보존', !!(m.phone_last4 && m.phone_last4.length === 4), m.phone_last4 || '없음');
    } else {
      mark('회원 데이터', true, '가입 회원 없음');
    }
  }

  print();
})();

function print() {
  console.log();
  console.log('─'.repeat(60));
  let bad = 0;
  results.forEach(x => {
    if (!x.ok) bad++;
    const tag = x.ok ? '정상' : '실패';
    console.log(` ${tag}  ${x.name.padEnd(22, ' ')} ${x.note}`);
  });
  console.log('─'.repeat(60));
  console.log(bad === 0
    ? `전체 ${results.length}개 항목 모두 정상입니다.`
    : `전체 ${results.length}개 중 ${bad}개 항목에서 문제가 발견되었습니다.`);
}
