/* =====================================================================
   건의함 API — Cloudflare Pages Function
   ---------------------------------------------------------------------
   POST   /api/feedback                누구나   건의 접수
   GET    /api/feedback                누구나   { ready } — 접수 가능 여부
   GET    /api/feedback  + 인증 헤더    관리자   목록
   PATCH  /api/feedback  { id, status } 관리자   처리 상태 변경 (new | done)
   DELETE /api/feedback  { id }         관리자   삭제

   관리자 인증: Authorization: Bearer <ADMIN_TOKEN>

   필요한 설정 (Cloudflare 대시보드 → Pages 프로젝트 → 설정)
     D1 바인딩    DB
     비밀 변수    ADMIN_TOKEN
   설정이 없으면 이 API 만 503 을 돌려주고 나머지 사이트는 영향이 없다.
   표는 첫 요청 때 스스로 만든다.

   개인정보: IP 는 저장하지 않는다. 도배를 막으려고 'IP + 날짜 + 비밀값'의
   해시만 남긴다. 날이 바뀌면 값이 달라져 같은 사람인지 이어 볼 수 없고,
   비밀값이 섞여 있어 해시에서 IP 를 거꾸로 찾을 수도 없다.
   ===================================================================== */

const KINDS = ['오류', '새 도구', '개선', '기타'];
const TOOLS = ['', 'xlsx-unlock', 'xlsx-unprotect', 'hwpx-edit', 'other'];
const BODY_MIN = 5, BODY_MAX = 2000, CONTACT_MAX = 100;
const PER_HOUR = 5;            // 같은 사람이 한 시간에 보낼 수 있는 수
const MIN_ELAPSED = 3000;      // 페이지를 연 뒤 이보다 빨리 보내면 봇으로 본다 (ms)

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
});

let tableReady = false;
async function ensureTable(db){
  if (tableReady) return;
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS feedback (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at TEXT    NOT NULL,
      kind       TEXT    NOT NULL,
      tool       TEXT    NOT NULL DEFAULT '',
      body       TEXT    NOT NULL,
      contact    TEXT    NOT NULL DEFAULT '',
      status     TEXT    NOT NULL DEFAULT 'new',
      ip_hash    TEXT    NOT NULL
    )`),
    db.prepare('CREATE INDEX IF NOT EXISTS feedback_ip_time ON feedback (ip_hash, created_at)')
  ]);
  tableReady = true;
}

async function sha256(s){
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
}
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

async function isAdmin(request, env){
  const h = request.headers.get('authorization') || '';
  const given = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!env.ADMIN_TOKEN || !given) return false;
  // 길이가 달라도 비교 시간이 새지 않도록 해시끼리 비교한다
  const [a, b] = await Promise.all([sha256(given), sha256(env.ADMIN_TOKEN)]);
  return crypto.subtle.timingSafeEqual(a, b);
}

async function readJson(request, limit = 16384){
  const text = await request.text();
  if (text.length > limit) return null;
  try { return JSON.parse(text); } catch { return null; }
}

/* ---------- 접수 ---------- */
export async function onRequestPost({ request, env }){
  if (!env.DB) return json({ error: 'not_configured' }, 503);

  // 다른 사이트의 페이지가 대신 보내는 요청은 받지 않는다
  const origin = request.headers.get('origin');
  if (origin && origin !== new URL(request.url).origin) return json({ error: 'origin' }, 403);

  const d = await readJson(request);
  if (!d || typeof d !== 'object') return json({ error: 'bad_request' }, 400);

  // 사람 눈에 안 보이는 칸(website)을 채웠거나 너무 빨리 보냈으면 봇이다.
  // 성공처럼 답해서 봇이 방식을 바꿔 다시 시도하지 않게 한다.
  if (d.website || !(Number(d.elapsed) >= MIN_ELAPSED)) return json({ ok: true });

  const kind = KINDS.includes(d.kind) ? d.kind : null;
  const tool = TOOLS.includes(d.tool) ? d.tool : '';
  const body = typeof d.body === 'string' ? d.body.trim() : '';
  const contact = typeof d.contact === 'string' ? d.contact.trim() : '';
  if (!kind) return json({ error: 'kind' }, 400);
  if (body.length < BODY_MIN || body.length > BODY_MAX) return json({ error: 'body' }, 400);
  if (contact.length > CONTACT_MAX) return json({ error: 'contact' }, 400);

  await ensureTable(env.DB);

  const now = new Date();
  const ip = request.headers.get('cf-connecting-ip') || '';
  const ipHash = hex(await sha256(ip + '|' + now.toISOString().slice(0, 10) + '|' + (env.ADMIN_TOKEN || 'tool.yool.me')));
  const since = new Date(now.getTime() - 3600e3).toISOString();
  const recent = await env.DB
    .prepare('SELECT COUNT(*) AS n FROM feedback WHERE ip_hash = ? AND created_at > ?')
    .bind(ipHash, since).first();
  if (recent.n >= PER_HOUR) return json({ error: 'rate' }, 429);

  await env.DB
    .prepare('INSERT INTO feedback (created_at, kind, tool, body, contact, ip_hash) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(now.toISOString(), kind, tool, body, contact, ipHash).run();
  return json({ ok: true });
}

/* ---------- 상태 확인 / 관리자 목록 ---------- */
export async function onRequestGet({ request, env }){
  if (!request.headers.get('authorization')) return json({ ready: !!env.DB });

  if (!env.DB || !env.ADMIN_TOKEN) return json({ error: 'not_configured' }, 503);
  if (!(await isAdmin(request, env))) return json({ error: 'auth' }, 401);
  await ensureTable(env.DB);
  const { results } = await env.DB
    .prepare('SELECT id, created_at, kind, tool, body, contact, status FROM feedback ORDER BY id DESC LIMIT 500')
    .all();
  return json({ items: results });
}

/* ---------- 관리자: 처리 상태 ---------- */
export async function onRequestPatch({ request, env }){
  if (!env.DB || !env.ADMIN_TOKEN) return json({ error: 'not_configured' }, 503);
  if (!(await isAdmin(request, env))) return json({ error: 'auth' }, 401);
  const d = await readJson(request, 1024);
  const id = Number(d && d.id);
  if (!Number.isInteger(id) || !['new', 'done'].includes(d.status)) return json({ error: 'bad_request' }, 400);
  await ensureTable(env.DB);
  const r = await env.DB.prepare('UPDATE feedback SET status = ? WHERE id = ?').bind(d.status, id).run();
  return json({ ok: r.meta.changes === 1 });
}

/* ---------- 관리자: 삭제 ---------- */
export async function onRequestDelete({ request, env }){
  if (!env.DB || !env.ADMIN_TOKEN) return json({ error: 'not_configured' }, 503);
  if (!(await isAdmin(request, env))) return json({ error: 'auth' }, 401);
  const d = await readJson(request, 1024);
  const id = Number(d && d.id);
  if (!Number.isInteger(id)) return json({ error: 'bad_request' }, 400);
  await ensureTable(env.DB);
  const r = await env.DB.prepare('DELETE FROM feedback WHERE id = ?').bind(id).run();
  return json({ ok: r.meta.changes === 1 });
}
