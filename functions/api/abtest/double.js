/* =====================================================================
   abtest B 사이트 API — Cloudflare Pages Function
   POST /api/abtest/double  { n }  →  { n, result: n*2 }
   GET  /api/abtest/double?n=3     →  { n, result: n*2 }
   ===================================================================== */

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
});

function reply(n) {
  const v = Number(n);
  const ok = n !== null && n !== undefined && n !== '' && Number.isFinite(v);
  return ok ? json({ n: v, result: v * 2 }) : json({ error: '숫자가 아님' }, 400);
}

export async function onRequestGet({ request }) {
  return reply(new URL(request.url).searchParams.get('n'));
}

export async function onRequestPost({ request }) {
  const text = await request.text();
  if (text.length > 10000) return json({ error: '요청이 너무 큼' }, 413);
  try { return reply(JSON.parse(text).n); } catch { return reply(null); }
}
