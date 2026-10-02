// Cloudflare Pages Functions with D1 Database

interface Env {
  DB?: D1Database;
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  const jsonResponse = (data: any, status = 200) => {
    return new Response(JSON.stringify(data), {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Recipient-Token',
      },
    });
  };

  if (method === 'OPTIONS') {
    return jsonResponse({ ok: true });
  }

  // Health check endpoint (Cloudflare deployment verification)
  if (method === 'GET' && path === '/api/health') {
    return jsonResponse({
      status: 'ok',
      service: 'ChocolateBox Cloudflare Pages API',
      d1Connected: Boolean(env.DB),
      message: env.DB ? 'D1 database successfully connected' : 'D1 database not bound (local mock mode)',
    });
  }

  // If D1 is not bound, notify client to use local fallback
  if (!env.DB) {
    return jsonResponse({ error: 'D1 database not bound' }, 503);
  }

  try {
    // 1. GET /api/items
    if (method === 'GET' && path === '/api/items') {
      const { results } = await env.DB.prepare(
        'SELECT * FROM items ORDER BY type ASC, order_num ASC'
      ).all();

      const items = (results || []).map((row: any) => ({
        ...row,
        is_opened: Boolean(row.is_opened),
        tags: typeof row.tags === 'string' ? JSON.parse(row.tags || '[]') : (row.tags || []),
      }));
      return jsonResponse(items);
    }

    // 2. POST /api/items/:id/open
    const openMatch = path.match(/^\/api\/items\/(\d+)\/open$/);
    if (method === 'POST' && openMatch) {
      const id = parseInt(openMatch[1], 10);
      const body: any = await request.json().catch(() => ({}));
      const openedAt = body.opened_at || new Date().toISOString();

      const itemRow: any = await env.DB.prepare('SELECT * FROM items WHERE id = ?').bind(id).first();
      if (!itemRow) {
        return jsonResponse({ error: 'Item not found' }, 404);
      }

      await env.DB.prepare(
        'UPDATE items SET is_opened = 1, opened_at = ?, updated_at = datetime("now") WHERE id = ?'
      ).bind(openedAt, id).run();

      const logInsert = await env.DB.prepare(
        'INSERT INTO open_logs (item_id, item_title, item_type, opened_at, action, note) VALUES (?, ?, ?, ?, "open", "개봉됨")'
      ).bind(id, itemRow.title, itemRow.type, openedAt).run();

      const updatedRow: any = await env.DB.prepare('SELECT * FROM items WHERE id = ?').bind(id).first();
      const updatedItem = {
        ...updatedRow,
        is_opened: true,
        tags: typeof updatedRow.tags === 'string' ? JSON.parse(updatedRow.tags || '[]') : [],
      };

      const log = {
        id: logInsert.meta?.last_row_id || Date.now(),
        item_id: id,
        item_title: itemRow.title,
        item_type: itemRow.type,
        opened_at: openedAt,
        action: 'open',
        note: '개봉됨',
      };

      return jsonResponse({ item: updatedItem, log });
    }

    // 3. POST /api/recipient/verify-pin (선물 받는 분 메인 페이지 전용 PIN 검증)
    if (method === 'POST' && path === '/api/recipient/verify-pin') {
      const body: any = await request.json().catch(() => ({}));
      const { pin, pin_hash } = body;

      const authRow: any = await env.DB.prepare('SELECT * FROM recipient_auth WHERE id = 1').first();
      if (!authRow) {
        // Fallback default hash for 7777: 71256d6e10db75f75a2750493de22e3864fdc8b02e5efdf3c9e3a202e0a31706
        const defaultHash = '71256d6e10db75f75a2750493de22e3864fdc8b02e5efdf3c9e3a202e0a31706';
        if (pin_hash === defaultHash) return jsonResponse({ success: true, token: 'recipient_unlocked_forever' });
        return jsonResponse({ success: false, error: '잘못된 선물 비밀번호입니다.' }, 401);
      }

      if (pin_hash && pin_hash === authRow.pin_hash) {
        return jsonResponse({ success: true, token: 'recipient_unlocked_forever' });
      }

      if (pin) {
        const encoder = new TextEncoder();
        const data = encoder.encode(pin + (authRow.salt || 'choco_salt_2026'));
        const hashBuf = await crypto.subtle.digest('SHA-256', data);
        const calcHash = Array.from(new Uint8Array(hashBuf))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

        if (calcHash === authRow.pin_hash) {
          return jsonResponse({ success: true, token: 'recipient_unlocked_forever' });
        }
      }

      return jsonResponse({ success: false, error: '잘못된 선물 비밀번호입니다.' }, 401);
    }

    // 4. POST /api/admin/verify-pin (관리자 PIN 검증)
    if (method === 'POST' && path === '/api/admin/verify-pin') {
      const body: any = await request.json().catch(() => ({}));
      const { pin, pin_hash } = body;

      const authRow: any = await env.DB.prepare('SELECT * FROM admin_auth WHERE id = 1').first();
      if (!authRow) {
        if (pin_hash) {
          await env.DB.prepare(
            'INSERT INTO admin_auth (id, pin_hash, salt) VALUES (1, ?, "choco_salt_2026")'
          ).bind(pin_hash).run();
          return jsonResponse({ success: true, initialized: true });
        }
        return jsonResponse({ success: false, error: 'Admin auth not setup' }, 400);
      }

      if (pin_hash && pin_hash === authRow.pin_hash) {
        return jsonResponse({ success: true });
      }

      if (pin) {
        const encoder = new TextEncoder();
        const data = encoder.encode(pin + (authRow.salt || 'choco_salt_2026'));
        const hashBuf = await crypto.subtle.digest('SHA-256', data);
        const calcHash = Array.from(new Uint8Array(hashBuf))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

        if (calcHash === authRow.pin_hash) {
          return jsonResponse({ success: true });
        }
      }

      return jsonResponse({ success: false, error: '잘못된 관리자 PIN입니다.' }, 401);
    }

    // 5. POST /api/admin/change-pin (관리자 PIN 변경)
    if (method === 'POST' && path === '/api/admin/change-pin') {
      const body: any = await request.json().catch(() => ({}));
      const { pin_hash } = body;
      if (!pin_hash) return jsonResponse({ error: 'Missing pin_hash' }, 400);

      await env.DB.prepare(
        'INSERT INTO admin_auth (id, pin_hash, salt, updated_at) VALUES (1, ?, "choco_salt_2026", datetime("now")) ON CONFLICT(id) DO UPDATE SET pin_hash = excluded.pin_hash, updated_at = datetime("now")'
      ).bind(pin_hash).run();

      return jsonResponse({ success: true });
    }

    // 6. POST /api/admin/change-recipient-pin (선물 받는 분 PIN 변경 - 어드민 전용)
    if (method === 'POST' && path === '/api/admin/change-recipient-pin') {
      const body: any = await request.json().catch(() => ({}));
      const { pin_hash } = body;
      if (!pin_hash) return jsonResponse({ error: 'Missing pin_hash' }, 400);

      await env.DB.prepare(
        'INSERT INTO recipient_auth (id, pin_hash, salt, updated_at) VALUES (1, ?, "choco_salt_2026", datetime("now")) ON CONFLICT(id) DO UPDATE SET pin_hash = excluded.pin_hash, updated_at = datetime("now")'
      ).bind(pin_hash).run();

      return jsonResponse({ success: true });
    }

    // 7. GET /api/admin/logs
    if (method === 'GET' && path === '/api/admin/logs') {
      const { results } = await env.DB.prepare(
        'SELECT * FROM open_logs ORDER BY opened_at DESC LIMIT 200'
      ).all();
      return jsonResponse(results || []);
    }

    // 8. Messages API: GET /api/messages
    if (method === 'GET' && path === '/api/messages') {
      const { results } = await env.DB.prepare(
        'SELECT * FROM messages ORDER BY created_at ASC LIMIT 500'
      ).all();
      const msgs = (results || []).map((row: any) => ({
        ...row,
        is_read: Boolean(row.is_read),
      }));
      return jsonResponse(msgs);
    }

    // 9. Messages API: POST /api/messages
    if (method === 'POST' && path === '/api/messages') {
      const b: any = await request.json();
      const sender = b.sender === 'admin' ? 'admin' : 'streamer';
      const text = b.text || '';
      const imageUrl = b.image_url || null;
      const linkUrl = b.link_url || null;

      const res = await env.DB.prepare(
        `INSERT INTO messages (sender, text, image_url, link_url, is_read, created_at)
         VALUES (?, ?, ?, ?, 0, datetime("now"))`
      ).bind(sender, text, imageUrl, linkUrl).run();

      const newId = res.meta?.last_row_id;
      const createdRow: any = await env.DB.prepare('SELECT * FROM messages WHERE id = ?').bind(newId).first();
      return jsonResponse({
        ...createdRow,
        is_read: false,
      });
    }

    // 10. Messages API: DELETE /api/messages/:id
    const msgDelMatch = path.match(/^\/api\/messages\/(\d+)$/);
    if (method === 'DELETE' && msgDelMatch) {
      const id = parseInt(msgDelMatch[1], 10);
      await env.DB.prepare('DELETE FROM messages WHERE id = ?').bind(id).run();
      return jsonResponse({ success: true });
    }

    // 11. POST /api/admin/items (Create)
    if (method === 'POST' && path === '/api/admin/items') {
      const b: any = await request.json();
      const tagsStr = JSON.stringify(b.tags || []);
      const res = await env.DB.prepare(
        `INSERT INTO items (type, order_num, title, artist, youtube_url, youtube_id, duration, mood_score, tags, chocolate_img, letter_img, letter_text, is_opened, opened_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        b.type || 'chocolate',
        b.order_num || 0,
        b.title || '새 항목',
        b.artist || '',
        b.youtube_url || '',
        b.youtube_id || '',
        b.duration || '03:30',
        b.mood_score ?? 50,
        tagsStr,
        b.chocolate_img || '',
        b.letter_img || '',
        b.letter_text || '',
        b.is_opened ? 1 : 0,
        b.opened_at || null
      ).run();

      const newId = res.meta?.last_row_id;
      const createdRow: any = await env.DB.prepare('SELECT * FROM items WHERE id = ?').bind(newId).first();
      return jsonResponse({
        ...createdRow,
        is_opened: Boolean(createdRow.is_opened),
        tags: JSON.parse(createdRow.tags || '[]'),
      });
    }

    // 12. PUT /api/admin/items/:id (Update)
    const itemPutMatch = path.match(/^\/api\/admin\/items\/(\d+)$/);
    if (method === 'PUT' && itemPutMatch) {
      const id = parseInt(itemPutMatch[1], 10);
      const b: any = await request.json();
      const tagsStr = JSON.stringify(b.tags || []);

      await env.DB.prepare(
        `UPDATE items SET 
          type = ?, order_num = ?, title = ?, artist = ?, youtube_url = ?, youtube_id = ?,
          duration = ?, mood_score = ?, tags = ?, chocolate_img = ?, letter_img = ?, letter_text = ?, is_opened = ?, opened_at = ?, updated_at = datetime("now")
         WHERE id = ?`
      ).bind(
        b.type || 'chocolate',
        b.order_num || 0,
        b.title || '',
        b.artist || '',
        b.youtube_url || '',
        b.youtube_id || '',
        b.duration || '03:30',
        b.mood_score ?? 50,
        tagsStr,
        b.chocolate_img || '',
        b.letter_img || '',
        b.letter_text || '',
        b.is_opened ? 1 : 0,
        b.opened_at || null,
        id
      ).run();

      const updatedRow: any = await env.DB.prepare('SELECT * FROM items WHERE id = ?').bind(id).first();
      return jsonResponse({
        ...updatedRow,
        is_opened: Boolean(updatedRow.is_opened),
        tags: JSON.parse(updatedRow.tags || '[]'),
      });
    }

    // 13. DELETE /api/admin/items/:id
    const itemDelMatch = path.match(/^\/api\/admin\/items\/(\d+)$/);
    if (method === 'DELETE' && itemDelMatch) {
      const id = parseInt(itemDelMatch[1], 10);
      await env.DB.prepare('DELETE FROM items WHERE id = ?').bind(id).run();
      return jsonResponse({ success: true });
    }

    // 14. DELETE /api/admin/logs/:id
    const logDelMatch = path.match(/^\/api\/admin\/logs\/(\d+)$/);
    if (method === 'DELETE' && logDelMatch) {
      const id = parseInt(logDelMatch[1], 10);
      await env.DB.prepare('DELETE FROM open_logs WHERE id = ?').bind(id).run();
      return jsonResponse({ success: true });
    }

    return jsonResponse({ error: 'Endpoint not found' }, 404);
  } catch (err: any) {
    return jsonResponse({ error: err.message || 'Server error' }, 500);
  }
};
