importScripts('/webui/rproxy_core.js');

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

function rewriteHtml(text, ctx) {
  const inject = '<script src="/webui/rproxy_core.js"></script><script src="/webui/inject.js"></script>';
  let out = RProxy.rewriteHtmlContent(text, ctx);
  if (out.indexOf('</head>') !== -1) {
    out = out.replace('</head>', inject + '</head>');
  } else {
    out = inject + out;
  }
  return out;
}

self.addEventListener('fetch', (event) => {
  event.respondWith((async () => {
    let req = event.request;
    let ctx = RProxy.parseContext(req.url);
    if (!ctx) {
      const client = event.clientId ? await self.clients.get(event.clientId) : null;
      const clientCtx = client ? RProxy.parseContext(client.url) : null;
      if (clientCtx) {
        const u = new URL(req.url);
        if (u.origin === self.location.origin && !u.pathname.startsWith('/rproxy/') && !u.pathname.startsWith('/webui/')) {
          const rewrittenUrl = clientCtx.prefix + clientCtx.base.origin + u.pathname + u.search + u.hash;
          req = new Request(rewrittenUrl, req);
          ctx = clientCtx;
        }
      }
    }
    const res = await fetch(req);
    if (!ctx) {
      return res;
    }
    const type = res.headers.get('content-type') || '';
    const dest = event.request.destination || '';
    const isDoc = event.request.mode === 'navigate' || dest === 'document' || dest === 'iframe';
    if (type.includes('text/html') || type.includes('text/css')) {
      if (type.includes('text/html') && !isDoc) {
        return res;
      }
      const charsetMatch = type.match(/charset=([^;]+)/i);
      const charset = charsetMatch ? charsetMatch[1].trim().toLowerCase() : 'utf-8';
      let text = '';
      if (charset !== 'utf-8' && charset !== 'utf8') {
        const buf = await res.arrayBuffer();
        let decoder;
        try {
          decoder = new TextDecoder(charset);
        } catch (_) {
          decoder = new TextDecoder('gb18030');
        }
        text = decoder.decode(buf);
      } else {
        text = await res.text();
      }
      const rewritten = type.includes('text/css')
        ? RProxy.rewriteCss(text, ctx, ctx.base)
        : rewriteHtml(text, ctx);
      const headers = new Headers(res.headers);
      headers.delete('content-length');
      if (type.includes('text/html')) {
        headers.delete('content-security-policy');
        headers.delete('content-security-policy-report-only');
        headers.delete('x-content-security-policy');
        headers.delete('x-webkit-csp');
        headers.set('content-type', 'text/html; charset=utf-8');
      } else {
        headers.set('content-type', 'text/css; charset=utf-8');
      }
      return new Response(rewritten, {
        status: res.status,
        statusText: res.statusText,
        headers: headers,
      });
    }
    return res;
  })());
});
