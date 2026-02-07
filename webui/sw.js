importScripts('/webui/rproxy_core.js');

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

function rewriteHtml(text, ctx) {
  const u = ctx.base;
  const jsString = (value) => JSON.stringify(value).replace(/</g, '\\u003c');
  const nonceMatch = text.match(/<script\b[^>]*\bnonce=(["'])([^"']+)\1/i);
  const nonceAttr = nonceMatch ? ` nonce="${nonceMatch[2]}"` : '';
  const inlineScript = `
    (function(){
      var ctx = {
        prefix: ${jsString(ctx.prefix)},
        base: {
          href: ${jsString(u.href)},
          origin: ${jsString(u.origin)},
          host: ${jsString(u.host)},
          hostname: ${jsString(u.hostname)},
          protocol: ${jsString(u.protocol)},
          port: ${jsString(u.port)},
          pathname: ${jsString(u.pathname)},
          search: ${jsString(u.search)},
          hash: ${jsString(u.hash)}
        }
      };
      window.__rproxy_ctx = ctx;

      function rewrite(raw) {
          if (window.RProxy && RProxy.rewriteUrl) return RProxy.rewriteUrl(raw, ctx);
          return raw;
      }

      function applyPatches(win) {
          if (win.__rproxy_patched) return;
          try {
              var History = win.History;
              var Location = win.Location;
              var history = win.history;
              var location = win.location;

              function wrapHistory(proto, method) {
                  var orig = proto && proto[method];
                  if (!orig) return;
                  return function() {
                    var args = Array.prototype.slice.call(arguments);
                    if (args.length > 2) {
                      var url = args[2];
                      if (typeof url === 'string') args[2] = RProxy.normalizeProxyPath(rewrite(url));
                      else if (url && typeof url === 'object' && url.toString) args[2] = RProxy.normalizeProxyPath(rewrite(url.toString()));
                    }
                    return orig.apply(this, args);
                  };
              }
              function wrapLoc(proto, method) {
                  var orig = proto && proto[method];
                  if (!orig) return;
                  return function(url) {
                    if (typeof url === 'string') url = rewrite(url);
                    else if (url && typeof url === 'object' && url.toString) url = rewrite(url.toString());
                    return orig.call(this, url);
                  };
              }

              var proto = History && History.prototype;
              if (proto) {
                  var push = wrapHistory(proto, 'pushState');
                  var replace = wrapHistory(proto, 'replaceState');
                  if (push) Object.defineProperty(proto, 'pushState', { configurable: true, writable: false, value: push });
                  if (replace) Object.defineProperty(proto, 'replaceState', { configurable: true, writable: false, value: replace });
                  Object.defineProperty(proto, '__rproxy_patched', { value: true, enumerable: false });
              }

              var locProto = Location && Location.prototype;
              if (locProto) {
                  var assign = wrapLoc(locProto, 'assign');
                  var replaceLoc = wrapLoc(locProto, 'replace');
                  if (assign) Object.defineProperty(locProto, 'assign', { configurable: true, writable: false, value: assign });
                  if (replaceLoc) Object.defineProperty(locProto, 'replace', { configurable: true, writable: false, value: replaceLoc });
                  Object.defineProperty(locProto, '__rproxy_patched', { value: true, enumerable: false });
              }

              if (win.navigation) {
                    if (win.navigation.navigate) {
                      var origNav = win.navigation.navigate;
                      win.navigation.navigate = function(url, opts) {
                        if (typeof url === 'string') url = rewrite(url);
                        else if (url && typeof url === 'object' && url.toString) url = rewrite(url.toString());
                        return origNav.call(this, url, opts);
                      };
                    }
                    if (win.navigation.updateCurrentEntry) {
                        var origUpdate = win.navigation.updateCurrentEntry;
                        win.navigation.updateCurrentEntry = function(opts) {
                            return origUpdate.call(this, opts);
                        };
                    }
                    Object.defineProperty(win.navigation, '__rproxy_patched', { value: true, enumerable: false });
              }

              win.__rproxy_patched = true;
          } catch(e) {}
      }

      // 1. Patch main window
      applyPatches(window);

      // 2. Patch iframes via HTMLIFrameElement.prototype.contentWindow
      try {
          var iframeProto = window.HTMLIFrameElement && window.HTMLIFrameElement.prototype;
          if (iframeProto) {
              var origContentWindowDesc = Object.getOwnPropertyDescriptor(iframeProto, 'contentWindow');
              var origContentWindow = origContentWindowDesc ? origContentWindowDesc.get : null;

              if (origContentWindow) {
                  Object.defineProperty(iframeProto, 'contentWindow', {
                      configurable: true,
                      enumerable: true,
                      get: function() {
                          var win = origContentWindow.call(this);
                          if (win) applyPatches(win);
                          return win;
                      }
                  });
              }
          }
      } catch(e) {}

      if (window.RProxy && RProxy.patchWindow) {
        RProxy.patchWindow(ctx);
      }
    })();
  `;
  const inject = `<script${nonceAttr} src="/webui/rproxy_core.js"></script><script${nonceAttr}>` + inlineScript + `</script><script${nonceAttr} src="/webui/inject.js"></script>`;
  let out = RProxy.rewriteHtmlContent(text, ctx);
  out = out.replace(/<iframe\b([^>]*?)\bsandbox=(["'])(.*?)\2([^>]*?)>/gi, (all, pre, q, val, post) => {
    if (/\ballow-scripts\b/i.test(val)) return all;
    const next = (val ? val + ' ' : '') + 'allow-scripts';
    return `<iframe${pre} sandbox=${q}${next}${q}${post}>`;
  });
  out = out.replace(/<iframe\b([^>]*?)\bsandbox\b([^>]*?)>/gi, (all, pre, post) => {
    if (/\bsandbox=/.test(all)) return all;
    return `<iframe${pre} sandbox="allow-scripts"${post}>`;
  });

  if (out.match(/<head\b[^>]*>/i)) {
    out = out.replace(/(<head\b[^>]*>)/i, '$1' + inject);
  } else if (out.match(/<body\b[^>]*>/i)) {
    out = out.replace(/(<body\b[^>]*>)/i, '$1' + inject);
  } else if (out.match(/<html\b[^>]*>/i)) {
    out = out.replace(/(<html\b[^>]*>)/i, '$1' + inject);
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
    if (res.status === 0) {
      return res;
    }
    if (!ctx) {
      return res;
    }
    const type = res.headers.get('content-type') || '';
    const dest = event.request.destination || '';
    const isDoc = event.request.mode === 'navigate' || dest === 'document' || dest === 'iframe';
    let body = res.body;
    let newType = null;

    // specific status codes that must not have a body
    if ([204, 205, 304].includes(res.status)) {
      body = null;
    } else if ((type.includes('text/html') && isDoc) || type.includes('text/css') || type.includes('javascript') || type.includes('ecmascript')) {
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

      if (type.includes('text/css')) {
        body = RProxy.rewriteCss(text, ctx, ctx.base);
        newType = 'text/css; charset=utf-8';
      } else if (type.includes('javascript') || type.includes('ecmascript')) {
        body = RProxy.rewriteJs(text, ctx);
        newType = 'application/javascript; charset=utf-8';
      } else {
        body = rewriteHtml(text, ctx);
        newType = 'text/html; charset=utf-8';
      }
    }

    const headers = new Headers(res.headers);
    if (newType) {
        headers.delete('content-length');
        headers.set('content-type', newType);
    }

    // Common header cleanup for all proxied content
    headers.delete('content-security-policy');
    headers.delete('content-security-policy-report-only');
    headers.delete('x-content-security-policy');
    headers.delete('x-webkit-csp');
    headers.set('access-control-allow-origin', '*');
    headers.set('timing-allow-origin', '*');

    return new Response(body, {
      status: res.status,
      statusText: res.statusText,
      headers: headers,
    });
  })());
});
