(function(scope) {
  scope.RProxy = scope.RProxy || {};

  scope.RProxy.parseContext = function(url) {
    var u;
    try {
      u = new URL(url, scope.location ? scope.location.href : undefined);
    } catch (_) {
      return null;
    }
    if (!u.pathname.startsWith('/rproxy/')) {
      return null;
    }
    var rest = u.pathname.slice('/rproxy/'.length);
    var slash = rest.indexOf('/');
    if (slash === -1) {
      return null;
    }
    var name = rest.slice(0, slash);
    var target = rest.slice(slash + 1);
    var base;
    try {
      if (target.indexOf('://') === -1) {
        base = new URL('http://' + target + u.search + u.hash);
      } else {
        base = new URL(target + u.search + u.hash);
      }
    } catch (_) {
      return null;
    }
    return {
      prefix: '/rproxy/' + name + '/',
      base: base,
    };
  };

  scope.RProxy.rewriteUrl = function(raw, ctx) {
    if (!raw || typeof raw !== 'string') return raw;
    raw = raw.trim();
    if (!raw) return raw;
    if (raw.indexOf('/webui/') === 0 ||
        raw.indexOf('data:') === 0 || raw.indexOf('mailto:') === 0 ||
        raw.indexOf('javascript:') === 0 || raw.indexOf('about:') === 0 || raw.indexOf('#') === 0) {
      return raw;
    }

    if (raw.indexOf(ctx.prefix) === 0 || raw.indexOf('/rproxy/') === 0) {
      return scope.RProxy.cleanLeakedProxyUrl(raw, ctx);
    }

    if (raw.indexOf('//') === 0) {
      // Handle cases where JS generates URL using current location (proxy host)
      if (scope.location && raw.indexOf('//' + scope.location.host) === 0) {
         return ctx.prefix + ctx.base.protocol + '//' + ctx.base.host + raw.slice(2 + scope.location.host.length);
      }
      return ctx.prefix + ctx.base.protocol + raw;
    }

    var parsed;
    try {
      // Use document.baseURI if available (browser context), otherwise ctx.base (sw context or fallback)
      var baseURI = (typeof document !== 'undefined' && document.baseURI) ? document.baseURI : ctx.base;
      parsed = new URL(raw, baseURI);
    } catch (_) {
      return raw;
    }

    if (scope.location && parsed.host === scope.location.host) {
       if (parsed.pathname.indexOf('/rproxy/') === 0) {
         return parsed.pathname + parsed.search + parsed.hash;
       }
       // Rebase path to target
       parsed = new URL(ctx.base.origin + parsed.pathname + parsed.search + parsed.hash);
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return raw;
    }

    // Clean leaked proxy prefixes in query string (e.g. redirectURL)
    // This handles cases where scripts read unmasked location.href and append it to params
    if (parsed.search) {
        parsed.search = scope.RProxy.cleanLeakedProxyUrl(parsed.search, ctx);
    }

    return ctx.prefix + parsed.href;
  };

  scope.RProxy.cleanLeakedProxyUrl = function(value, ctx) {
    if (typeof value !== 'string' || typeof location === 'undefined') {
        return value;
    }

    var originsToCheck = [];
    // Always check current origin (strip trailing slash)
    var curr = location.origin;
    if (curr.endsWith('/')) curr = curr.slice(0, -1);
    originsToCheck.push(curr);

    var safeSuffixRaw = '/rproxy/';
    var safeSuffixEnc = encodeURIComponent(safeSuffixRaw);

    var esc = function(s) { return s.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'); };

    var checks = [];
    originsToCheck.forEach(function(proxyOrigin) {
        checks.push({
            type: 'Encoded (' + proxyOrigin + ')',
            pOrigin: encodeURIComponent(proxyOrigin),
            tOrigin: encodeURIComponent(ctx.base.origin),
            prefix: encodeURIComponent(ctx.prefix),
            suffix: safeSuffixEnc
        });

        // Mixed case (Protocol Encoded, Host Raw) - mainly for current location
        if (proxyOrigin === location.origin || proxyOrigin === curr) {
            checks.push({
                type: 'Mixed (' + proxyOrigin + ')',
                pOrigin: encodeURIComponent(location.protocol + '//') + location.host,
                tOrigin: encodeURIComponent(ctx.base.protocol + '//') + ctx.base.host,
                prefix: encodeURIComponent(ctx.prefix),
                suffix: safeSuffixEnc
            });
        }

        checks.push({
            type: 'Raw (' + proxyOrigin + ')',
            pOrigin: proxyOrigin,
            tOrigin: ctx.base.origin,
            prefix: ctx.prefix,
            suffix: safeSuffixRaw
        });
    });

    checks.forEach(function(c) {
         // 1. Remove full proxy path: origin + /rproxy/name/
         var fullPrefix = c.pOrigin + c.prefix;
         if (value.indexOf(fullPrefix) !== -1) {
             var re = new RegExp(esc(fullPrefix), 'g');
             value = value.replace(re, '');
         } else {
             // No-op.
         }

         // 2. Replace standalone proxy origin
         if (value.indexOf(c.pOrigin) !== -1) {
             var pattern = esc(c.pOrigin);
             var re = new RegExp(pattern, 'g');
             value = value.replace(re, c.tOrigin);
         }
    });

    return value;
  };

  scope.RProxy.patchWindow = function(ctx) {
    if (!ctx || !ctx.base || !ctx.prefix || scope.RProxy._windowPatched) {
      return;
    }
    if (typeof scope.Location === 'undefined' || typeof scope.Document === 'undefined') {
      return;
    }
    scope.RProxy._windowPatched = true;

    var baseInfo = {
      origin: ctx.base.origin,
      host: ctx.base.host,
      hostname: ctx.base.hostname,
      protocol: ctx.base.protocol,
      port: ctx.base.port,
    };
    var currentOrigin = scope.location ? scope.location.origin : '';
    var unmask = function(u) {
      if (!u || typeof u !== 'string') return u;
      if (u.indexOf(ctx.prefix) === 0) {
        var rest = u.slice(ctx.prefix.length);
        if (rest.indexOf('http') === 0) return rest;
        return baseInfo.origin + (rest[0] === '/' ? '' : '/') + rest;
      }
      if (currentOrigin && u.indexOf(currentOrigin + ctx.prefix) === 0) {
        var rest = u.slice((currentOrigin + ctx.prefix).length);
        if (rest.indexOf('http') === 0) return rest;
        return baseInfo.origin + (rest[0] === '/' ? '' : '/') + rest;
      }
      return u;
    };
    var unwrap = function(u) {
      if (!u || typeof u !== 'string') return u;
      var c = scope.RProxy.parseContext(u);
      if (c && c.base) return c.base.href;
      return u;
    };
    var patch = function(obj, prop, getOnly) {
      try {
        var desc = Object.getOwnPropertyDescriptor(obj, prop);
        if (!desc || !desc.get) return;
        Object.defineProperty(obj, prop, {
          configurable: true,
          enumerable: true,
          get: function() {
            if (this === scope.location || this === document.location || this === document) {
              if (baseInfo.hasOwnProperty(prop)) {
                  return baseInfo[prop];
              }
            }
            if ((this === scope.location || this === document.location) && (prop === 'pathname' || prop === 'search' || prop === 'hash')) {
              try {
                var full = unmask(scope.location.href);
                return new URL(full)[prop];
              } catch (e) {}
            }
            var v = desc.get.call(this);
            if (this === scope.location || this === document.location || this === document || (this.tagName === 'A' && prop === 'href')) {
              return unmask(v);
            }
            return v;
          },
          set: getOnly ? desc.set : function(v) { return desc.set.call(this, v); }
        });
      } catch (e) {}
    };

    ['href','origin','protocol','host','hostname','port','pathname','search','hash'].forEach(function(p){ patch(Location.prototype, p); });
    ['URL','documentURI','baseURI','referrer'].forEach(function(p){ patch(Document.prototype, p, true); });
    try {
      Object.defineProperty(scope, 'origin', { configurable: true, enumerable: true, get: function() { return baseInfo.origin; } });
    } catch (e) {}
    // Hook Document extras (domain/cookie)
    var docProps = ['URL', 'documentURI', 'baseURI', 'referrer', 'domain', 'cookie'];
    docProps.forEach(function(prop) {
      var proto = Document.prototype;
      var desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc) { desc = Object.getOwnPropertyDescriptor(HTMLDocument.prototype, prop); proto = HTMLDocument.prototype; }
      if (!desc && (prop === 'referrer' || prop === 'cookie')) { desc = Object.getOwnPropertyDescriptor(document, prop); proto = document; }

      if (desc && desc.get) {
        Object.defineProperty(proto, prop, {
          configurable: true,
          enumerable: true,
          get: function() {
            var raw = desc.get.call(this);
            if (prop === 'cookie') return raw;
            if (prop === 'domain') {
              var c = scope.RProxy.parseContext(scope.location ? scope.location.href : '');
              return (c && c.base) ? c.base.hostname : raw;
            }
            return unwrap(raw);
          },
          set: desc.set ? function(v) {
            if (prop === 'domain') return;
            if (prop === 'cookie' && typeof v === 'string') {
              var parts = v.split(';');
              var newParts = [];
              var c = scope.RProxy.parseContext(scope.location ? scope.location.href : '');
              for (var i = 0; i < parts.length; i++) {
                var part = parts[i].trim();
                var lower = part.toLowerCase();
                if (lower.startsWith('domain=')) continue;
                if (lower.startsWith('path=') && c) {
                  var p = part.split('=')[1] || '/';
                  if (p[0] !== '/') p = '/' + p;
                  newParts.push('path=' + c.prefix + c.base.origin + p);
                  continue;
                }
                newParts.push(part);
              }
              v = newParts.join('; ');
            }
            return desc.set.call(this, v);
          } : undefined
        });
      }
    });

    // Hook window.origin
    try {
      var originDesc = Object.getOwnPropertyDescriptor(scope, 'origin');
      if (originDesc && originDesc.get) {
        Object.defineProperty(scope, 'origin', {
          configurable: true,
          get: function() { return scope.location ? scope.location.origin : baseInfo.origin; }
        });
      }
    } catch (e) {}

    // Hook Location.prototype.toString
    var origLocToString = Location.prototype.toString;
    Location.prototype.toString = function() {
      if (this === scope.location || this === document.location) {
        return this.href;
      }
      return origLocToString.call(this);
    };
  };

  scope.RProxy.rewriteSrcset = function(value, ctx) {
    return value.split(',').map(function(part) {
      var seg = part.trim();
      if (!seg) return seg;
      var space = seg.search(/\s/);
      if (space === -1) {
        return scope.RProxy.rewriteUrl(seg, ctx);
      }
      var url = seg.slice(0, space);
      var desc = seg.slice(space);
      return scope.RProxy.rewriteUrl(url, ctx) + desc;
    }).join(', ');
  };

  scope.RProxy.rewritePing = function(value, ctx) {
    if (!value || typeof value !== 'string') return value;
    return value.split(/\s+/).map(function(item) {
      return scope.RProxy.rewriteUrl(item, ctx);
    }).join(' ');
  };

  scope.RProxy.rewriteCss = function(text, ctx) {
    if (!text || typeof text !== 'string') return text;
    var out = text;
    out = out.replace(/@import\s+(?:url\()?['"]?([^'")\s]+)['"]?\)?/gi, function(match, url) {
      var rewritten = scope.RProxy.rewriteUrl(url, ctx);
      return match.replace(url, rewritten);
    });
    out = out.replace(/url\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi, function(match, quote, url) {
      var rewritten = scope.RProxy.rewriteUrl(url, ctx);
      if (quote) {
        return 'url(' + quote + rewritten + quote + ')';
      }
      return 'url(' + rewritten + ')';
    });
    return out;
  };

  scope.RProxy.rewriteJs = function(text, ctx) {
    if (!text || typeof text !== 'string') return text;
    var out = text;
    // 1. import(...)
    out = out.replace(/(\bimport\s*\(\s*)(["'])([^"']+)\2(\s*\))/g, function(match, pre, quote, url, post) {
        return pre + quote + scope.RProxy.rewriteUrl(url, ctx) + quote + post;
    });
    // 2. import/export ... from "..."
    out = out.replace(/(\b(?:import|export)\s(?:[\s\S]*?)\s+from\s+)(["'])([^"']+)\2/g, function(match, prefix, quote, url) {
        return prefix + quote + scope.RProxy.rewriteUrl(url, ctx) + quote;
    });
    // 3. import "..."
    out = out.replace(/(\bimport\s+)(["'])([^"']+)\2/g, function(match, prefix, quote, url) {
        return prefix + quote + scope.RProxy.rewriteUrl(url, ctx) + quote;
    });
    return out;
  };

  scope.RProxy.rewriteBaseTag = function(tag, ctx, fallbackBase) {
    let baseUrl = fallbackBase;
    const hrefMatch = tag.match(/\bhref\s*=\s*(?:(['"])([^'"]*)\1|([^\s>]+))/i);
    if (hrefMatch) {
      const href = hrefMatch[2] || hrefMatch[3];
      const quote = hrefMatch[1] || '"';
      try {
        baseUrl = new URL(href, ctx.base);
      } catch (_) {
        baseUrl = ctx.base;
      }
      const rewritten = scope.RProxy.rewriteUrl(href, ctx, ctx.base);
      if (hrefMatch[1]) {
        return {
          tag: tag.replace(/\bhref\s*=\s*(['"])([^'"]*)\1/i, 'href=' + hrefMatch[1] + rewritten + hrefMatch[1]),
          baseUrl: baseUrl,
        };
      }
      return {
        tag: tag.replace(/\bhref\s*=\s*([^\s>]+)/i, 'href=' + quote + rewritten + quote),
        baseUrl: baseUrl,
      };
    }
    const rewritten = scope.RProxy.rewriteUrl('/', ctx, ctx.base);
    const endsWithSlash = tag.endsWith('/>');
    const cutLen = endsWithSlash ? 2 : 1;
    const suffix = endsWithSlash ? ' />' : '>';
    let prefix = tag.slice(0, tag.length - cutLen);
    if (!prefix.endsWith(' ')) {
        prefix += ' ';
    }
    return {
      tag: prefix + 'href="' + rewritten + '"' + suffix,
      baseUrl: baseUrl,
    };
  };

  scope.RProxy.rewriteHtmlContent = function(text, ctx) {
    let baseUrl = ctx.base;
    let out = text.replace(/<meta[^>]+http-equiv\s*=\s*(['"]?)content-security-policy\1[^>]*>/gi, '');
    out = out.replace(/<base\b[^>]*>/i, (tag) => {
      const rewritten = scope.RProxy.rewriteBaseTag(tag, ctx, baseUrl);
      baseUrl = rewritten.baseUrl;
      return rewritten.tag;
    });
    out = out.replace(/\bstyle\s*=\s*(['"])([^'"]*)\1/gi,
      (match, quote, value) => {
        const rewritten = scope.RProxy.rewriteCss(value, ctx, baseUrl);
        return 'style=' + quote + rewritten + quote;
      });
    out = out.replace(/\bping\s*=\s*(['"])([^'"]*)\1/gi,
      (match, quote, value) => {
        const rewritten = scope.RProxy.rewritePing(value, ctx, baseUrl);
        return 'ping=' + quote + rewritten + quote;
      });
    out = out.replace(/\b(href|src|action|poster)\s*=\s*(['"])([^'"]+)\2/gi,
      (match, attr, quote, url) => {
        const rewritten = scope.RProxy.rewriteUrl(url, ctx, baseUrl);
        return attr + '=' + quote + rewritten + quote;
      });
    out = out.replace(/\bsrcset\s*=\s*(['"])([^'"]+)\1/gi,
      (match, quote, value) => {
        return 'srcset=' + quote + scope.RProxy.rewriteSrcset(value, ctx, baseUrl) + quote;
      });
    out = out.replace(/<style\b[^>]*>([\s\S]*?)<\/style>/gi,
      (match, css) => {
        const rewritten = scope.RProxy.rewriteCss(css, ctx, baseUrl);
        return match.replace(css, rewritten);
      });
    out = out.replace(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi, (match, attrs, content) => {
        const typeMatch = attrs.match(/\btype\s*=\s*(?:(['"])(.*?)\1|([^\s>]+))/i);
        const type = typeMatch ? (typeMatch[2] || typeMatch[3]).toLowerCase() : 'text/javascript';
        if (type === 'application/json' || type === 'application/ld+json' || type.indexOf('template') !== -1) {
            return match;
        }
        const rewritten = scope.RProxy.rewriteJs(content, ctx);
        return match.replace(content, rewritten);
    });
    return out;
  };

})(typeof self !== 'undefined' ? self : window);
