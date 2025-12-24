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
    if (raw.indexOf(ctx.prefix) === 0 || raw.indexOf('/rproxy/') === 0 || 
        raw.indexOf('data:') === 0 || raw.indexOf('mailto:') === 0 ||
        raw.indexOf('javascript:') === 0 || raw.indexOf('about:') === 0 || raw.indexOf('#') === 0) {
      return raw;
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
    return ctx.prefix + parsed.href;
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
    const suffix = tag.endsWith('/>') ? ' />' : '>';
    return {
      tag: tag.slice(0, tag.length - suffix.length) + ' href="' + rewritten + '"' + suffix,
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
    return out;
  };

})(typeof self !== 'undefined' ? self : window);
