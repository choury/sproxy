(function(){
  var ctx = RProxy.parseContext(location.href);
  if (ctx && window.console && console.log) {
    console.log('[rproxy] ctx', ctx.prefix, ctx.base && ctx.base.href);
  }
  if (!ctx) return;
  
  function rewrite(url) {
    return RProxy.rewriteUrl(url, ctx);
  }
  function toLower(name) {
    return typeof name === 'string' ? name.toLowerCase() : '';
  }
  var attrRewriters = {
    href: RProxy.rewriteUrl,
    src: RProxy.rewriteUrl,
    action: RProxy.rewriteUrl,
    poster: RProxy.rewriteUrl,
    srcset: RProxy.rewriteSrcset,
    ping: RProxy.rewritePing,
    style: RProxy.rewriteCss,
  };
  function rewriteAttrValue(name, value) {
    var lower = toLower(name);
    if (lower === 'href') {
      value = RProxy.cleanLeakedProxyUrl(value, ctx);
    }
    var handler = attrRewriters[lower];
    if (handler) return handler(value, ctx);
    return value;
  }
  function shouldUnwrapAttr(name) {
    var lower = toLower(name);
    return lower === 'href' || lower === 'src' || lower === 'action' || lower === 'poster';
  }

  var lastNavigateRewrite = null;
  var lastNavigateAt = 0;
  try {
    if (window.navigation && navigation.addEventListener) {
      navigation.addEventListener('navigate', function(event){
        try {
          if (!event || event.hashChange || event.downloadRequest) return;

          var dest = event.destination;

          // Avoid forcing full reloads on same-document SPA navigations (history.pushState/replaceState).
          // Let the app/router handle these; our history.pushState hook already rewrites URLs.
          if (dest && dest.sameDocument && (event.navigationType === 'push' || event.navigationType === 'replace')) return;
          if (!dest || !dest.url) return;
          var rewritten = rewrite(dest.url);
          var absRewritten = rewritten;
          try {
            absRewritten = new URL(rewritten, window.location.href).href;
            if (absRewritten === dest.url || absRewritten === window.location.href) return;
          } catch (e) {
            if (rewritten === dest.url || rewritten === window.location.href) return;
          }
          var now = Date.now ? Date.now() : +new Date();
          if (lastNavigateRewrite && absRewritten === lastNavigateRewrite && now - lastNavigateAt < 1000) return;
          if (event.cancelable) event.preventDefault();
          lastNavigateRewrite = absRewritten;
          lastNavigateAt = now;
          window.location.href = rewritten;
        } catch (e) {}
      });
    }
  } catch (e) {}
  var origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function(input, init){
      try {
        if (typeof input === 'string') {
          input = rewrite(input);
        } else if (input && typeof input === 'object' && input.url) {
          input = new Request(rewrite(input.url), input);
        }
      } catch (e) {}
      return origFetch.call(this, input, init);
    };
  }
  var origOpen = XMLHttpRequest.prototype.open;
  if (origOpen) {
    XMLHttpRequest.prototype.open = function(method, url){
      try { url = rewrite(url); } catch (e) {}
      return origOpen.apply(this, arguments);
    };
  }
  var origWinOpen = window.open;
  if (origWinOpen) {
    window.open = function(url, target, features){
      if (url && typeof url === 'string') {
        try { url = rewrite(url); } catch(e){}
      }
      return origWinOpen.call(this, url, target, features);
    };
  }
  var origPushState = history.pushState;
  if (origPushState && (!window.History || !window.History.prototype || !window.History.prototype.__rproxy_patched)) {
    history.pushState = function(state, unused, url){
      if (url && typeof url === 'string') {
        try { url = RProxy.normalizeProxyPath(rewrite(url)); } catch(e){}
      } else if (url && typeof url === 'object' && url.toString) {
         try { url = RProxy.normalizeProxyPath(rewrite(url.toString())); } catch(e){}
      }
      return origPushState.call(this, state, unused, url);
    };
  }
  var origReplaceState = history.replaceState;
  if (origReplaceState && (!window.History || !window.History.prototype || !window.History.prototype.__rproxy_patched)) {
    history.replaceState = function(state, unused, url){
      if (url && typeof url === 'string') {
        try { url = RProxy.normalizeProxyPath(rewrite(url)); } catch(e){}
      } else if (url && typeof url === 'object' && url.toString) {
         try { url = RProxy.normalizeProxyPath(rewrite(url.toString())); } catch(e){}
      }
      return origReplaceState.call(this, state, unused, url);
    };
  }

  window.addEventListener('click', function(e){
      if (e.defaultPrevented) return;
      
      var path = e.composedPath ? e.composedPath() : [];
      var target = path.length > 0 ? path[0] : e.target;
      
      // Use composedPath to find the anchor tag even inside Shadow DOM
      var foundLink = false;
      for (var i = 0; i < path.length; i++) {
          var node = path[i];
          if (node.tagName === 'A' && node.href) {
              target = node; // Treat this as the target
              foundLink = true;
              break;
          }
          if (node === document) break;
      }
      
      if (!foundLink) {
           // Fallback for browsers without composedPath or non-shadow clicks
           target = e.target;
           while(target && target !== document){
               if(target.tagName === 'A' && target.href){
                   foundLink = true;
                   break;
               }
               target = target.parentNode;
           }
      }

      if(foundLink){
          var href = target.getAttribute('href');
          if(href && !href.startsWith('javascript:') && !href.startsWith('#')){
              var rewritten = rewrite(href);
              if(rewritten !== href) {
                   target.setAttribute('href', rewritten);
              }
          }
      }
  }, true);
  var origBeacon = navigator.sendBeacon;
  if (origBeacon) {
    navigator.sendBeacon = function(url, data){
      try { url = rewrite(url); } catch (e) {}
      return origBeacon.call(this, url, data);
    };
  }

  function unwrap(url) {
    if (!url || typeof url !== 'string') return url;
    var c = RProxy.parseContext(url);
    if (c && c.base) return c.base.href;
    return url;
  }

  var origGetAttr = Element.prototype.getAttribute;
  Element.prototype.getAttribute = function(name) {
    var val = origGetAttr.call(this, name);
    if (typeof val === 'string' && shouldUnwrapAttr(name)) {
       if (val.trim().indexOf('#') === 0) return val;
       return unwrap(val);
    }
    return val;
  };

  var origSet = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value){
    if (typeof value === 'string') {
      value = rewriteAttrValue(name, value);
      if (toLower(name) === 'sandbox' && this.tagName === 'IFRAME') {
        if (!/\ballow-scripts\b/i.test(value)) value = (value ? value + ' ' : '') + 'allow-scripts';
      }
    }
    return origSet.call(this, name, value);
  };

  if (RProxy.patchWindow) {
    RProxy.patchWindow(ctx);
  }

  function patchProp(proto, prop, handler){
    if (!proto) return;
    var desc = Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || desc.__rproxy_patched) return;
    var newDesc = {
      configurable: true,
      enumerable: desc.enumerable,
    };
    if (desc.get) {
      newDesc.get = function() {
        var val = desc.get.call(this);
        if (typeof val === 'string' && shouldUnwrapAttr(prop)) {
          if (prop === 'href' && typeof origGetAttr === 'function') {
            var rawHref = origGetAttr.call(this, 'href');
            if (typeof rawHref === 'string') {
              var trimmedRawHref = rawHref.trim();
              if (trimmedRawHref.indexOf('#') === 0) return val;
            }
          }
          return unwrap(val);
        }
        return val;
      };
    }
    if (desc.set) {
      newDesc.set = function(value) {
        if (typeof value === 'string') {
          value = handler(value, ctx);
        }
        return desc.set.call(this, value);
      };
    }
    Object.defineProperty(proto, prop, newDesc);
    Object.defineProperty(newDesc.get || newDesc.set, '__rproxy_patched', { value: true, enumerable: false });
  }

  function patchGetter(proto, prop, mapper){
    if (!proto) return;
    var desc = Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.get || desc.__rproxy_patched) return;
    var newDesc = {
      configurable: true,
      enumerable: desc.enumerable,
      get: function() {
        return mapper(desc.get.call(this));
      },
      set: desc.set,
    };
    Object.defineProperty(proto, prop, newDesc);
    Object.defineProperty(newDesc.get, '__rproxy_patched', { value: true, enumerable: false });
  }

  function wrapCtor(name) {
      var Orig = window[name];
      if (!Orig) return;
      var Wrapped = function(url, options) {
          return new Orig(rewrite(url), options);
      };
      Wrapped.prototype = Orig.prototype;
      try { Object.setPrototypeOf(Wrapped, Orig); } catch(e) {}
      try {
          Object.getOwnPropertyNames(Orig).forEach(function(key) {
              if (key in Wrapped) return;
              try { Wrapped[key] = Orig[key]; } catch(e) {}
          });
      } catch(e) {}
      window[name] = Wrapped;
  }
  wrapCtor('Worker');
  wrapCtor('SharedWorker');
  if (window.PerformanceResourceTiming) {
      patchGetter(PerformanceResourceTiming.prototype, 'name', unwrap);
  }
  if (window.PerformanceNavigationTiming) {
      patchGetter(PerformanceNavigationTiming.prototype, 'name', unwrap);
  }
  if (window.performance) {
      var origGetEntriesByType = performance.getEntriesByType;
      if (origGetEntriesByType) {
          performance.getEntriesByType = function(type) {
              var entries = origGetEntriesByType.call(this, type);
              if (type === 'navigation' && Array.isArray(entries)) {
                  entries.forEach(function(entry) {
                      if (!entry || typeof entry.name !== 'string') return;
                      var fixed = unwrap(entry.name);
                      if (fixed === entry.name) return;
                      try {
                          Object.defineProperty(entry, 'name', {
                              configurable: true,
                              enumerable: true,
                              get: function() { return fixed; }
                          });
                      } catch (e) {
                          try { entry.name = fixed; } catch (e2) {}
                      }
                  });
              }
              return entries;
          };
      }
      var origGetEntriesByName = performance.getEntriesByName;
      if (origGetEntriesByName) {
          performance.getEntriesByName = function(name, type) {
              var entries = origGetEntriesByName.call(this, name, type);
              if (type === 'navigation' && Array.isArray(entries)) {
                  entries.forEach(function(entry) {
                      if (!entry || typeof entry.name !== 'string') return;
                      var fixed = unwrap(entry.name);
                      if (fixed === entry.name) return;
                      try {
                          Object.defineProperty(entry, 'name', {
                              configurable: true,
                              enumerable: true,
                              get: function() { return fixed; }
                          });
                      } catch (e) {
                          try { entry.name = fixed; } catch (e2) {}
                      }
                  });
              }
              return entries;
          };
      }
  }
  if (window.XMLHttpRequest) {
      patchProp(XMLHttpRequest.prototype, 'responseURL', function(v){return v;});
  }
  if (window.NavigationHistoryEntry) {
      patchGetter(NavigationHistoryEntry.prototype, 'url', unwrap);
  }
  if (window.NavigationDestination) {
      patchGetter(NavigationDestination.prototype, 'url', unwrap);
  }
  if (window.WebSocket) {
      var origWS = window.WebSocket;

      // Wrap WebSocket to rewrite URL for rproxy, but preserve static constants
      // (WebSocket.OPEN/CONNECTING/CLOSING/CLOSED) and other static props.
      // NOTE: Avoid block-scoped function declarations for broad browser compatibility
      // (Annex B semantics can differ). Use a function expression instead.
      var WrappedWS = function(url, protocols) {
          return new origWS(rewrite(url), protocols);
      };
      WrappedWS.prototype = origWS.prototype;

      // Preserve WebSocket static constants and other static properties.
      // Prefer copying full descriptors (writable/configurable/enumerable) to better match native API surface.
      try {
          var skip = { length: 1, name: 1, prototype: 1, arguments: 1, caller: 1 };
          Object.getOwnPropertyNames(origWS).forEach(function(k){
              if (Object.prototype.hasOwnProperty.call(WrappedWS, k)) return;
              if (skip[k]) return;
              var desc;
              try { desc = Object.getOwnPropertyDescriptor(origWS, k); } catch (e) { desc = null; }
              if (!desc) return;
              try {
                  Object.defineProperty(WrappedWS, k, desc);
              } catch (e) {
                  // Fallback: best-effort assignment.
                  try { WrappedWS[k] = origWS[k]; } catch (e2) {}
              }
          });
      } catch (e) {}

      // Preserve prototype chain where possible (after defining own props).
      try { Object.setPrototypeOf(WrappedWS, origWS); } catch (e) {}

      // Preserve the constructor name when possible.
      try { Object.defineProperty(WrappedWS, 'name', { value: 'WebSocket' }); } catch (e) {}

      window.WebSocket = WrappedWS;
  }
  ['HTMLAnchorElement', 'HTMLAreaElement'].forEach(function(cls){
      var proto = window[cls] && window[cls].prototype;
      if (!proto) return;
      ['protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash', 'origin'].forEach(function(prop){
          var desc = Object.getOwnPropertyDescriptor(proto, prop);
          if (desc && desc.get) {
              Object.defineProperty(proto, prop, {
                  configurable: true,
                  enumerable: true,
                  get: function() {
                      var val = desc.get.call(this);
                      var c = RProxy.parseContext(this.href);
                      if (c && c.base) return c.base[prop];
                      return val;
                  },
                  set: desc.set ? function(v) { return desc.set.call(this, v); } : undefined
              });
          }
      });
  });

  patchProp(HTMLAnchorElement && HTMLAnchorElement.prototype, 'href', RProxy.rewriteUrl);
  patchProp(HTMLAreaElement && HTMLAreaElement.prototype, 'href', RProxy.rewriteUrl);
  patchProp(HTMLLinkElement && HTMLLinkElement.prototype, 'href', RProxy.rewriteUrl);
  patchProp(HTMLBaseElement && HTMLBaseElement.prototype, 'href', RProxy.rewriteUrl);
  patchProp(HTMLFormElement && HTMLFormElement.prototype, 'action', RProxy.rewriteUrl);
  patchProp(HTMLImageElement && HTMLImageElement.prototype, 'src', RProxy.rewriteUrl);
  patchProp(HTMLScriptElement && HTMLScriptElement.prototype, 'src', RProxy.rewriteUrl);
  patchProp(HTMLIFrameElement && HTMLIFrameElement.prototype, 'src', RProxy.rewriteUrl);
  patchProp(HTMLVideoElement && HTMLVideoElement.prototype, 'poster', RProxy.rewriteUrl);
  patchProp(HTMLVideoElement && HTMLVideoElement.prototype, 'src', RProxy.rewriteUrl);
  patchProp(HTMLAudioElement && HTMLAudioElement.prototype, 'src', RProxy.rewriteUrl);
  patchProp(HTMLSourceElement && HTMLSourceElement.prototype, 'src', RProxy.rewriteUrl);
  patchProp(HTMLAnchorElement && HTMLAnchorElement.prototype, 'ping', RProxy.rewritePing);
  // patchProp(CSSStyleDeclaration && CSSStyleDeclaration.prototype, 'cssText', RProxy.rewriteCss);
  var origSetProp = CSSStyleDeclaration && CSSStyleDeclaration.prototype && CSSStyleDeclaration.prototype.setProperty;
  if (origSetProp) {
    CSSStyleDeclaration.prototype.setProperty = function(name, value, priority){
      try {
        if (typeof value === 'string') value = RProxy.rewriteCss(value, ctx);
      } catch (e) {}
      return origSetProp.call(this, name, value, priority);
    };
  }
  function patchAttr(el, name, handler){
    var val = (typeof origGetAttr === 'function') ? origGetAttr.call(el, name) : el.getAttribute(name);
    if (!val) return;
    var rewritten = handler ? handler(val, ctx) : val;
    if (rewritten !== val) el.setAttribute(name, rewritten);
  }
  function patchStyleEl(el){
    if (!el || el.tagName !== 'STYLE') return;
    var css = el.textContent || '';
    var rewritten = RProxy.rewriteCss(css, ctx);
    if (rewritten !== css) el.textContent = rewritten;
  }
  function patchNode(node){
    if (!node || node.nodeType !== 1) return;
    var el = node;
    if (el.tagName === 'A') {
      patchAttr(el, 'href', RProxy.rewriteUrl);
      patchAttr(el, 'ping', RProxy.rewritePing);
    }
    if (el.tagName === 'IMG' || el.tagName === 'SCRIPT' || el.tagName === 'IFRAME') {
      patchAttr(el, 'src', RProxy.rewriteUrl);
    }
    if (el.tagName === 'FORM') patchAttr(el, 'action', RProxy.rewriteUrl);
    if (el.tagName === 'VIDEO' || el.tagName === 'AUDIO') patchAttr(el, 'poster', RProxy.rewriteUrl);
    if (el.hasAttribute && el.hasAttribute('srcset')) patchAttr(el, 'srcset', RProxy.rewriteSrcset);
    if (el.hasAttribute && el.hasAttribute('style')) patchAttr(el, 'style', RProxy.rewriteCss);
    if (el.tagName === 'BASE') patchAttr(el, 'href', RProxy.rewriteUrl);
    if (el.tagName === 'STYLE') patchStyleEl(el);
    if (el.tagName === 'IFRAME' && el.hasAttribute && el.hasAttribute('sandbox')) {
      var sb = el.getAttribute('sandbox') || '';
      if (!/\ballow-scripts\b/i.test(sb)) {
        el.setAttribute('sandbox', (sb ? sb + ' ' : '') + 'allow-scripts');
      }
    }
  }
  var mo = new MutationObserver(function(muts){
    muts.forEach(function(m){
      m.addedNodes && m.addedNodes.forEach(function(n){
        patchNode(n);
        if (n.querySelectorAll) {
          n.querySelectorAll('[href],[src],[action],[poster],[srcset],[ping],base[href]').forEach(patchNode);
          n.querySelectorAll('style').forEach(patchStyleEl);
        }
      });
    });
  });
  mo.observe(document.documentElement, { childList: true, subtree: true });
  document.querySelectorAll('[href],[src],[action],[poster],[srcset],[ping],base[href],style').forEach(patchNode);
})();
