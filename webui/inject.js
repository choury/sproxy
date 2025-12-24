(function(){
  var ctx = RProxy.parseContext(location.href);
  if (ctx && window.console && console.log) {
    console.log('[rproxy] ctx', ctx.prefix, ctx.base && ctx.base.href);
  }
  if (!ctx) return;
  
  function rewrite(url) {
    return RProxy.rewriteUrl(url, ctx);
  }

  try {
    if (window.navigation && navigation.addEventListener) {
      navigation.addEventListener('navigate', function(event){
        try {
          if (!event || event.hashChange || event.downloadRequest) return;
          var dest = event.destination;
          if (!dest || !dest.url) return;
          var rewritten = rewrite(dest.url);
          if (rewritten === dest.url || rewritten === window.location.href) return;
          if (event.cancelable) event.preventDefault();
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
  if (origPushState) {
    history.pushState = function(state, unused, url){
      if (url && typeof url === 'string') {
        try { url = rewrite(url); } catch(e){}
      } else if (url && typeof url === 'object' && url.toString) {
         try { url = rewrite(url.toString()); } catch(e){}
      }
      return origPushState.call(this, state, unused, url);
    };
  }
  var origReplaceState = history.replaceState;
  if (origReplaceState) {
    history.replaceState = function(state, unused, url){
      if (url && typeof url === 'string') {
        try { url = rewrite(url); } catch(e){}
      } else if (url && typeof url === 'object' && url.toString) {
         try { url = rewrite(url.toString()); } catch(e){}
      }
      return origReplaceState.call(this, state, unused, url);
    };
  }
  window.addEventListener('click', function(e){
      if (e.defaultPrevented) return;
      var target = e.target;
      while(target && target !== document){
          if(target.tagName === 'A' && target.href){
              var href = target.getAttribute('href');
              if(href && !href.startsWith('javascript:') && !href.startsWith('#')){
                  var rewritten = rewrite(href);
                  if(rewritten !== href) {
                       target.setAttribute('href', rewritten);
                  }
              }
              break;
          }
          target = target.parentNode;
      }
  }, true);
  var origBeacon = navigator.sendBeacon;
  if (origBeacon) {
    navigator.sendBeacon = function(url, data){
      try { url = rewrite(url); } catch (e) {}
      return origBeacon.call(this, url, data);
    };
  }

  var origSet = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value){
    if (typeof value === 'string') {
      if (name === 'href' || name === 'src' || name === 'action' || name === 'poster') value = RProxy.rewriteUrl(value, ctx);
      else if (name === 'srcset') value = RProxy.rewriteSrcset(value, ctx);
      else if (name === 'ping') value = RProxy.rewritePing(value, ctx);
      else if (name === 'style') value = RProxy.rewriteCss(value, ctx);
      else if (name === 'href' && this.tagName === 'BASE') value = RProxy.rewriteUrl(value, ctx);
    }
    return origSet.call(this, name, value);
  };
  function patchProp(proto, prop, handler){
    if (!proto) return;
    var desc = Object.getOwnPropertyDescriptor(proto, prop);
    if (!desc || !desc.set || desc.set.__rproxy_patched) return;
    Object.defineProperty(proto, prop, {
      configurable: true,
      enumerable: desc.enumerable,
      get: desc.get,
      set: function(value){
        return desc.set.call(this, handler(value, ctx));
      }
    });
    Object.defineProperty(Object.getOwnPropertyDescriptor(proto, prop).set, '__rproxy_patched', { value: true });
  }
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
  patchProp(CSSStyleDeclaration && CSSStyleDeclaration.prototype, 'cssText', RProxy.rewriteCss);
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
    var val = el.getAttribute(name);
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
    if (el.tagName === 'A') patchAttr(el, 'href', RProxy.rewriteUrl);
    if (el.tagName === 'A') patchAttr(el, 'ping', RProxy.rewritePing);
    if (el.tagName === 'IMG' || el.tagName === 'SCRIPT' || el.tagName === 'IFRAME') patchAttr(el, 'src', RProxy.rewriteUrl);
    if (el.tagName === 'FORM') patchAttr(el, 'action', RProxy.rewriteUrl);
    if (el.tagName === 'VIDEO' || el.tagName === 'AUDIO') patchAttr(el, 'poster', RProxy.rewriteUrl);
    if (el.hasAttribute && el.hasAttribute('srcset')) patchAttr(el, 'srcset', RProxy.rewriteSrcset);
    if (el.hasAttribute && el.hasAttribute('style')) patchAttr(el, 'style', RProxy.rewriteCss);
    if (el.tagName === 'BASE') patchAttr(el, 'href', RProxy.rewriteUrl);
    if (el.tagName === 'STYLE') patchStyleEl(el);
  }
  var baseEl = document.querySelector('base');
  if (baseEl) {
    var before = baseEl.getAttribute('href') || '';
    var rewritten = RProxy.rewriteUrl(before || '/', ctx);
    if (rewritten !== before) {
      baseEl.setAttribute('href', rewritten);
      if (window.console && console.log) {
        console.log('[rproxy] base href', before, '->', baseEl.getAttribute('href'));
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
