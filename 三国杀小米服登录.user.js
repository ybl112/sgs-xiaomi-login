// ==UserScript==
// @name         三国杀一将成名 · 小米服登录
// @namespace    local.sgs.xiaomi.browser
// @version      0.2.6
// @updateURL    https://raw.githubusercontent.com/ybl112/sgs-xiaomi-login/main/三国杀小米服登录.user.js
// @downloadURL  https://raw.githubusercontent.com/ybl112/sgs-xiaomi-login/main/三国杀小米服登录.user.js
// @description  在三国杀官网使用本人小米账号授权并接入小米服。浏览器测试版。
// @match        https://web.sanguosha.com/*
// @match        http://game.xiaomi.com/oauthcallback/mioauth*
// @match        https://game.xiaomi.com/oauthcallback/mioauth*
// @run-at       document-start
// @sandbox      raw
// @noframes
// @grant        unsafeWindow
// @grant        GM_xmlhttpRequest
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_deleteValue
// @grant        GM_listValues
// @grant        GM_addValueChangeListener
// @grant        GM_removeValueChangeListener
// @grant        GM_registerMenuCommand
// @grant        GM_openInTab
// @connect      account.migc.g.mi.com
// @connect      anysdk.dobest.cn
// @connect      10th-sdk-login.sanguosha.com
// @connect      raw.githubusercontent.com
// ==/UserScript==

(() => {
  'use strict';
  if (window.top !== window) return;
  /* CORE-BEGIN */
const XiaomiCore = (() => {
  const endpoints = Object.freeze({
    oauth: 'https://account.migc.g.mi.com/misdk/v2/oauth',
    session: 'https://account.migc.g.mi.com/migc-sdk-account/getLoginAppAccount_v2',
    channel: 'https://anysdk.dobest.cn/v1/login',
    launch: 'https://10th-sdk-login.sanguosha.com/xiaomi2/app/login'
  });
  const transportKey = new TextEncoder().encode('migc_game_sdkkey'); // Public APK transport constant, not an account secret.
  const zero = new Uint8Array(16);
  const key = () => crypto.subtle.importKey('raw', transportKey, 'AES-CBC', false, ['encrypt', 'decrypt']);
  const base64 = bytes => btoa(String.fromCharCode(...bytes));
  function unbase64(text) {
    if (typeof text !== 'string' || text.length > 1048576) throw new Error('SDK 响应格式错误');
    return Uint8Array.from(atob(text.trim()), c => c.charCodeAt(0));
  }
  // The SDK requires ECB. Native CBC on an isolated block with zero IV gives E_K(block).
  // Discard the extra block added by WebCrypto's mandatory CBC padding.
  async function encode(text) {
    const raw = new TextEncoder().encode(text);
    const pad = 16 - raw.length % 16;
    const input = new Uint8Array(raw.length + pad);
    input.set(raw); input.fill(pad, raw.length);
    const k = await key(), output = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i += 16) {
      const encrypted = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-CBC', iv: zero}, k, input.slice(i, i + 16)));
      output.set(encrypted.subarray(0, 16), i);
    }
    return base64(output);
  }
  async function decode(text) {
    const input = unbase64(text);
    if (!input.length || input.length % 16) throw new Error('SDK 响应长度错误');
    const k = await key(), output = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i += 16) {
      const c = input.slice(i, i + 16);
      // Append E_K(C xor 0x10) so the second CBC plaintext block is valid PKCS7 padding.
      const paddingInput = c.map(value => value ^ 16);
      const paddingCipher = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-CBC', iv: zero}, k, paddingInput));
      const pair = new Uint8Array(32); pair.set(c); pair.set(paddingCipher.subarray(0, 16), 16);
      const plain = new Uint8Array(await crypto.subtle.decrypt({name: 'AES-CBC', iv: zero}, k, pair));
      output.set(plain, i);
    }
    const pad = output[output.length - 1];
    if (pad < 1 || pad > 16 || !output.slice(-pad).every(value => value === pad)) throw new Error('SDK 响应填充错误');
    return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(output.subarray(0, output.length - pad)));
  }
  function allowed(raw) {
    const url = new URL(raw);
    return !url.username && !url.password && Object.values(endpoints).some(value => {
      const expected = new URL(value);
      return url.origin === expected.origin && url.pathname === expected.pathname;
    });
  }
  function request(url, options = {}, signal) {
    if (!allowed(url)) return Promise.reject(new Error('请求地址不在官方接口列表中'));
    return new Promise((resolve, reject) => {
      let finished = false, handle;
      const finish = (fn, value) => {
        if (finished) return;
        finished = true; clearTimeout(timer);
        if (signal) signal.removeEventListener('abort', cancel);
        fn(value);
      };
      const cancel = () => { finish(reject, new Error('已取消')); if (handle) handle.abort(); };
      const timer = setTimeout(() => { finish(reject, new Error('官方接口请求超时')); if (handle) handle.abort(); }, 35000);
      if (signal && signal.aborted) return cancel();
      if (signal) signal.addEventListener('abort', cancel, {once: true});
      try { handle = GM_xmlhttpRequest({
        method: options.method || 'GET', url, data: options.data, headers: options.headers || {},
        anonymous: true, redirect: 'error', timeout: 30000,
        onload(response) {
          if (response.status < 200 || response.status >= 300) return finish(reject, new Error('官方接口 HTTP ' + Number(response.status)));
          if (response.finalUrl && !allowed(response.finalUrl)) return finish(reject, new Error('官方接口出现意外跳转'));
          finish(resolve, response.responseText);
        },
        onerror: () => finish(reject, new Error('官方接口网络请求失败，请检查油猴的跨域授权')),
        ontimeout: () => finish(reject, new Error('官方接口请求超时')),
        onabort: () => finish(reject, new Error('已取消'))
      }); } catch (_) { finish(reject, new Error('官方接口请求未发出，请检查油猴权限')); }
    });
  }
  const value = (object, name) => object && object[name] != null ? String(object[name]) : '';
  const safeCode = raw => /^-?\d{1,10}$/.test(String(raw)) ? String(raw) : '未提供';
  function requireFields(object, fields, message) {
    if (!object || fields.some(name => !value(object, name))) throw new Error(message);
  }
  function callback(raw, expectedState) {
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol) || url.hostname !== 'game.xiaomi.com'
      || url.port || url.username || url.password || url.pathname !== '/oauthcallback/mioauth') throw new Error('不是本次小米官方回调地址');
    let params = url.searchParams;
    if (!params.get('code')) params = new URLSearchParams(url.hash.slice(1));
    const state = params.get('state'), code = params.get('code');
    if (!/^[a-f0-9]{32}$/.test(state || '') || state !== expectedState) throw new Error('授权校验不匹配，请从官网重新发起小米登录');
    if (!code || code.length > 4096 || /[\r\n\x00]/.test(code)) throw new Error('未取得小米授权码，请重新授权');
    return {state, code};
  }
  async function connect(code, progress, signal, checkIdentity = () => {}) {
    progress('正在转换小米官方授权…');
    const oauth = await decode(await request(endpoints.oauth + '?p=' + encodeURIComponent(await encode(
      'accountType=4&code=' + code + '&isSaveSt=true&appid=2000202')), {}, signal));
    code = null;
    if (value(oauth, 'code') !== '0' || value(oauth, 'uuid') === '0') throw new Error('小米授权转换失败，错误码 ' + safeCode(oauth.code));
    requireFields(oauth, ['uuid', 'st'], '小米授权响应缺少必要字段');
    progress('正在取得一将成名小米游戏会话…');
    const channel = 'meng_1439_345_android';
    // SDK ReqLoginAppAccount appends raw values before AES. Only the OUTER p form field is URL-encoded.
    const plain = 'fuid=' + value(oauth, 'uuid') + '&devAppId=2882303761520011303&toke=' + value(oauth, 'st')
      + '&imei=&sdkVersion=SDK_MI_SP_3.3.0.6&channel=' + channel + '&ua=Windows&currentChannel=' + channel
      + '&imeiMd5=&firstChannel=' + channel + '&oaid=&needRealNameInfo=false&needServiceToken=true&needRiskControl=true';
    const game = await decode(await request(endpoints.session, {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      data: new URLSearchParams({p: await encode(plain)}).toString()}, signal));
    if (value(game, 'retCode') !== '200' || value(game, 'appAccountId') === '0') throw new Error('小米游戏会话失败，错误码 ' + safeCode(game.retCode));
    requireFields(game, ['appAccountId', 'session'], '小米游戏响应缺少必要字段');
    // Check the actual Xiaomi game identity before requesting a Yoka ticket or entering the game.
    await checkIdentity({id: value(game, 'appAccountId'), nickname: value(game, 'nickName')});
    if (signal && signal.aborted) throw new Error('已取消');
    progress('正在连接游卡小米渠道…');
    const payload = {
      appid: '485', package_id: '117', platform_id: '10038', platform_name: 'xiaomi',
      base: {device_id: '', version_code: '347', version_name: '1.0.347', device_mobile: 'Windows', device_network: '', device_os: 'Windows',
        device_os_version: '', device_pixel: screen.width + '*' + screen.height, device_type: 'PC', device_version_code: ''},
      ext: null, data: {thirdparty: 'xiaomi', pid: '10038', gid: '485', uid: value(game, 'appAccountId'), username: value(game, 'nickName'),
        session: value(game, 'session'), thirdAdult: '0', thirdRealNameStatus: '0', thirdAge: '0'}
    };
    const exchange = JSON.parse(await request(endpoints.channel, {method: 'POST', headers: {'Content-Type': 'application/json; charset=utf-8'}, data: JSON.stringify(payload)}, signal));
    if (value(exchange, 'code') !== '0') throw new Error('游卡渠道转换失败，错误码 ' + safeCode(exchange.code));
    requireFields(exchange.data, ['session'], '游卡渠道响应缺少必要字段');
    progress('正在取得小米服启动参数…');
    // Same Xiaomi-specific route and default status as the supplied APK; actual account validation remains on the server.
    const launch = JSON.parse(await request(endpoints.launch + '?ticket=' + encodeURIComponent(value(exchange.data, 'session')) + '&is_adult=1', {}, signal));
    if (value(launch, 'code') !== '0') throw new Error('小米服启动失败，错误码 ' + safeCode(launch.code));
    requireFields(launch.data, ['account', 'token', 'sign', 'timestamp'], '小米服启动响应缺少必要字段');
    return {channel_id: 320052, account: value(launch.data, 'account'), token: value(launch.data, 'token'), sign: value(launch.data, 'sign'), timestamp: value(launch.data, 'timestamp')};
  }
  function installBridge(page, credentials, emit) {
    const original = Object.assign({}, credentials, {channel_id: 320052});
    const args = Object.assign({}, original);
    const current = Object.getOwnPropertyDescriptor(page, 'ReqObj');
    if (current) throw new Error('脚本注入偏晚，请确认油猴允许脚本运行后重新登录');
    Object.defineProperty(page, 'channel_id', {get: () => 320052, set() {}, configurable: false});
    Object.defineProperty(page, 'ReqObj', {get: () => args, set: incoming => Object.assign(args, incoming || {}, original), configurable: false});
    page.__xiaomiBrowserEvent = emit;
    const previous = page.scriptContent;
    page.scriptContent = function (name, source) {
      if (typeof previous === 'function') source = previous(name, source);
      if (typeof source !== 'string' || !name || !name.includes('main')) return source;
      const markers = [
        ['authHandler(e){let t=e.Protocol;', "authHandler(e){let t=e.Protocol;try{window.__xiaomiConnectionState=()=>{try{let s=WBMgr.GetInstance().IsConnected;return typeof s==='boolean'?s:null;}catch(_){return null;}};window.__xiaomiBrowserEvent('auth-result',{code:Number(t.errCode)});}catch(_){}"],
        ['notifyUserData(e){let t=e.Protocol;if(t.finished){', "notifyUserData(e){let t=e.Protocol;if(t.finished){try{window.__xiaomiBrowserEvent('user-data',{roleName:UserData.Self?String(UserData.Self.Nickname||''):'',roleId:AccountInfo.Self?String(AccountInfo.Self.UserId||''):'',serverId:AccountInfo.Self?String(AccountInfo.Self.SeverID||''):''});}catch(_){}"],
        ['enterScene(){if(NSRegressActivity2026Manager', "enterScene(){try{window.__xiaomiBrowserEvent('enter-scene',{});}catch(_){}if(NSRegressActivity2026Manager"]
      ];
      const hooks = markers.map(([find, replacement]) => {
        const matched = source.split(find).length - 1 === 1;
        if (matched) source = source.replace(find, replacement);
        return matched;
      });
      emit('game-code', {hooks});
      return source;
    };
  }
  function createAccountStore(storage, now = () => Date.now(), makeId = () => crypto.randomUUID()) {
    const prefix = 'sgs-xiaomi-accounts-v1:';
    const profileKey = id => prefix + 'profile:' + encodeURIComponent(id);
    const clean = (value, length = 80) => typeof value === 'string' ? value.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, length) : '';
    const validId = value => typeof value === 'string' && /^[A-Za-z0-9._:-]{1,256}$/.test(value);
    function get(id) {
      if (!validId(id)) return null;
      const value = storage.get(profileKey(id), null);
      return value && value.id === id ? value : null;
    }
    function update(id, changes, create = false) {
      if (!validId(id)) throw new Error('账号标识格式不正确');
      const old = get(id);
      if (!old && !create) return null;
      const next = Object.assign({id, windowKey: makeId(), createdAt: now()}, old || {});
      // Persist only the explicit metadata fields, never arbitrary protocol objects.
      for (const field of ['alias', 'nickname', 'roleName', 'roleId', 'serverId', 'zoneNote']) {
        if (Object.prototype.hasOwnProperty.call(changes, field)) next[field] = clean(changes[field]);
      }
      if (Object.prototype.hasOwnProperty.call(changes, 'loginAccount')) next.loginAccount = clean(changes.loginAccount, 256);
      for (const field of ['lastAuthorizedAt', 'lastLoginAt']) if (Number.isFinite(changes[field])) next[field] = changes[field];
      storage.set(profileKey(id), next);
      return next;
    }
    function profiles() {
      return storage.keys().filter(key => key.startsWith(prefix + 'profile:')).map(key => storage.get(key, null))
        .filter(profile => profile && validId(profile.id)).sort((a, b) => (b.lastLoginAt || b.lastAuthorizedAt || 0) - (a.lastLoginAt || a.lastAuthorizedAt || 0));
    }
    function live(id, except = '') {
      return storage.keys().filter(key => key.startsWith(prefix + 'live:') && key !== prefix + 'live:' + except)
        .map(key => ({key, value: storage.get(key, null)})).filter(item => {
          if (!item.value || !Number.isFinite(item.value.expires) || item.value.expires <= now()) { storage.remove(item.key); return false; }
          return item.value.profileId === id;
        }).map(item => item.value);
    }
    return {
      get, update, profiles, validId,
      register: identity => update(identity.id, {nickname: identity.nickname, lastAuthorizedAt: now()}, true),
      remove: id => { if (validId(id)) storage.remove(profileKey(id)); },
      live,
      beat: (instance, profileId, phase, ownerName = '') => {
        if (validId(profileId)) storage.set(prefix + 'live:' + instance, {instance, profileId, phase: clean(phase, 24), ownerName: clean(ownerName, 100), expires: now() + 180000});
      },
      release: instance => storage.remove(prefix + 'live:' + instance),
      label: profile => profile ? profile.alias || profile.roleName || profile.nickname || '小米账号 · ' + profile.id.slice(-4) : '新账号'
    };
  }
  return {encode, decode, allowed, callback, connect, installBridge, endpoints, createAccountStore};
})();
/* CORE-END */

  const PREFIX = 'sgs-xiaomi-v1:';
  const LAUNCH = PREFIX + 'launch';
  const GAME = 'https://web.sanguosha.com/x/pc/index.php';
  const ACCOUNT_CONTEXT = 'sgs-xiaomi-account-context';
  const OWNER_CONTEXT = 'sgs-xiaomi-window-owner';
  const LOGIN_PAGE = 'https://web.sanguosha.com/login/10th_client/index.html';
  const VERSION = '0.2.6';
  const UPDATE_URL = 'https://raw.githubusercontent.com/ybl112/sgs-xiaomi-login/main/' + encodeURIComponent('三国杀小米服登录.user.js');
  const UPDATE_STATE = 'sgs-xiaomi-update-v1';
  const UPDATE_INTERVAL = 6 * 60 * 60 * 1000;
  // UI changes apply only to this document; each new page starts shown at the top right.
  GM_deleteValue('sgs-xiaomi-panel-prefs'); // Discard the legacy persistent preference.
  let panelState = {hidden: false, left: null, top: null};
  const log = [];
  let stateText = '方式一：原授权页；方式二：可选择微信等方式的小米官方标准登录页。';
  let statusNode, logNode, loginButton, alternateLoginButton, cancelButton, importArea, active = null;
  let consumedLaunch = false;
  let panelHost = null;
  let accounts = null, expectedProfileId = null, currentProfileId = null, accountPhase = 'waiting';
  let phaseStartedAt = Date.now(), duplicateRetry = null, retryLoginButton;
  let accountsView, currentAccountNode, accountFingerprint = '', entryError = false;
  let selectedProfileId = null, accountInfo, accountOpen, accountEdit, accountRemove, accountEditor, aliasInput, zoneInput;
  let editingProfileId = null, removingProfileId = null;
  let accountInspect, accountDetails, accountDetailsText, inspectingProfileId = null;
  let checkUpdateButton, updateTask = null, deferredUpdate = null;
  const linkedWindows = new Map();
  const ownedWindows = new Set();
  let ownerName = '';
  function preferences() {
    return panelState;
  }
  function savePreferences(changes) { panelState = Object.assign({}, panelState, changes); }
  function setPanelVisible(visible) {
    if (!panelHost) return;
    panelHost.hidden = !visible;
    // The host reset and page CSS can override the browser's default [hidden] rule.
    panelHost.style.setProperty('display', visible ? 'block' : 'none', 'important');
  }
  function positionPanel(left, top) {
    if (!panelHost) return;
    const rect = panelHost.getBoundingClientRect();
    const width = rect.width || Math.min(302, window.innerWidth - 24);
    const height = rect.height || 100;
    panelHost.style.left = Math.max(8, Math.min(left, window.innerWidth - width - 8)) + 'px';
    panelHost.style.top = Math.max(8, Math.min(top, window.innerHeight - height - 8)) + 'px';
    panelHost.style.right = 'auto';
  }
  function showPanel(reset = false) {
    savePreferences(reset ? {hidden: false, left: null, top: null} : {hidden: false});
    if (!panelHost) return;
    setPanelVisible(true);
    if (reset) { panelHost.style.left = 'auto'; panelHost.style.right = '16px'; panelHost.style.top = '16px'; }
    else {
      const prefs = preferences();
      if (Number.isFinite(prefs.left) && Number.isFinite(prefs.top)) positionPanel(prefs.left, prefs.top);
    }
  }
  const randomId = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), n => n.toString(16).padStart(2, '0')).join('');
  const instanceId = randomId();
  const pendingKey = state => PREFIX + 'pending:' + state;
  const resultKey = state => PREFIX + 'callback:' + state;
  const validTime = expires => typeof expires === 'number' && expires > Date.now() && expires <= Date.now() + 11 * 60 * 1000;
  function status(text) {
    stateText = text;
    log.push({time: new Date().toISOString(), status: text});
    if (log.length > 40) log.shift();
    if (statusNode) statusNode.textContent = text;
    if (logNode) logNode.textContent = log.map(item => item.status).join('\n');
  }
  function cleanup() {
    for (const key of GM_listValues()) {
      if (!key.startsWith(PREFIX)) continue;
      const stored = GM_getValue(key, null);
      if (!stored || !validTime(stored.expires)) GM_deleteValue(key);
    }
  }
  cleanup();
  function ready(fn) {
    if (document.body) return fn();
    const observer = new MutationObserver(() => { if (document.body) { observer.disconnect(); fn(); } });
    observer.observe(document, {childList: true, subtree: true});
  }
  function callbackPage() {
    const raw = location.href;
    let parsed, currentState;
    try {
      const url = new URL(raw);
      currentState = url.searchParams.get('state') || new URLSearchParams(url.hash.slice(1)).get('state');
      parsed = XiaomiCore.callback(raw, currentState);
    } catch (_) {
      status('未取得有效的小米授权回调，请回到三国杀官网重新发起登录。');
      ready(() => panel(true));
      return;
    }
    // Remove the OAuth code before the rest of the callback document loads resources.
    try { history.replaceState(null, '', location.pathname); } catch (_) {}
    const pending = GM_getValue(pendingKey(currentState), null);
    if (!pending || !validTime(pending.expires)) {
      status('这次授权已过期或原登录页已关闭，请回官网重新登录。');
      ready(() => panel(true));
      return;
    }
    const key = resultKey(currentState);
    GM_setValue(key, {state: currentState, code: parsed.code, expires: Date.now() + 30000});
    parsed = null;
    setTimeout(() => GM_deleteValue(key), 30000);
    status('已收到小米授权，请返回刚才的三国杀官网标签页。此页可以关闭。');
    ready(() => panel(true));
  }
  if (location.hostname === 'game.xiaomi.com') {
    if (location.pathname === '/oauthcallback/mioauth') callbackPage();
    return;
  }
  if (location.origin !== 'https://web.sanguosha.com') return;

  function versionParts(value) {
    return typeof value === 'string' && /^\d{1,6}(?:\.\d{1,6}){1,3}$/.test(value) ? value.split('.').map(Number) : null;
  }
  function newerVersion(value) {
    const remote = versionParts(value), local = versionParts(VERSION);
    if (!remote) return false;
    for (let i = 0; i < Math.max(remote.length, local.length); i++) {
      const difference = (remote[i] || 0) - (local[i] || 0);
      if (difference) return difference > 0;
    }
    return false;
  }
  function updateState() {
    const saved = GM_getValue(UPDATE_STATE, null) || {};
    return {version: versionParts(saved.version) ? saved.version : '',
      openedVersion: versionParts(saved.openedVersion) ? saved.openedVersion : '',
      checkedAt: Number.isFinite(saved.checkedAt) ? saved.checkedAt : 0,
      attemptAt: Number.isFinite(saved.attemptAt) ? saved.attemptAt : 0};
  }
  function openUpdate(version, force = false) {
    if (!newerVersion(version)) return false;
    if (active) { deferredUpdate = {version, force}; return false; }
    const saved = updateState();
    if (!force && saved.openedVersion === version) return false;
    // Reserve before opening so other game windows don't open the same update again.
    GM_setValue(UPDATE_STATE, {...saved, openedVersion: version});
    try {
      GM_openInTab(UPDATE_URL + '?version=' + encodeURIComponent(version), {active: true, setParent: true});
      return true;
    } catch (_) {
      const current = updateState();
      if (current.openedVersion === version) GM_setValue(UPDATE_STATE, {...current, openedVersion: saved.openedVersion});
      if (force) status('暂时无法打开更新页，请稍后再试。');
      return false;
    }
  }
  function fetchUpdateVersion() {
    return new Promise((resolve, reject) => {
      let done = false, handle;
      const finish = (error, version) => {
        if (done) return; done = true; clearTimeout(timer);
        error ? reject(new Error('更新检查失败')) : resolve(version);
      };
      const timer = setTimeout(() => { finish(true); if (handle) handle.abort(); }, 15000);
      try {
        handle = GM_xmlhttpRequest({method: 'GET', url: UPDATE_URL + '?check=' + Math.floor(Date.now() / 60000),
          anonymous: true, redirect: 'error', timeout: 12000, nocache: true,
          onload(response) {
            try {
              const final = new URL(response.finalUrl || UPDATE_URL), expected = new URL(UPDATE_URL);
              if (response.status !== 200 || final.origin !== expected.origin || final.pathname !== expected.pathname
                || final.username || final.password || typeof response.responseText !== 'string') return finish(true);
              const text = response.responseText, end = text.indexOf('// ==/UserScript==');
              if (!text.startsWith('// ==UserScript==') || end < 0 || end > 8192) return finish(true);
              const header = text.slice(0, end);
              const match = header.match(/^\/\/[ \t]+@version[ \t]+([^\s]+)[ \t]*\r?$/m);
              if (!/^\/\/[ \t]+@namespace[ \t]+local\.sgs\.xiaomi\.browser[ \t]*\r?$/m.test(header)
                || !match || !versionParts(match[1])) return finish(true);
              finish(false, match[1]);
            } catch (_) { finish(true); }
          }, onerror: () => finish(true), ontimeout: () => finish(true), onabort: () => finish(true)});
      } catch (_) { finish(true); }
    });
  }
  async function checkUpdates(force = false) {
    if (updateTask) { try { await updateTask; } catch (_) {} return; }
    if (force && active) return;
    const saved = updateState(), now = Date.now();
    if (!force) {
      if (saved.version && saved.checkedAt <= now && now - saved.checkedAt < UPDATE_INTERVAL) return openUpdate(saved.version);
      if (saved.attemptAt > 0 && saved.attemptAt <= now && now - saved.attemptAt < 10 * 60 * 1000) return;
    }
    GM_setValue(UPDATE_STATE, {...saved, attemptAt: now});
    if (checkUpdateButton) { checkUpdateButton.disabled = true; checkUpdateButton.textContent = '检查中…'; }
    updateTask = fetchUpdateVersion();
    try {
      const version = await updateTask;
      GM_setValue(UPDATE_STATE, {...updateState(), version, checkedAt: Date.now()});
      if (newerVersion(version)) openUpdate(version, force);
      else if (force) status('当前已是最新版本（' + VERSION + '）。');
    } catch (_) {
      if (force) status('暂时无法检查更新，请检查网络后重试。');
    } finally {
      updateTask = null;
      if (checkUpdateButton) { checkUpdateButton.disabled = !!active; checkUpdateButton.textContent = '检查更新'; }
    }
  }

  accounts = XiaomiCore.createAccountStore({get: GM_getValue, set: GM_setValue, remove: GM_deleteValue, keys: GM_listValues}, () => Date.now(), randomId);
  try {
    const fragment = new URLSearchParams(location.hash.slice(1));
    if (fragment.has('sgs-xiaomi-window')) {
      const nonce = fragment.get('sgs-xiaomi-window');
      const key = PREFIX + 'window:' + nonce;
      const entry = /^[a-f0-9]{32}$/.test(nonce || '') ? GM_getValue(key, null) : null;
      GM_deleteValue(key); sessionStorage.removeItem(LAUNCH); sessionStorage.removeItem(ACCOUNT_CONTEXT); sessionStorage.removeItem(OWNER_CONTEXT);
      history.replaceState(null, '', location.pathname + location.search);
      if (!entry || !validTime(entry.expires) || (entry.profileId && !accounts.get(entry.profileId))) {
        entryError = true; status('账号窗口入口已过期，请从账号列表重新打开。');
      } else {
        ownerName = typeof entry.ownerName === 'string' && /^sgs-xiaomi-(manager|profile)-[a-f0-9]{32}$/.test(entry.ownerName) ? entry.ownerName : '';
        if (ownerName) sessionStorage.setItem(OWNER_CONTEXT, ownerName);
        if (entry.profileId) {
          expectedProfileId = entry.profileId;
          sessionStorage.setItem(ACCOUNT_CONTEXT, expectedProfileId);
          status('已绑定所选账号，请使用“登录方式一”或“登录方式二”，在小米官方页面选择对应账号。');
        } else status('这是新的账号窗口，请使用“登录方式一”或“登录方式二”添加账号。');
      }
    } else {
      const savedId = sessionStorage.getItem(ACCOUNT_CONTEXT);
      if (accounts.get(savedId)) expectedProfileId = savedId;
      else sessionStorage.removeItem(ACCOUNT_CONTEXT);
      const savedOwner = sessionStorage.getItem(OWNER_CONTEXT);
      if (typeof savedOwner === 'string' && /^sgs-xiaomi-(manager|profile)-[a-f0-9]{32}$/.test(savedOwner)) ownerName = savedOwner;
    }
  } catch (_) { entryError = true; status('账号窗口初始化未完成，请从账号列表重新打开。'); }

  function profileName(profile) { return 'sgs-xiaomi-profile-' + profile.windowKey; }
  const activePhases = ['connected', 'loading', 'authorizing'];
  function setAccountPhase(phase) { accountPhase = phase; phaseStartedAt = Date.now(); }
  function heartbeat() {
    const id = currentProfileId || expectedProfileId;
    if (['connected', 'disconnected'].includes(accountPhase)) {
      try {
        const connected = typeof unsafeWindow.__xiaomiConnectionState === 'function' ? unsafeWindow.__xiaomiConnectionState() : null;
        if (connected === false && accountPhase === 'connected') setAccountPhase('disconnected');
        else if (connected === true && accountPhase === 'disconnected') setAccountPhase('connected');
      } catch (_) {}
    }
    if (['loading', 'authorizing'].includes(accountPhase) && Date.now() - phaseStartedAt > 120000) setAccountPhase('failed');
    if (id && accounts.get(id)) accounts.beat(instanceId, id, accountPhase, ownerName);
  }
  function probeAccountWindows(id, signal) {
    const candidates = accounts.live(id, instanceId).filter(item => activePhases.includes(item.phase));
    if (!candidates.length) return Promise.resolve(false);
    return new Promise((resolve, reject) => {
      const nonce = randomId(), key = PREFIX + 'presence-ack:' + nonce;
      const candidatesById = new Set(candidates.map(item => item.instance));
      let done = false;
      const finish = (present, cancelled = false) => {
        if (done) return; done = true;
        clearTimeout(timer); GM_removeValueChangeListener(listener); GM_deleteValue(key);
        for (const item of candidates) GM_deleteValue(PREFIX + 'presence:' + item.instance);
        if (signal) signal.removeEventListener('abort', abort);
        if (cancelled) reject(new Error('已取消')); else resolve(present);
      };
      const abort = () => finish(false, true);
      const listener = GM_addValueChangeListener(key, (_key, _old, response) => {
        if (!response || !validTime(response.expires) || response.profileId !== id || !candidatesById.has(response.instance)) return;
        if (activePhases.includes(response.phase)) finish(true);
      });
      const timer = setTimeout(() => finish(false), 1200);
      if (signal) { signal.addEventListener('abort', abort, {once: true}); if (signal.aborted) return abort(); }
      for (const item of candidates) GM_setValue(PREFIX + 'presence:' + item.instance, {reply: nonce, expires: Date.now() + 10000});
    });
  }
  function updateAccountHeading() {
    if (!accounts) return;
    const profile = accounts.get(currentProfileId || expectedProfileId);
    if (currentAccountNode) currentAccountNode.textContent = profile
      ? (accountPhase === 'connected' ? '当前账号：' : '待登录账号：') + accounts.label(profile) : '当前窗口未绑定账号';
    if (profile) {
      document.title = '[小米服 · ' + accounts.label(profile).slice(0, 24) + '] 三国杀一将成名';
      try { window.name = profileName(profile); } catch (_) {}
    }
  }
  function findOwnedWindow(profile) {
    const cached = linkedWindows.get(profile.id);
    if (cached && !cached.closed) return cached;
    for (const child of ownedWindows) {
      if (child.closed) { ownedWindows.delete(child); continue; }
      try {
        if (child.name === profileName(profile) || child.sessionStorage.getItem(ACCOUNT_CONTEXT) === profile.id) {
          linkedWindows.set(profile.id, child); return child;
        }
      } catch (_) {}
    }
    return null;
  }
  function requestExistingWindow(live) {
    const nonce = randomId(), key = PREFIX + 'focus-ack:' + nonce;
    let complete = false;
    const finish = text => {
      if (complete) return;
      complete = true; clearTimeout(timer); GM_removeValueChangeListener(listener); GM_deleteValue(key); status(text);
    };
    const listener = GM_addValueChangeListener(key, (_key, _old, response) => {
      if (!response || !validTime(response.expires)) return;
      finish(response.focused ? '已返回原账号窗口。' : '原窗口已收到请求，但浏览器没有切换焦点。请从浏览器标签或任务栏切到原窗口；新版创建的账号窗口可直接返回。');
    });
    const timer = setTimeout(() => finish('未能定位原窗口。若它已关闭或掉线，可选择登录方式重新授权。'), 2000);
    for (const record of live) if (record.instance) GM_setValue(PREFIX + 'focus:' + record.instance, {expires: Date.now() + 10000, reply: nonce});
    status('正在请求原账号窗口显示…');
  }
  function focusOwnedWindow(child) {
    try {
      child.focus();
      status('已请求切回原账号窗口；若浏览器未切换，请从标签或任务栏选择该窗口。');
    } catch (_) { status('原窗口暂时无法访问，请从标签或任务栏切回；关闭后可重新打开。'); }
  }
  function openAccountWindow(id = null) {
    const profile = id ? accounts.get(id) : null;
    if (id && !profile) return status('该账号记录已移除，请刷新账号列表。');
    if (id && (currentProfileId || expectedProfileId) === id) {
      showPanel();
      if (!consumedLaunch || ['failed', 'disconnected'].includes(accountPhase)) return begin();
      return status('这里就是该账号当前的游戏窗口。');
    }
    const held = profile ? findOwnedWindow(profile) : null;
    if (held) return focusOwnedWindow(held);
    const live = id ? accounts.live(id, instanceId) : [];
    // An unrelated/old window cannot always be activated by a userscript. Never flash a blank window as a probe.
    if (live.length && !live.some(record => record.ownerName && record.ownerName === window.name)) return requestExistingWindow(live);
    const name = profile ? profileName(profile) : 'sgs-xiaomi-add-' + randomId();
    const child = window.open('', name, 'width=1280,height=850,resizable=yes,scrollbars=yes');
    if (!child) return status('浏览器拦截了账号窗口，请允许官网弹出窗口后重试。');
    try {
      if (child.location.href && child.location.href !== 'about:blank') { if (id) linkedWindows.set(id, child); ownedWindows.add(child); return focusOwnedWindow(child); }
    } catch (_) { return focusOwnedWindow(child); }
    const nonce = randomId();
    if (!/^sgs-xiaomi-(manager|profile)-[a-f0-9]{32}$/.test(window.name || '')) window.name = 'sgs-xiaomi-manager-' + instanceId;
    GM_setValue(PREFIX + 'window:' + nonce, {profileId: id, ownerName: window.name, expires: Date.now() + 600000});
    // The startup entry clears inherited tab storage before binding the selected account.
    // Keep the same-origin opener and handle so this manager can return to the window after login.
    ownedWindows.add(child);
    child.location.replace(LOGIN_PAGE + '#sgs-xiaomi-window=' + nonce);
    if (id) linkedWindows.set(id, child);
    status('账号窗口已打开；请在新窗口完成小米官方授权。');
  }
  function renderAccounts(force = false) {
    if (!accountsView || !accounts) return;
    const profiles = accounts.profiles();
    const data = profiles.map(profile => ({profile, live: accounts.live(profile.id).map(item => item.phase)}));
    if (!profiles.some(profile => profile.id === selectedProfileId)) {
      selectedProfileId = profiles.find(profile => profile.id === (currentProfileId || expectedProfileId))?.id || profiles[0]?.id || null;
      editingProfileId = removingProfileId = inspectingProfileId = null;
    }
    const fingerprint = JSON.stringify({data, selectedProfileId, currentProfileId, expectedProfileId, accountPhase, consumedLaunch, busy: !!active});
    if (!force && fingerprint === accountFingerprint) return;
    accountFingerprint = fingerprint; accountsView.replaceChildren();
    accountsView.disabled = !profiles.length;
    for (const {profile, live} of data) {
      const option = document.createElement('option'); option.value = profile.id;
      option.textContent = accounts.label(profile) + ' · ' + (live.includes('connected') ? '游戏已打开' : live.includes('disconnected') ? '连接已断开' : live.length ? '待登录' : '未打开');
      option.selected = profile.id === selectedProfileId; accountsView.appendChild(option);
    }
    accountsView.value = selectedProfileId || '';
    const profile = accounts.get(selectedProfileId);
    accountEdit.disabled = accountRemove.disabled = !profile;
    accountInspect.disabled = !profile;
    accountDetails.hidden = !profile || inspectingProfileId !== selectedProfileId;
    accountDetailsText.value = profile ? [
      '所选账号：' + accounts.label(profile),
      '小米游戏账号标识（appAccountId）：' + profile.id,
      '游戏接入账号（account）：' + (profile.loginAccount || '尚未读取，请用新版重新授权一次'),
      '小米游戏昵称：' + (profile.nickname || '未返回'),
      '角色名：' + (profile.roleName || '等待游戏返回'),
      '游戏用户 ID：' + (profile.roleId || '等待游戏返回')
    ].join('\n') : '';
    accountEditor.hidden = !profile || editingProfileId !== selectedProfileId;
    accountRemove.textContent = removingProfileId === selectedProfileId && profile ? '确认移除所选记录' : '移除记录';
    accountOpen.disabled = !profile;
    accountOpen.textContent = '打开账号窗口';
    if (profile) {
      const live = accounts.live(profile.id);
      const own = (currentProfileId || expectedProfileId) === profile.id;
      accountOpen.textContent = own ? (active ? '正在登录…' : consumedLaunch && !['failed', 'disconnected'].includes(accountPhase) ? '当前游戏窗口' : '登录此账号') : live.length ? '返回已有窗口' : '打开账号窗口';
      accountOpen.disabled = own && (!!active || (consumedLaunch && !['failed', 'disconnected'].includes(accountPhase)));
      const recent = profile.lastLoginAt ? new Date(profile.lastLoginAt).toLocaleString('zh-CN', {hour12: false}) : '尚未确认游戏登录';
      accountInfo.textContent = '已选：' + accounts.label(profile) + '\n' + (profile.roleName ? '角色：' + profile.roleName + ' · ' : '')
        + (profile.zoneNote || (profile.serverId ? '区服 ' + profile.serverId : '区服未标注')) + ' · 账号尾号 ' + profile.id.slice(-4) + '\n最近登录：' + recent;
    } else accountInfo.textContent = '还没有账号。添加并完成一次授权后，会自动出现在这里。';
    updateAccountHeading();
  }
  const focusListener = GM_addValueChangeListener(PREFIX + 'focus:' + instanceId, (_key, _old, request) => {
    if (!request || !validTime(request.expires)) return;
    GM_deleteValue(PREFIX + 'focus:' + instanceId); showPanel(); window.focus();
    if (/^[a-f0-9]{32}$/.test(request.reply || '')) setTimeout(() => {
      GM_setValue(PREFIX + 'focus-ack:' + request.reply, {expires: Date.now() + 10000, focused: document.hasFocus()});
    }, 100);
  });
  const presenceListener = GM_addValueChangeListener(PREFIX + 'presence:' + instanceId, (_key, _old, request) => {
    if (!request || !validTime(request.expires) || !/^[a-f0-9]{32}$/.test(request.reply || '')) return;
    GM_deleteValue(PREFIX + 'presence:' + instanceId); heartbeat();
    GM_setValue(PREFIX + 'presence-ack:' + request.reply, {instance: instanceId, profileId: currentProfileId || expectedProfileId, phase: accountPhase, expires: Date.now() + 10000});
  });
  const accountRefresh = setInterval(() => { heartbeat(); renderAccounts(); }, 15000);
  window.addEventListener('focus', () => renderAccounts());
  heartbeat();

  // Read and delete the one-navigation handoff synchronously, before official game initialization.
  if (location.pathname === '/x/pc/index.php') {
    let saved;
    try {
      const raw = sessionStorage.getItem(LAUNCH);
      sessionStorage.removeItem(LAUNCH);
      if (raw) saved = JSON.parse(raw);
      if (saved && validTime(saved.expires)) {
        if (saved.profileId && (!accounts.get(saved.profileId) || (expectedProfileId && saved.profileId !== expectedProfileId))) throw new Error('账号窗口绑定不匹配');
        currentProfileId = saved.profileId || null;
        selectedProfileId = currentProfileId;
        if (currentProfileId) { expectedProfileId = currentProfileId; sessionStorage.setItem(ACCOUNT_CONTEXT, currentProfileId); }
        setAccountPhase('loading'); heartbeat();
        if (document.readyState !== 'loading') throw new Error('脚本启动偏晚，请重新登录并检查油猴注入设置');
        XiaomiCore.installBridge(unsafeWindow, saved.args, (kind, extra = {}) => {
          if (kind === 'auth-result') {
            if (extra.code === 0) { setAccountPhase('connected'); if (currentProfileId) accounts.update(currentProfileId, {lastLoginAt: Date.now()}); heartbeat(); }
            else { setAccountPhase('failed'); heartbeat(); }
            status(extra.code === 0 ? '游戏服务器认证成功，正在加载角色…' : Number.isFinite(extra.code) ? '游戏服务器返回错误码 ' + extra.code : '游戏认证响应已到达，请以实际画面为准。');
            renderAccounts();
          }
          if (kind === 'user-data') {
            if (currentProfileId) accounts.update(currentProfileId, {roleName: extra.roleName, roleId: extra.roleId, serverId: extra.serverId});
            updateAccountHeading(); renderAccounts(); status('已收到小米服角色数据，正在进入大厅…');
          }
          if (kind === 'enter-scene') status('已收到进入游戏场景通知，请核对原小米服角色／大厅。');
          if (kind === 'game-code' && extra.hooks.some(item => !item)) status('游戏已更新，部分状态提示无法读取；请以实际画面为准。');
        });
        consumedLaunch = true;
        status('小米服启动参数已接入，正在加载官网电脑端游戏…');
      }
    } catch (error) { setAccountPhase('failed'); heartbeat(); status(error.message === '脚本启动偏晚，请重新登录并检查油猴注入设置' ? error.message : '小米服接入初始化失败，请重新授权；若重复出现，请导出诊断。'); }
    saved = null;
  } else {
    // Expired credentials are never reused by a later visit.
    sessionStorage.removeItem(LAUNCH);
  }
  function busy(value) {
    if (loginButton) loginButton.disabled = value;
    if (alternateLoginButton) alternateLoginButton.disabled = value;
    if (checkUpdateButton) checkUpdateButton.disabled = value || !!updateTask;
    if (retryLoginButton) retryLoginButton.hidden = value || !duplicateRetry;
    if (cancelButton) cancelButton.hidden = !value;
    if (importArea) importArea.hidden = !value;
    renderAccounts(true);
  }
  function waitForCode(context) {
    return new Promise((resolve, reject) => {
      let done = false;
      const key = resultKey(context.state);
      const finish = (fn, result) => {
        if (done) return;
        done = true; clearInterval(interval); clearTimeout(timer);
        GM_removeValueChangeListener(listener);
        context.controller.signal.removeEventListener('abort', cancel);
        context.accept = null;
        GM_deleteValue(key); GM_deleteValue(pendingKey(context.state));
        fn(result);
      };
      const cancel = () => finish(reject, new Error('已取消'));
      const accept = data => {
        if (!data || data.state !== context.state || !validTime(data.expires) || typeof data.code !== 'string' || !data.code || data.code.length > 4096) return;
        finish(resolve, data.code);
      };
      const listener = GM_addValueChangeListener(key, (_key, _old, data) => accept(data));
      const interval = setInterval(() => accept(GM_getValue(key, null)), 750);
      const timer = setTimeout(() => finish(reject, new Error('小米授权等待超时，请重新发起登录')), 10 * 60 * 1000);
      context.accept = accept;
      context.controller.signal.addEventListener('abort', cancel, {once: true});
    });
  }
  async function begin(retryProfileId = null, loginMethod = 1) {
    if (active) return;
    if (entryError) return status('账号窗口入口已过期，请从账号列表重新打开。');
    duplicateRetry = null;
    const context = {state: randomId(), controller: new AbortController(), popup: null, accept: null};
    active = context; busy(true);
    GM_setValue(pendingKey(context.state), {expires: Date.now() + 10 * 60 * 1000});
    const authorization = new URL('https://account.xiaomi.com/oauth2/authorize');
    authorization.search = new URLSearchParams({client_id: '2882303761517516898', response_type: 'code', scope: '1 3',
      redirect_uri: 'http://game.xiaomi.com/oauthcallback/mioauth', state: context.state}).toString();
    // The OAuth-specific form hides social sign-in. Use Xiaomi's standard login
    // form, then let its official callback continue this exact OAuth request.
    const loginEntry = new URL('https://account.xiaomi.com/pass/serviceLogin');
    loginEntry.search = new URLSearchParams({sid: 'passport', callback: authorization.href}).toString();
    try {
      const waiting = waitForCode(context);
      waiting.catch(() => {}); // Also handle cancellation before the popup has opened.
      // Open immediately within the click event; detach opener while retaining a close handle.
      context.popup = window.open('about:blank', 'xiaomi-sgs-' + context.state, 'width=560,height=780');
      if (!context.popup) {
        context.controller.abort();
        try { await waiting; } catch (_) {}
        throw new Error('浏览器拦截了登录窗口，请允许此官网弹出窗口后重试');
      }
      context.popup.opener = null;
      context.popup.location.replace(loginMethod === 2 ? loginEntry.href : authorization.href);
      status(loginMethod === 2
        ? '请在小米官方标准登录页选择微信等方式登录；完成后会自动继续游戏授权。若需换号，请先使用“切换小米账号”。'
        : '请在新窗口完成小米官方授权；完成后会自动回到游戏接入流程。');
      let code = await waiting;
      if (context.popup) { try { context.popup.close(); } catch (_) {} }
      const args = await XiaomiCore.connect(code, status, context.controller.signal, async identity => {
        const targetProfileId = expectedProfileId || (typeof retryProfileId === 'string' ? retryProfileId : null);
        if (targetProfileId && identity.id !== targetProfileId) throw new Error('授权账号与所选账号不一致，已停止接入。请先点“切换小米账号”换号，再授权。');
        if (retryProfileId !== identity.id && await probeAccountWindows(identity.id, context.controller.signal)) {
          duplicateRetry = {id: identity.id, loginMethod};
          throw new Error('该账号的其他游戏窗口仍有响应。可返回原窗口；若它未登录或已掉线，请点“仍在此窗口登录”重新授权。');
        }
        if (context.controller.signal.aborted) throw new Error('已取消');
        const profile = accounts.register(identity);
        currentProfileId = expectedProfileId = profile.id; setAccountPhase('authorizing');
        selectedProfileId = profile.id;
        sessionStorage.setItem(ACCOUNT_CONTEXT, profile.id); heartbeat(); updateAccountHeading(); renderAccounts();
      });
      code = null;
      if (context.controller.signal.aborted) throw new Error('已取消');
      // Save only the account identifier from the validated launch response, never its token/sign/ticket.
      accounts.update(currentProfileId, {loginAccount: args.account});
      // A tab-scoped, one-use handoff; no credentials in query strings or persistent GM storage.
      sessionStorage.setItem(LAUNCH, JSON.stringify({expires: Date.now() + 60000, args, profileId: currentProfileId}));
      status('小米服登录准备完成，正在打开官网游戏…');
      location.assign(GAME);
    } catch (error) {
      const message = error instanceof Error ? error.message : '';
      const trusted = /^(小米|游卡|官方接口|浏览器拦截|请求地址|不是本次|授权校验|授权账号|该账号|账号标识|未取得|SDK 响应|已取消)/.test(message);
      if (accountPhase === 'authorizing') { setAccountPhase('failed'); heartbeat(); }
      status(trusted ? message : '登录接入未完成，请导出诊断后反馈最后状态。');
    } finally {
      context.controller.abort();
      GM_deleteValue(pendingKey(context.state)); GM_deleteValue(resultKey(context.state));
      active = null; busy(false);
      if (deferredUpdate) { const pendingUpdate = deferredUpdate; deferredUpdate = null; openUpdate(pendingUpdate.version, pendingUpdate.force); }
    }
  }
  function manual(raw) {
    if (!active || !active.accept) return status('请先点击“登录方式一”或“登录方式二”。');
    try {
      const data = XiaomiCore.callback(raw, active.state);
      active.accept({...data, expires: Date.now() + 30000});
    } catch (error) { status(/^(不是本次|授权校验|未取得)/.test(error.message) ? error.message : '回调地址格式不正确，请复制小米授权后地址栏的完整地址。'); }
  }
  window.addEventListener('pagehide', () => {
    clearInterval(accountRefresh); accounts.release(instanceId); GM_removeValueChangeListener(focusListener); GM_removeValueChangeListener(presenceListener);
    GM_deleteValue(PREFIX + 'focus:' + instanceId);
    GM_deleteValue(PREFIX + 'presence:' + instanceId);
    if (active) {
      active.controller.abort();
      GM_deleteValue(pendingKey(active.state)); GM_deleteValue(resultKey(active.state));
    }
  });
  function panel(callbackOnly = false) {
    const host = document.createElement('div');
    host.id = 'xiaomi-sgs-login-panel';
    host.style.cssText = 'position:fixed;right:16px;top:16px;width:302px;max-width:calc(100vw - 24px);z-index:2147483647;';
    if (!callbackOnly) panelHost = host;
    const root = host.attachShadow({mode: 'closed'});
    const style = document.createElement('style');
    style.textContent = ':host{all:initial}:host([hidden]){display:none!important}*{box-sizing:border-box}.box{font:14px/1.6 "Microsoft YaHei",sans-serif;color:#efe9dd;background:#242121;border:1px solid #bfa779;border-radius:10px;box-shadow:0 8px 30px #0006;padding:14px}header{display:flex;align-items:center;justify-content:space-between;font-weight:bold;color:#e6c98e}p{margin:10px 0;overflow-wrap:anywhere}button{font:inherit;cursor:pointer;border:0;border-radius:5px;padding:7px 12px;background:#e1c48b;color:#28211a;margin:4px 5px 4px 0}button:disabled{opacity:.5;cursor:wait}.minor{background:#48403b;color:#eee;font-size:12px}input{width:100%;font:inherit;background:#fff;color:#222;padding:6px;border:1px solid #aaa;border-radius:4px}small,summary{font-size:12px;color:#bfb9af}pre{font:12px/1.7 sans-serif;white-space:pre-wrap;max-height:180px;overflow:auto}[hidden]{display:none!important}';
    root.appendChild(style);
    const accountStyle = document.createElement('style');
    accountStyle.textContent = '.box{max-height:calc(100vh - 32px);overflow:auto}.accounts{display:block;width:100%;height:94px;overflow:auto;margin:8px 0;background:#302b27;color:#efe9dd;border:1px solid #76644e;border-radius:5px;font:13px/1.6 "Microsoft YaHei",sans-serif}.accounts option{padding:6px}.account-info{display:block;white-space:pre-line;overflow-wrap:anywhere;font-size:11px;margin:6px 0}.account-editor input{margin-top:6px;font-size:12px}';
    root.appendChild(accountStyle);
    const box = document.createElement('section'); box.className = 'box'; root.appendChild(box);
    const header = document.createElement('header'); header.textContent = '一将成名 · 小米服'; box.appendChild(header);
    const content = document.createElement('div');
    const collapse = document.createElement('button'); collapse.className = 'minor'; collapse.textContent = '收起';
    collapse.onclick = () => { content.hidden = !content.hidden; collapse.textContent = content.hidden ? '展开' : '收起'; };
    header.appendChild(collapse); box.appendChild(content);
    if (!callbackOnly) {
      const hide = document.createElement('button'); hide.className = 'minor'; hide.textContent = '隐藏';
      hide.title = '可从油猴菜单的“小米服：显示登录面板”重新打开';
      hide.onclick = () => { setPanelVisible(false); savePreferences({hidden: true}); };
      header.appendChild(hide);
      header.style.cursor = 'move'; header.style.touchAction = 'none'; header.style.userSelect = 'none';
      header.title = '按住标题拖动；隐藏后可从油猴菜单重新显示';
      let drag = null;
      header.addEventListener('pointerdown', event => {
        if (event.button !== 0 || event.target.closest('button')) return;
        const rect = host.getBoundingClientRect();
        drag = {id: event.pointerId, x: event.clientX, y: event.clientY, left: rect.left, top: rect.top};
        header.setPointerCapture(event.pointerId); event.preventDefault();
      });
      header.addEventListener('pointermove', event => {
        if (!drag || event.pointerId !== drag.id) return;
        positionPanel(drag.left + event.clientX - drag.x, drag.top + event.clientY - drag.y);
      });
      const endDrag = event => {
        if (!drag || event.pointerId !== drag.id) return;
        try { header.releasePointerCapture(event.pointerId); } catch (_) {}
        drag = null;
        savePreferences({left: parseFloat(host.style.left), top: parseFloat(host.style.top)});
      };
      header.addEventListener('pointerup', endDrag); header.addEventListener('pointercancel', endDrag);
      window.addEventListener('resize', () => {
        const prefs = preferences();
        if (!host.hidden && Number.isFinite(prefs.left) && Number.isFinite(prefs.top)) positionPanel(prefs.left, prefs.top);
      });
    }
    statusNode = document.createElement('p'); statusNode.textContent = stateText; statusNode.setAttribute('role', 'status'); content.appendChild(statusNode);
    if (!callbackOnly) {
      loginButton = document.createElement('button'); loginButton.textContent = '登录方式一';
      loginButton.title = '打开原小米官方游戏授权页'; loginButton.onclick = () => begin(); content.appendChild(loginButton);
      alternateLoginButton = document.createElement('button'); alternateLoginButton.textContent = '登录方式二';
      alternateLoginButton.title = '先打开小米官方标准登录页，可选择微信等登录方式';
      alternateLoginButton.onclick = () => begin(null, 2); content.appendChild(alternateLoginButton);
      retryLoginButton = document.createElement('button'); retryLoginButton.className = 'minor'; retryLoginButton.textContent = '仍在此窗口登录'; retryLoginButton.hidden = !duplicateRetry;
      retryLoginButton.title = '重新授权同一账号，服务器可能使原窗口下线';
      retryLoginButton.onclick = () => {
        if (!duplicateRetry) { retryLoginButton.hidden = true; return status('请先点击“登录方式一”或“登录方式二”。'); }
        return begin(duplicateRetry.id, duplicateRetry.loginMethod);
      }; content.appendChild(retryLoginButton);
      currentAccountNode = document.createElement('small'); currentAccountNode.className = 'account-info'; content.appendChild(currentAccountNode);
      const manager = document.createElement('details'); manager.open = true;
      const managerTitle = document.createElement('summary'); managerTitle.textContent = '账号管理'; manager.appendChild(managerTitle);
      const add = document.createElement('button'); add.className = 'minor'; add.textContent = '添加账号（新窗口）'; add.onclick = () => openAccountWindow(); manager.appendChild(add);
      const refresh = document.createElement('button'); refresh.className = 'minor'; refresh.textContent = '刷新列表'; refresh.onclick = () => renderAccounts(true); manager.appendChild(refresh);
      const switchXiaomi = document.createElement('button'); switchXiaomi.className = 'minor'; switchXiaomi.textContent = '切换小米账号';
      switchXiaomi.title = '打开小米官方账号页，换号后再回本窗口授权';
      switchXiaomi.onclick = () => {
        const popup = window.open('https://account.xiaomi.com/', 'xiaomi-sgs-account-switch', 'width=560,height=780');
        if (!popup) return status('浏览器拦截了小米账号窗口，请允许弹出窗口后重试。');
        popup.opener = null; status('请在小米官方账号页自行换号，完成后回到所选窗口重新授权。');
      }; manager.appendChild(switchXiaomi);
      accountsView = document.createElement('select'); accountsView.className = 'accounts'; accountsView.size = 3;
      accountsView.setAttribute('aria-label', '选择要管理的账号');
      accountsView.onchange = () => {
        selectedProfileId = accountsView.value; editingProfileId = removingProfileId = inspectingProfileId = null; renderAccounts(true);
      }; manager.appendChild(accountsView);
      accountInfo = document.createElement('small'); accountInfo.className = 'account-info'; manager.appendChild(accountInfo);
      accountOpen = document.createElement('button'); accountOpen.className = 'minor';
      accountOpen.onclick = () => openAccountWindow(selectedProfileId); manager.appendChild(accountOpen);
      accountEdit = document.createElement('button'); accountEdit.className = 'minor'; accountEdit.textContent = '修改备注';
      accountEdit.onclick = () => {
        const profile = accounts.get(selectedProfileId); if (!profile) return renderAccounts(true);
        editingProfileId = profile.id; removingProfileId = null;
        aliasInput.value = profile.alias || ''; zoneInput.value = profile.zoneNote || ''; renderAccounts(true);
      }; manager.appendChild(accountEdit);
      accountRemove = document.createElement('button'); accountRemove.className = 'minor'; accountRemove.textContent = '移除记录';
      accountRemove.onclick = () => {
        const profile = accounts.get(selectedProfileId); if (!profile) return renderAccounts(true);
        if (removingProfileId !== profile.id) { removingProfileId = profile.id; editingProfileId = null; renderAccounts(true); return; }
        accounts.remove(profile.id); editingProfileId = removingProfileId = null;
        renderAccounts(true); status('所选账号的本地记录已移除，已打开的游戏不会退出。');
      }; manager.appendChild(accountRemove);
      accountInspect = document.createElement('button'); accountInspect.className = 'minor'; accountInspect.textContent = '查看账号信息';
      accountInspect.onclick = () => {
        inspectingProfileId = inspectingProfileId === selectedProfileId ? null : selectedProfileId; renderAccounts(true);
      }; manager.appendChild(accountInspect);
      accountDetails = document.createElement('div'); accountDetails.hidden = true;
      accountDetailsText = document.createElement('textarea'); accountDetailsText.readOnly = true;
      accountDetailsText.setAttribute('aria-label', '账号信息（不含登录凭据）');
      accountDetailsText.style.cssText = 'width:100%;height:155px;resize:vertical;font:12px/1.7 sans-serif;padding:6px;background:#fff;color:#222;';
      accountDetails.appendChild(accountDetailsText);
      const identityHint = document.createElement('small'); identityHint.className = 'account-info';
      identityHint.textContent = '这些是官方登录流程返回的账号标识；不等于绑定手机号，也不代表可使用官网密码登录。'; accountDetails.appendChild(identityHint);
      const copyIdentity = document.createElement('button'); copyIdentity.className = 'minor'; copyIdentity.textContent = '复制账号信息';
      copyIdentity.onclick = async () => {
        if (!accounts.get(selectedProfileId) || accountDetails.hidden) return;
        try { await navigator.clipboard.writeText(accountDetailsText.value); status('账号信息已复制，不含登录凭据。'); }
        catch (_) { accountDetailsText.focus(); accountDetailsText.select(); status('已选中账号信息，请按 Ctrl+C 复制。'); }
      }; accountDetails.appendChild(copyIdentity); manager.appendChild(accountDetails);
      accountEditor = document.createElement('div'); accountEditor.className = 'account-editor'; accountEditor.hidden = true;
      aliasInput = document.createElement('input'); aliasInput.placeholder = '账号备注，如大号／小号'; aliasInput.maxLength = 80;
      aliasInput.setAttribute('aria-label', '账号备注'); accountEditor.appendChild(aliasInput);
      zoneInput = document.createElement('input'); zoneInput.placeholder = '区服备注（可选）'; zoneInput.maxLength = 80;
      zoneInput.setAttribute('aria-label', '区服备注'); accountEditor.appendChild(zoneInput);
      const save = document.createElement('button'); save.className = 'minor'; save.textContent = '保存备注';
      save.onclick = () => {
        if (!editingProfileId || editingProfileId !== selectedProfileId || !accounts.get(editingProfileId)) return renderAccounts(true);
        accounts.update(editingProfileId, {alias: aliasInput.value, zoneNote: zoneInput.value}); editingProfileId = null;
        renderAccounts(true); status('所选账号的备注已保存。');
      }; accountEditor.appendChild(save);
      const cancelEdit = document.createElement('button'); cancelEdit.className = 'minor'; cancelEdit.textContent = '取消修改';
      cancelEdit.onclick = () => { editingProfileId = null; renderAccounts(true); }; accountEditor.appendChild(cancelEdit);
      manager.appendChild(accountEditor); content.appendChild(manager);
      cancelButton = document.createElement('button'); cancelButton.textContent = '取消'; cancelButton.className = 'minor'; cancelButton.hidden = true;
      cancelButton.onclick = () => { if (active) { active.controller.abort(); try { active.popup.close(); } catch (_) {} } }; content.appendChild(cancelButton);
      importArea = document.createElement('details'); importArea.hidden = true;
      const summary = document.createElement('summary'); summary.textContent = '授权后卡在 404／空白页？'; importArea.appendChild(summary);
      const hint = document.createElement('small'); hint.textContent = '复制授权后地址栏的完整地址，粘贴到这里继续。'; importArea.appendChild(hint);
      const input = document.createElement('input'); input.type = 'password'; input.autocomplete = 'off'; input.placeholder = '粘贴小米授权回调地址'; importArea.appendChild(input);
      const submit = document.createElement('button'); submit.className = 'minor'; submit.textContent = '继续登录';
      submit.onclick = () => { const raw = input.value.trim(); input.value = ''; manual(raw); }; importArea.appendChild(submit); content.appendChild(importArea);
      const diagnostics = document.createElement('details'); const label = document.createElement('summary'); label.textContent = '查看状态记录'; diagnostics.appendChild(label);
      logNode = document.createElement('pre'); logNode.textContent = log.map(item => item.status).join('\n'); diagnostics.appendChild(logNode);
      const download = document.createElement('button'); download.className = 'minor'; download.textContent = '导出诊断';
      download.onclick = () => {
        const url = URL.createObjectURL(new Blob([JSON.stringify({version: VERSION, scope: '阶段提示；不包含账号与会话值', events: log}, null, 2)], {type: 'application/json'}));
        const link = document.createElement('a'); link.href = url; link.download = '小米服浏览器诊断.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      }; diagnostics.appendChild(download); content.appendChild(diagnostics);
      checkUpdateButton = document.createElement('button'); checkUpdateButton.className = 'minor'; checkUpdateButton.textContent = '检查更新';
      checkUpdateButton.onclick = () => checkUpdates(true); content.appendChild(checkUpdateButton);
      const note = document.createElement('small'); note.textContent = VERSION + ' · 账号记录会保留，小框状态每次重置'; content.appendChild(note);
    }
    document.body.appendChild(host);
    if (!callbackOnly) {
      const prefs = preferences();
      setPanelVisible(prefs.hidden !== true);
      if (!host.hidden && Number.isFinite(prefs.left) && Number.isFinite(prefs.top)) positionPanel(prefs.left, prefs.top);
      renderAccounts(true); updateAccountHeading();
    }
  }
  GM_registerMenuCommand('小米服：显示登录面板', () => showPanel());
  GM_registerMenuCommand('小米服：重置面板位置', () => showPanel(true));
  GM_registerMenuCommand('小米服：打开官网登录页', () => location.assign('https://web.sanguosha.com/login/10th_client/index.html'));
  GM_registerMenuCommand('小米服：清除临时授权记录', () => {
    if (active) active.controller.abort();
    for (const key of GM_listValues()) if (key.startsWith(PREFIX)) GM_deleteValue(key);
    sessionStorage.removeItem(LAUNCH); status('临时授权记录已清除；游戏内退出请使用游戏自带功能。');
  });
  ready(() => { panel(); checkUpdates(); });
  setInterval(() => checkUpdates(), UPDATE_INTERVAL);
})();
