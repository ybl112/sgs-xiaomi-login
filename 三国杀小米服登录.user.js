// ==UserScript==
// @name         三国杀一将成名 · 小米服登录
// @namespace    local.sgs.xiaomi.browser
// @version      0.3.2
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
// @connect      account.xiaomi.com
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
  async function xiaomiSession(code, progress, signal) {
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
    return game;
  }
  async function authorize(code, progress, signal) {
    const game = await xiaomiSession(code, progress, signal);
    if (signal && signal.aborted) throw new Error('已取消');
    return {id: value(game, 'appAccountId'), nickname: value(game, 'nickName'), session: value(game, 'session')};
  }
  async function connect(code, progress, signal, checkIdentity = () => {}) {
    const game = await xiaomiSession(code, progress, signal);
    // Check the actual Xiaomi game identity before requesting a Yoka ticket or entering the game.
    await checkIdentity({id: value(game, 'appAccountId'), nickname: value(game, 'nickName'), session: value(game, 'session')});
    return launchSession(game, progress, signal);
  }
  async function connectSaved(identity, progress, signal) {
    requireFields(identity, ['id', 'session'], '小米登录凭据缺少必要字段，请重新授权');
    return launchSession({appAccountId: identity.id, nickName: identity.nickname || '', session: identity.session}, progress, signal);
  }
  async function launchSession(game, progress, signal) {
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
  return {encode, decode, allowed, callback, connect, authorize, connectSaved, installBridge, endpoints, createAccountStore};
})();
/* CORE-END */

  const PREFIX = 'sgs-xiaomi-v1:';
  const LAUNCH = PREFIX + 'launch';
  const GAME = 'https://web.sanguosha.com/x/pc/index.php';
  const ACCOUNT_CONTEXT = 'sgs-xiaomi-account-context';
  const OWNER_CONTEXT = 'sgs-xiaomi-window-owner';
  const LOGIN_PAGE = 'https://web.sanguosha.com/login/10th_client/index.html';
  const VERSION = '0.3.2';
  const UPDATE_URL = 'https://raw.githubusercontent.com/ybl112/sgs-xiaomi-login/main/' + encodeURIComponent('三国杀小米服登录.user.js');
  const UPDATE_STATE = 'sgs-xiaomi-update-v1';
  const UPDATE_INTERVAL = 6 * 60 * 60 * 1000;
  // UI changes apply only to this document; each new page starts shown at the top right.
  GM_deleteValue('sgs-xiaomi-panel-prefs'); // Discard the legacy persistent preference.
  let panelState = {hidden: false, left: null, top: null};
  const log = [];
  let stateText = '选择一种登录方式，在小米官方页面完成授权。';
  let statusNode, logNode, loginButton, alternateLoginButton, switchXiaomiButton, cancelButton, importArea, active = null;
  let loginGridNode, loginHintNode, loginSectionNode;
  let selectedAccountSection, accountEmptyNode, accountRecentNode;
  let addAccountButton, addLoginMethod;
  const SESSION_PREFIX = 'sgs-xiaomi-sessions-v1:';
  let accountClear, accountReauthorize, accountMoreNode;
  let autoLoginProfileId = null;
  let consumedLaunch = false;
  let panelHost = null;
  let accounts = null, expectedProfileId = null, currentProfileId = null, accountPhase = 'waiting';
  let phaseStartedAt = Date.now(), duplicateRetry = null, retryLoginButton;
  let accountsView, currentAccountNode, accountCountNode, accountActionsNode, accountFingerprint = '', entryError = false;
  let selectedProfileId = null, accountInfo, accountOpen, accountEdit, accountRemove, accountEditor, aliasInput, zoneInput;
  let editingProfileId = null, removingProfileId = null;
  let accountInspect, accountDetails, accountDetailsText, inspectingProfileId = null;
  let checkUpdateButton, updateTask = null, deferredUpdate = null;
  let statusCard, statusCaption, historyDetails, historyCount, historyFilterButton, historyClearButton, errorsOnly = false;
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
    const width = rect.width || Math.min(336, window.innerWidth - 24);
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
  function statusLevel(text) {
    if (/失败|错误码|未完成|超时|异常|不一致|未能|拦截|无效|过期|未取得|不是本次|不正确|格式错误|缺少|启动偏晚|无法/.test(text)) return 'error';
    if (/取消|仍有响应|断开|掉线|游戏已更新|已清除/.test(text)) return 'warning';
    if (/正在|等待|请在.*(授权|登录)|请.*完成授权/.test(text)) return 'progress';
    if (/已收到|成功|准备完成|已是最新|已保存|已复制|已移除|已绑定|已打开/.test(text)) return 'success';
    return 'info';
  }
  function renderStatus() {
    if (statusNode) statusNode.textContent = stateText;
    const level = statusLevel(stateText);
    if (statusCard) statusCard.className = 'status-card ' + level;
    if (statusCaption) statusCaption.textContent = {info: '准备就绪', progress: '正在处理', success: '操作完成', error: '遇到问题', warning: '操作提示'}[level];
  }
  function renderHistory() {
    if (!logNode) return;
    const unusual = log.filter(item => ['error', 'warning'].includes(item.level));
    if (historyCount) historyCount.textContent = log.length + ' 条' + (unusual.length ? ' · ' + unusual.length + ' 异常' : '');
    if (historyFilterButton) {
      historyFilterButton.textContent = errorsOnly ? '显示全部' : '仅看异常';
      historyFilterButton.setAttribute('aria-pressed', String(errorsOnly));
    }
    if (historyClearButton) historyClearButton.disabled = !log.length;
    logNode.replaceChildren();
    const visible = log.map((item, index) => ({...item, current: index === log.length - 1}))
      .filter(item => !errorsOnly || ['error', 'warning'].includes(item.level)).reverse();
    if (!visible.length) {
      const empty = document.createElement('li'); empty.className = 'record-empty';
      empty.textContent = errorsOnly ? '暂无异常记录' : '暂无记录，登录和操作过程会显示在这里。'; logNode.appendChild(empty);
      return;
    }
    for (const item of visible) {
      const row = document.createElement('li'); row.className = 'record-item ' + item.level + (item.current ? ' is-current' : '');
      const meta = document.createElement('div'); meta.className = 'record-meta';
      const time = document.createElement('time'); time.dateTime = item.time;
      time.textContent = new Date(item.time).toLocaleTimeString('zh-CN', {hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'});
      const badge = document.createElement('span'); badge.className = 'record-badge';
      badge.textContent = item.level === 'error' ? '异常' : item.level === 'warning' ? '注意' : item.level === 'success' ? '完成' : item.current ? '当前' : '过程';
      meta.appendChild(time); meta.appendChild(badge); row.appendChild(meta);
      const message = document.createElement('div'); message.className = 'record-message'; message.textContent = item.status;
      row.appendChild(message); logNode.appendChild(row);
    }
  }
  function status(text) {
    stateText = text;
    const level = statusLevel(text);
    log.push({time: new Date().toISOString(), status: text, level});
    if (log.length > 40) log.shift();
    renderStatus(); renderHistory();
    if (historyDetails && level === 'error') historyDetails.open = true;
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
  sessionStorage.removeItem('sgs-xiaomi-fresh-login'); // Retire 0.2.9's automatic logout flag.
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
          if (entry.useSavedSession) autoLoginProfileId = entry.profileId;
          status('已绑定所选账号，请使用“登录方式一”或“登录方式二”，在小米官方页面选择对应账号。');
        } else status('这是未绑定的游戏窗口。可直接登录，或在账号管理中添加账号。');
      }
    } else {
      const savedId = sessionStorage.getItem(ACCOUNT_CONTEXT);
      if (accounts.get(savedId)) expectedProfileId = savedId;
      else sessionStorage.removeItem(ACCOUNT_CONTEXT);
      const savedOwner = sessionStorage.getItem(OWNER_CONTEXT);
      if (typeof savedOwner === 'string' && /^sgs-xiaomi-(manager|profile)-[a-f0-9]{32}$/.test(savedOwner)) ownerName = savedOwner;
    }
  } catch (_) { entryError = true; status('账号窗口初始化未完成，请从账号列表重新打开。'); }

  function savedSession(id) {
    if (!accounts.validId(id)) return null;
    const value = GM_getValue(SESSION_PREFIX + encodeURIComponent(id), null);
    return value && value.id === id && typeof value.session === 'string' && value.session.length > 0 && value.session.length <= 8192
      && !/[\r\n\x00]/.test(value.session) ? value : null;
  }
  function saveSession(identity) {
    if (!accounts.validId(identity.id) || typeof identity.session !== 'string' || !identity.session || identity.session.length > 8192
      || /[\r\n\x00]/.test(identity.session)) throw new Error('小米登录凭据格式不正确，请重新授权');
    GM_setValue(SESSION_PREFIX + encodeURIComponent(identity.id), {id: identity.id, nickname: String(identity.nickname || '').slice(0, 80), session: identity.session, savedAt: Date.now()});
  }
  function clearSession(id) { if (accounts.validId(id)) GM_deleteValue(SESSION_PREFIX + encodeURIComponent(id)); }

  function profileName(profile) { return 'sgs-xiaomi-profile-' + profile.windowKey; }
  const activePhases = ['connected', 'loading', 'authorizing'];
  function renderLoginVisibility() {
    const loggedIn = consumedLaunch && accountPhase === 'connected';
    for (const node of [loginButton, alternateLoginButton, loginGridNode, loginHintNode, loginSectionNode]) if (node) node.hidden = loggedIn;
  }
  function setAccountPhase(phase) { accountPhase = phase; phaseStartedAt = Date.now(); renderLoginVisibility(); }
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
  function loginSelectedAccount(id) {
    if (active) return;
    if (!accounts.get(id)) return status('该账号记录已移除，请刷新账号列表。');
    if (currentProfileId === id && consumedLaunch && !['failed', 'disconnected'].includes(accountPhase)) return status('这里就是该账号当前的游戏窗口。');
    if (savedSession(id)) return loginSaved(id, false, true);
    return begin(null, Number(addLoginMethod.value), false, null, id);
  }
  function renderAccounts(force = false) {
    renderLoginVisibility();
    if (!accountsView || !accounts) return;
    const profiles = accounts.profiles();
    if (accountCountNode) accountCountNode.textContent = profiles.length + ' 个账号';
    accountsView.hidden = !profiles.length;
    if (selectedAccountSection) selectedAccountSection.hidden = !profiles.length;
    if (accountEmptyNode) accountEmptyNode.hidden = !!profiles.length;
    if (accountActionsNode) accountActionsNode.hidden = !profiles.length;
    if (accountMoreNode) accountMoreNode.hidden = !profiles.length;
    const data = profiles.map(profile => ({profile, live: accounts.live(profile.id).map(item => item.phase), ready: !!savedSession(profile.id)}));
    if (!profiles.some(profile => profile.id === selectedProfileId)) {
      selectedProfileId = profiles.find(profile => profile.id === (currentProfileId || expectedProfileId))?.id || profiles[0]?.id || null;
      editingProfileId = removingProfileId = inspectingProfileId = null;
    }
    const fingerprint = JSON.stringify({data, selectedProfileId, currentProfileId, expectedProfileId, accountPhase, consumedLaunch, busy: !!active});
    if (!force && fingerprint === accountFingerprint) return;
    accountFingerprint = fingerprint; accountsView.replaceChildren();
    for (const {profile, live, ready} of data) {
      const chosen = profile.id === selectedProfileId;
      const option = document.createElement('button'); option.className = 'account-row' + (chosen ? ' selected' : ''); option.value = profile.id;
      option.setAttribute('aria-pressed', String(chosen));
      const heading = document.createElement('span'); heading.className = 'account-row-heading'; option.appendChild(heading);
      const name = document.createElement('span'); name.className = 'account-row-name'; name.textContent = accounts.label(profile); heading.appendChild(name);
      const badge = document.createElement('span'); badge.className = 'account-row-state';
      badge.textContent = live.includes('connected') ? '游戏中' : ready ? '凭据已保存' : '需要授权'; heading.appendChild(badge);
      const description = document.createElement('span'); description.className = 'account-row-detail';
      description.textContent = [profile.roleName, profile.zoneNote, '账号尾号 ' + profile.id.slice(-4)].filter(Boolean).join(' · '); option.appendChild(description);
      option.onclick = () => { selectedProfileId = profile.id; editingProfileId = removingProfileId = inspectingProfileId = null; renderAccounts(true); };
      accountsView.appendChild(option);
    }
    accountsView.value = selectedProfileId || '';
    const profile = accounts.get(selectedProfileId);
    accountEdit.disabled = accountRemove.disabled = !profile;
    accountInspect.disabled = !profile;
    accountClear.disabled = !profile || !savedSession(profile.id) || !!active;
    accountReauthorize.disabled = !profile || !!active;
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
    accountOpen.textContent = '登录所选账号';
    if (profile) {
      const own = (currentProfileId || expectedProfileId) === profile.id;
      accountOpen.textContent = active ? '正在处理…' : own && consumedLaunch && !['failed', 'disconnected'].includes(accountPhase) ? '当前游戏窗口' : savedSession(profile.id) ? '登录所选账号' : '授权并登录';
      accountOpen.disabled = !!active || (own && consumedLaunch && !['failed', 'disconnected'].includes(accountPhase));
      const recent = profile.lastLoginAt ? new Date(profile.lastLoginAt).toLocaleString('zh-CN', {hour12: false}) : '尚未确认游戏登录';
      accountInfo.textContent = '已选：' + accounts.label(profile);
      accountRecentNode.textContent = '最近游戏登录：' + recent;
    } else accountInfo.textContent = '还没有保存的账号。点击“添加账号”，在小米官方窗口登录并授权。';
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
    if (switchXiaomiButton) switchXiaomiButton.disabled = value;
    if (addAccountButton) addAccountButton.disabled = value;
    if (addLoginMethod) addLoginMethod.disabled = value;
    if (checkUpdateButton) checkUpdateButton.disabled = value || !!updateTask;
    if (retryLoginButton) retryLoginButton.hidden = value || !duplicateRetry;
    if (cancelButton) cancelButton.hidden = !value;
    if (importArea) importArea.hidden = !value || !!(active && active.saved);
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
      const interval = setInterval(() => {
        accept(GM_getValue(key, null));
        if (!done && context.popup && context.popup.closed) finish(reject, new Error('小米登录窗口已关闭，可重新发起授权。'));
      }, 750);
      const timer = setTimeout(() => finish(reject, new Error('小米授权等待超时，请重新发起登录')), 10 * 60 * 1000);
      context.accept = accept;
      context.controller.signal.addEventListener('abort', cancel, {once: true});
    });
  }
  function xiaomiLogoutURL(callback) {
    const logout = new URL('https://account.xiaomi.com/pass/logout');
    logout.search = new URLSearchParams({callback}).toString();
    return logout.href;
  }
  function newAccountLoginURL(loginEntry, authorization, signal) {
    // Initialize a signed official form anonymously so an existing SSO cookie
    // cannot turn Add into automatic authorization of the currently signed-in user.
    // This does not request logout or read/remove any browser cookies.
    return new Promise((resolve, reject) => {
      let done = false, handle;
      const finish = (fn, value) => {
        if (done) return;
        done = true; clearTimeout(timer); signal.removeEventListener('abort', cancel); fn(value);
      };
      const cancel = () => { finish(reject, new Error('已取消')); if (handle) handle.abort(); };
      const timer = setTimeout(() => { finish(reject, new Error('小米登录页初始化超时，请重试')); if (handle) handle.abort(); }, 20000);
      if (signal.aborted) return cancel();
      signal.addEventListener('abort', cancel, {once: true});
      try {
        handle = GM_xmlhttpRequest({method: 'GET', url: loginEntry.href, anonymous: true, redirect: 'follow', timeout: 18000,
          onload(response) {
            try {
              const url = new URL(response.finalUrl);
              if (response.status !== 200 || url.origin !== 'https://account.xiaomi.com' || url.username || url.password
                || url.pathname !== '/fe/service/login' || url.searchParams.get('sid') !== 'passport'
                || url.searchParams.get('callback') !== authorization.href || !url.searchParams.get('_sign')) throw new Error();
              finish(resolve, url.href);
            } catch (_) { finish(reject, new Error('小米登录页初始化失败，请检查网络后重试')); }
          },
          onerror: () => finish(reject, new Error('小米登录页请求失败，请检查网络及油猴权限')),
          ontimeout: () => finish(reject, new Error('小米登录页初始化超时，请重试')),
          onabort: () => finish(reject, new Error('已取消'))
        });
      } catch (_) { finish(reject, new Error('小米登录页请求未发出，请检查油猴权限')); }
    });
  }
  async function begin(retryProfileId = null, loginMethod = 1, addOnly = false, replaceProfileId = null, selectedLoginId = null) {
    if (active) return;
    if (entryError && !addOnly) return status('账号窗口入口已过期，请从账号列表重新打开。');
    duplicateRetry = null;
    const context = {state: randomId(), controller: new AbortController(), popup: null, accept: null, addOnly};
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
      let target = loginMethod === 2 ? loginEntry.href : authorization.href;
      if (addOnly || selectedLoginId) {
        status(addOnly ? '正在打开小米官方登录窗口，请登录要添加的账号。本次只保存账号及凭据，不进入游戏。' : '正在打开小米官方登录窗口，请授权所选账号，完成后将在当前窗口进入游戏。');
        // Keep the two standard game-login methods unchanged. Add always starts
        // from a credential form; method one requests the password tab explicitly.
        target = await newAccountLoginURL(loginEntry, authorization, context.controller.signal);
        if (loginMethod === 1) { const password = new URL(target); password.pathname = '/fe/service/login/password'; target = password.href; }
        if (context.controller.signal.aborted) throw new Error('已取消');
        if (context.popup.closed) throw new Error('小米登录窗口已关闭，请重新发起登录');
      }
      context.popup.location.replace(target);
      status(addOnly
        ? '请在小米登录窗口登录并授权要添加的账号。授权后只保存账号记录；当前游戏窗口保持原账号。'
        : selectedLoginId ? '请在小米登录窗口授权所选账号，完成后将在当前窗口接入游戏。'
        : loginMethod === 2
        ? '请在小米官方标准登录页选择微信等方式登录；完成后会自动继续游戏授权。若需换号，请先使用“退出小米网页登录”。'
        : '请在新窗口完成小米官方授权；完成后会自动回到游戏接入流程。');
      let code = await waiting;
      if (context.popup) { try { context.popup.close(); } catch (_) {} }
      if (addOnly) {
        const identity = await XiaomiCore.authorize(code, status, context.controller.signal); code = null;
        if (context.controller.signal.aborted) throw new Error('已取消');
        if (replaceProfileId && identity.id !== replaceProfileId) throw new Error('授权账号与所选账号不一致，未更改所选账号凭据。');
        if (replaceProfileId && !accounts.get(replaceProfileId)) throw new Error('该账号记录已移除，请重新添加账号。');
        const existed = !!accounts.get(identity.id);
        const profile = accounts.register(identity);
        saveSession(identity);
        selectedProfileId = profile.id; editingProfileId = removingProfileId = inspectingProfileId = null;
        renderAccounts(true);
        status(existed ? '该账号的登录凭据已更新，可从列表直接登录。当前游戏账号未切换。' : '账号及登录凭据已保存，可从列表直接登录。当前游戏账号未切换。');
        return;
      }
      let authorizedProfileId = null;
      const args = await XiaomiCore.connect(code, status, context.controller.signal, async identity => {
        const targetProfileId = selectedLoginId || expectedProfileId || (typeof retryProfileId === 'string' ? retryProfileId : null);
        if (targetProfileId && identity.id !== targetProfileId) throw new Error('授权账号与所选账号不一致，已停止接入。请先点“退出小米网页登录”换号，再授权。');
        if (retryProfileId !== identity.id && await probeAccountWindows(identity.id, context.controller.signal)) {
          duplicateRetry = {id: identity.id, loginMethod, selectedLoginId};
          throw new Error('该账号的其他游戏窗口仍有响应。可返回原窗口；若它未登录或已掉线，请点“仍在此窗口登录”重新授权。');
        }
        if (context.controller.signal.aborted) throw new Error('已取消');
        const profile = accounts.register(identity);
        saveSession(identity);
        authorizedProfileId = profile.id;
      });
      code = null;
      if (context.controller.signal.aborted) throw new Error('已取消');
      launchInCurrentWindow(authorizedProfileId, args);
    } catch (error) {
      const message = error instanceof Error ? error.message : '';
      const trusted = /^(小米|游卡|官方接口|浏览器拦截|请求地址|不是本次|授权校验|授权账号|该账号|账号标识|未取得|SDK 响应|已取消)/.test(message);
      if (!addOnly && !consumedLaunch && accountPhase === 'authorizing') { setAccountPhase('failed'); heartbeat(); }
      if (context.popup) { try { context.popup.close(); } catch (_) {} }
      status(trusted ? message : '登录接入未完成，请导出诊断后反馈最后状态。');
    } finally {
      context.controller.abort();
      GM_deleteValue(pendingKey(context.state)); GM_deleteValue(resultKey(context.state));
      active = null; busy(false);
      if (deferredUpdate) { const pendingUpdate = deferredUpdate; deferredUpdate = null; openUpdate(pendingUpdate.version, pendingUpdate.force); }
    }
  }
  function launchInCurrentWindow(id, args) {
    if (!accounts.get(id)) throw new Error('该账号记录已移除，请重新添加账号。');
    accounts.update(id, {loginAccount: args.account});
    sessionStorage.setItem(ACCOUNT_CONTEXT, id);
    sessionStorage.setItem(LAUNCH, JSON.stringify({expires: Date.now() + 60000, args, profileId: id}));
    // Existing game callbacks still belong to its original account until navigation.
    // The next document consumes the new binding and installs the selected account.
    if (!consumedLaunch) {
      currentProfileId = expectedProfileId = id; selectedProfileId = id;
      setAccountPhase('authorizing'); heartbeat(); updateAccountHeading(); renderAccounts();
    }
    status('小米服登录准备完成，正在当前窗口进入游戏…'); location.assign(GAME);
  }
  async function loginSaved(id, retryHere = false, switchHere = false) {
    if (active) return;
    duplicateRetry = null;
    const identity = savedSession(id);
    if (!identity || !accounts.get(id)) return status('该账号没有保存的登录凭据，请选中账号后点击“重新授权”。');
    if (!switchHere && expectedProfileId && expectedProfileId !== id) return status('账号窗口绑定不匹配，请从账号列表选择目标账号。');
    const context = {state: randomId(), controller: new AbortController(), popup: null, accept: null, saved: true};
    active = context; busy(true);
    try {
      if (!retryHere && await probeAccountWindows(id, context.controller.signal)) {
        duplicateRetry = {id, saved: true};
        throw new Error('该账号的其他游戏窗口仍有响应。如需在当前窗口登录，请点“仍在此窗口登录”。');
      }
      status('正在使用所选账号的已保存凭据登录…');
      const args = await XiaomiCore.connectSaved(identity, status, context.controller.signal);
      if (context.controller.signal.aborted) throw new Error('已取消');
      if (!accounts.get(id) || !savedSession(id)) throw new Error('小米登录凭据已移除，请重新授权');
      launchInCurrentWindow(id, args);
    } catch (error) {
      if (!consumedLaunch) { setAccountPhase('failed'); heartbeat(); }
      const message = error instanceof Error ? error.message : '';
      const trusted = /^(小米|游卡|官方接口|已取消|该账号)/.test(message);
      status((trusted ? message : '使用保存凭据接入未完成。') + (context.controller.signal.aborted || duplicateRetry ? '' : ' 如凭据已失效，请选中账号后点击“重新授权”。'));
    } finally {
      context.controller.abort(); active = null; busy(false);
      if (deferredUpdate) { const pending = deferredUpdate; deferredUpdate = null; openUpdate(pending.version, pending.force); }
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
    host.style.cssText = 'position:fixed;right:16px;top:16px;width:360px;max-width:calc(100vw - 24px);z-index:2147483647;';
    if (!callbackOnly) panelHost = host;
    const root = host.attachShadow({mode: 'closed'});
    const style = document.createElement('style');
    style.textContent = `
      :host{all:initial}:host([hidden]){display:none!important}*{box-sizing:border-box}[hidden]{display:none!important}
      .box{font:13px/1.65 "Microsoft YaHei",system-ui,sans-serif;color:#e9e4da;background:#201e1b;border:1px solid #736044;border-radius:13px;box-shadow:0 16px 48px #0007;overflow:hidden}
      header{display:flex;align-items:center;gap:8px;padding:12px 14px;border-bottom:1px solid #ffffff0d;background:#29251f;color:#edd6a5}.brand{flex:1;font-weight:700;font-size:14px;letter-spacing:.5px}.header-actions{display:flex;gap:4px}.header-actions button{padding:3px 7px;font-size:10px;background:transparent;color:#bcb19e;border:1px solid #ffffff12}
      .panel-content{padding:12px;max-height:calc(100vh - 145px);overflow:auto;scrollbar-width:thin;scrollbar-color:#68543c transparent}
      button{font:inherit;cursor:pointer;border:1px solid transparent;border-radius:7px;padding:8px 11px;background:#dec18a;color:#292218;transition:background .15s,border-color .15s}button:hover{background:#edd3a2}button:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid #e4c58c;outline-offset:2px}button:disabled{opacity:.42;cursor:default}.minor{background:#332e27;border-color:#ffffff10;color:#cfc5b5;font-size:11px;padding:6px 9px}.minor:hover{background:#443b30}.danger{color:#e8aaa0}
      .status-card{padding:8px 10px;background:#292620;border:1px solid #d8ba7c22;border-radius:8px;margin-bottom:12px}.status-caption{font-size:10px;font-weight:700;letter-spacing:.5px;color:#c4ad82;display:flex;align-items:center;gap:7px}.status-caption:before{content:"";width:5px;height:5px;background:currentColor;border-radius:50%}.status-card p{font-size:11px;margin:4px 0 0;color:#c5bdaf;overflow-wrap:anywhere;line-height:1.75}.status-card.error{border-color:#dd81734a;background:#392722}.status-card.error .status-caption{color:#f0a196}.status-card.warning .status-caption{color:#e3bd75}.status-card.success .status-caption{color:#9cc9ad}
      .section-label{display:block;font-size:10px;font-weight:600;color:#a99a80;margin:0 0 6px}.login-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px}.login-grid button{font-size:12px;font-weight:700}.login-grid .secondary{background:#302b23;color:#e5c993;border-color:#9b805747}.login-grid .secondary:hover{background:#3d3427}.login-hint{display:block;margin:5px 0 0;font-size:10px;color:#958975}.current-account{display:block;font-size:10px;color:#c5b393;margin:7px 0 0;overflow-wrap:anywhere}.retry-login{width:100%;margin-top:8px}
      details.section-card{border:1px solid #ffffff10;background:#25221e;border-radius:9px;margin-top:11px;overflow:hidden}summary{display:flex;align-items:center;gap:7px;cursor:pointer;list-style:none;padding:8px 11px;font-size:12px;font-weight:700;color:#dbceba;user-select:none}summary::-webkit-details-marker{display:none}summary:after{content:"›";margin-left:auto;color:#9f8d70;font-size:17px;line-height:1;transform:rotate(0deg)}details[open]>summary:after{transform:rotate(90deg)}.section-body{padding:2px 10px 10px}.record-count{margin-left:3px;padding:1px 6px;border-radius:20px;background:#ffffff08;color:#a99c87;font-size:10px;font-weight:400}
      .account-add{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:7px}.account-add button{font-size:11px;font-weight:700;padding:7px 12px}.add-method{min-width:0;width:100%;background:#1e1c19;color:#d7cab5;border:1px solid #68563d;border-radius:7px;padding:7px;font:11px "Microsoft YaHei",sans-serif}.account-add-hint{display:block;font-size:10px;line-height:1.7;color:#958873;margin:5px 0 12px}
      .account-list-heading{display:flex;align-items:center;justify-content:space-between;margin:10px 0 5px}.account-list-heading .section-label{margin:0}.account-refresh{font-size:10px;padding:2px 0;background:transparent;border:0;color:#a39276}.account-refresh:hover{color:#e4c894;background:transparent}.accounts{display:flex;flex-direction:column;gap:6px;max-height:208px;overflow:auto;scrollbar-width:thin;scrollbar-color:#68543c transparent}
      .account-row{display:block;width:100%;flex:none;text-align:left;background:#1e1c19;border:1px solid #ffffff0d;color:#d1c7b7;padding:7px 9px;border-radius:7px}.account-row:hover{background:#30291f;border-color:#a38b5f66}.account-row.selected{background:#3b3021;border-color:#b3945d}.account-row-heading{display:flex;align-items:center;gap:8px}.account-row-name{font-size:12px;font-weight:700;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.account-row-state{font-size:9px;color:#bcaa8e;white-space:nowrap}.account-row-detail{display:block;font-size:10px;color:#a99a83;margin-top:2px;overflow-wrap:anywhere}
      .selected-account{margin-top:8px;padding-top:7px;border-top:1px solid #ffffff0c}.account-info{display:block;white-space:pre-line;overflow-wrap:anywhere;font-size:11px;color:#c4b598;margin:0 0 7px}.account-actions{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:6px}.account-actions .account-open{font-size:12px;font-weight:700;padding:7px 10px}.account-empty{font-size:11px;color:#9d907b;margin:10px 0 4px}.account-more{margin-top:8px}.account-more summary{padding:4px 0;font-size:10px;font-weight:400;color:#a99b84}.account-recent{display:block;font-size:10px;color:#8f8370;margin:5px 0 7px}.account-more-actions{display:grid;grid-template-columns:1fr 1fr;gap:6px}.account-more-actions button{text-align:left;font-size:11px;padding:7px 9px;background:#2e2923;border:1px solid #ffffff0a}.account-more-actions button:hover{background:#3b3228}
      input,textarea{width:100%;font:inherit;background:#1e1c19;color:#e9e2d6;padding:8px;border:1px solid #68563d;border-radius:6px}input::placeholder{color:#8e8578}.account-editor{padding:3px 0 5px}.account-editor input{margin-top:7px;font-size:12px}.account-editor button{margin:7px 5px 0 0}
      .record-tools{display:flex;gap:5px;padding:0 10px 8px}.record-tools button{flex:1;font-size:10px;padding:5px 6px}.record-list{list-style:none;padding:0 10px 0 20px;margin:0 0 10px;max-height:200px;overflow:auto;scrollbar-width:thin;scrollbar-color:#68543c transparent}.record-item{position:relative;border-left:1px solid #514636;padding:0 8px 13px 13px;margin:0}.record-item:before{content:"";position:absolute;left:-4px;top:7px;width:7px;height:7px;border-radius:50%;background:#80725c;border:2px solid #25221e}.record-item:last-child{padding-bottom:0;border-left-color:transparent}.record-item.error:before{background:#ef998c}.record-item.warning:before{background:#d5af6b}.record-item.success:before{background:#9bc4a9}.record-item.is-current.progress:before{background:#e2c38a;box-shadow:0 0 0 3px #e2c38a19}
      .record-meta{display:flex;align-items:center;justify-content:space-between;font-size:10px;color:#8f8371;font-variant-numeric:tabular-nums}.record-badge{font-size:9px;color:#9f927c}.record-item.is-current .record-badge{color:#dfc38e}.record-item.error .record-badge,.record-item.error .record-message{color:#edaa9e}.record-item.success .record-badge{color:#a4c4ae}.record-message{font-size:11px;color:#bdb3a3;line-height:1.8;margin-top:3px;overflow-wrap:anywhere}.record-item.is-current .record-message{color:#eee1ca}.record-item.error.is-current .record-message{color:#edaa9e}.record-empty{font-size:11px;color:#958875;padding:8px 0 12px;line-height:1.8}
      .panel-footer{display:flex;align-items:center;justify-content:space-between;gap:7px;padding:9px 12px;border-top:1px solid #ffffff0d;background:#25211c}.panel-footer small{color:#92836b;font-size:10px}.footer-actions{display:flex;align-items:center;gap:9px}.panel-footer button{font-size:10px;padding:4px 6px}.footer-link{background:transparent;border:0;color:#978c7a;padding:4px 0!important}.footer-link:hover{background:transparent;color:#d7c5a7}.manual-entry{margin:9px 0}.manual-entry small{display:block;font-size:11px;color:#b5a68d;margin-bottom:7px}.manual-entry button{margin-top:7px}.cancel-login{margin-top:8px;width:100%}
    `;
    root.appendChild(style);
    const box = document.createElement('section'); box.className = 'box'; root.appendChild(box);
    const header = document.createElement('header'); box.appendChild(header);
    const brand = document.createElement('span'); brand.className = 'brand'; brand.textContent = '一将成名 · 小米服'; header.appendChild(brand);
    const headerActions = document.createElement('div'); headerActions.className = 'header-actions'; header.appendChild(headerActions);
    const content = document.createElement('div'); content.className = 'panel-content';
    const collapse = document.createElement('button'); collapse.className = 'minor'; collapse.textContent = '收起';
    collapse.onclick = () => { content.hidden = !content.hidden; collapse.textContent = content.hidden ? '展开' : '收起'; };
    headerActions.appendChild(collapse); box.appendChild(content);
    if (!callbackOnly) {
      const hide = document.createElement('button'); hide.className = 'minor'; hide.textContent = '隐藏';
      hide.title = '可从油猴菜单的“小米服：显示登录面板”重新打开';
      hide.onclick = () => { setPanelVisible(false); savePreferences({hidden: true}); };
      headerActions.appendChild(hide);
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
    statusCard = document.createElement('div'); statusCard.className = 'status-card'; content.appendChild(statusCard);
    statusCaption = document.createElement('div'); statusCaption.className = 'status-caption'; statusCard.appendChild(statusCaption);
    statusNode = document.createElement('p'); statusNode.setAttribute('role', 'status'); statusNode.setAttribute('aria-live', 'polite'); statusCard.appendChild(statusNode); renderStatus();
    if (!callbackOnly) {
      loginSectionNode = document.createElement('div'); loginSectionNode.className = 'login-section'; content.appendChild(loginSectionNode);
      const loginTitle = document.createElement('small'); loginTitle.className = 'section-label'; loginTitle.textContent = '小米官方登录'; loginSectionNode.appendChild(loginTitle);
      const loginGrid = document.createElement('div'); loginGridNode = loginGrid; loginGrid.className = 'login-grid'; loginSectionNode.appendChild(loginGrid);
      loginButton = document.createElement('button'); loginButton.textContent = '登录方式一';
      loginButton.title = '打开原小米官方游戏授权页'; loginButton.onclick = () => begin(); loginGrid.appendChild(loginButton);
      alternateLoginButton = document.createElement('button'); alternateLoginButton.textContent = '登录方式二';
      alternateLoginButton.className = 'secondary'; alternateLoginButton.title = '先打开小米官方标准登录页，可选择微信等登录方式';
      alternateLoginButton.onclick = () => begin(null, 2); loginGrid.appendChild(alternateLoginButton);
      const loginHint = document.createElement('small'); loginHintNode = loginHint; loginHint.className = 'login-hint'; loginHint.textContent = '方式一：原授权入口　方式二：支持微信等方式'; loginSectionNode.appendChild(loginHint);
      retryLoginButton = document.createElement('button'); retryLoginButton.className = 'minor retry-login'; retryLoginButton.textContent = '仍在此窗口登录'; retryLoginButton.hidden = !duplicateRetry;
      retryLoginButton.title = '重新授权同一账号，服务器可能使原窗口下线';
      retryLoginButton.onclick = () => {
        if (!duplicateRetry) { retryLoginButton.hidden = true; return status('请先点击“登录方式一”或“登录方式二”。'); }
        if (duplicateRetry.saved) return loginSaved(duplicateRetry.id, true, true);
        return begin(duplicateRetry.id, duplicateRetry.loginMethod, false, null, duplicateRetry.selectedLoginId);
      }; content.appendChild(retryLoginButton);
      currentAccountNode = document.createElement('small'); currentAccountNode.className = 'current-account'; content.appendChild(currentAccountNode);
      const manager = document.createElement('details'); manager.className = 'section-card'; manager.open = false;
      const managerTitle = document.createElement('summary'); manager.appendChild(managerTitle);
      const managerLabel = document.createElement('span'); managerLabel.textContent = '账号管理'; managerTitle.appendChild(managerLabel);
      accountCountNode = document.createElement('span'); accountCountNode.className = 'record-count'; managerTitle.appendChild(accountCountNode);
      const managerBody = document.createElement('div'); managerBody.className = 'section-body'; manager.appendChild(managerBody);
      const accountToolbar = document.createElement('div'); accountToolbar.className = 'account-add'; managerBody.appendChild(accountToolbar);
      addLoginMethod = document.createElement('select'); addLoginMethod.className = 'add-method'; addLoginMethod.setAttribute('aria-label', '添加账号时使用的登录方式');
      for (const [value, text] of [['2', '标准登录（含微信）'], ['1', '账号密码登录']]) {
        const option = document.createElement('option'); option.value = value; option.textContent = text; addLoginMethod.appendChild(option);
      }
      addLoginMethod.value = '2'; accountToolbar.appendChild(addLoginMethod);
      const add = document.createElement('button'); addAccountButton = add; add.textContent = '添加账号'; add.title = '在小米官方窗口授权并保存凭据，不自动进入游戏或退出原账号'; add.onclick = () => begin(null, Number(addLoginMethod.value), true); accountToolbar.appendChild(add);
      const listHeading = document.createElement('div'); listHeading.className = 'account-list-heading'; managerBody.appendChild(listHeading);
      const listTitle = document.createElement('small'); listTitle.className = 'section-label'; listTitle.textContent = '选择账号'; listHeading.appendChild(listTitle);
      const refresh = document.createElement('button'); refresh.className = 'minor account-refresh'; refresh.textContent = '刷新列表'; refresh.onclick = () => renderAccounts(true); listHeading.appendChild(refresh);
      accountsView = document.createElement('div'); accountsView.className = 'accounts'; accountsView.setAttribute('role', 'group');
      accountsView.setAttribute('aria-label', '已保存的账号，点击选择'); managerBody.appendChild(accountsView);
      accountEmptyNode = document.createElement('p'); accountEmptyNode.className = 'account-empty'; accountEmptyNode.textContent = '还没有保存的账号，先在上方添加。'; managerBody.appendChild(accountEmptyNode);
      const switchXiaomi = document.createElement('button'); switchXiaomiButton = switchXiaomi; switchXiaomi.className = 'footer-link'; switchXiaomi.textContent = '退出小米网页登录';
      switchXiaomi.title = '退出小米网站的登录状态并打开登录页；不清除账号列表里已保存的游戏凭据';
      switchXiaomi.onclick = () => {
        if (active) return status('请先完成或取消当前授权，再切换小米账号。');
        // Use Xiaomi's own logout chain to clear its web SSO cookies across domains.
        // Do not delete game-window bindings or account-manager records.
        const popup = window.open('about:blank', 'xiaomi-sgs-account-switch-' + randomId(), 'width=560,height=780');
        if (!popup) return status('浏览器拦截了小米账号窗口，请允许弹出窗口后重试。');
        popup.opener = null; popup.location.replace(xiaomiLogoutURL('https://account.xiaomi.com/pass/serviceLogin?sid=passport'));
        status('已打开小米官方退出流程，将清理旧网页登录并进入登录页。添加账号无需使用此操作。');
      };
      selectedAccountSection = document.createElement('div'); selectedAccountSection.className = 'selected-account'; managerBody.appendChild(selectedAccountSection);
      accountInfo = document.createElement('small'); accountInfo.className = 'account-info'; selectedAccountSection.appendChild(accountInfo);
      const accountActions = document.createElement('div'); accountActionsNode = accountActions; accountActions.className = 'account-actions'; selectedAccountSection.appendChild(accountActions);
      accountOpen = document.createElement('button'); accountOpen.className = 'account-open';
      accountOpen.onclick = () => loginSelectedAccount(selectedProfileId); accountOpen.title = '在当前窗口登录选中的账号'; accountActions.appendChild(accountOpen);
      accountEdit = document.createElement('button'); accountEdit.className = 'minor'; accountEdit.textContent = '修改备注';
      accountEdit.onclick = () => {
        const profile = accounts.get(selectedProfileId); if (!profile) return renderAccounts(true);
        editingProfileId = profile.id; removingProfileId = null;
        aliasInput.value = profile.alias || ''; zoneInput.value = profile.zoneNote || ''; renderAccounts(true);
      }; accountActions.appendChild(accountEdit);
      accountRemove = document.createElement('button'); accountRemove.className = 'minor danger'; accountRemove.textContent = '移除记录';
      accountRemove.onclick = () => {
        const profile = accounts.get(selectedProfileId); if (!profile) return renderAccounts(true);
        if (removingProfileId !== profile.id) { removingProfileId = profile.id; editingProfileId = null; renderAccounts(true); return; }
        clearSession(profile.id); accounts.remove(profile.id); editingProfileId = removingProfileId = null;
        renderAccounts(true); status('所选账号的本地记录已移除，已打开的游戏不会退出。');
      };
      accountInspect = document.createElement('button'); accountInspect.className = 'minor'; accountInspect.textContent = '查看账号信息';
      accountInspect.onclick = () => {
        inspectingProfileId = inspectingProfileId === selectedProfileId ? null : selectedProfileId; renderAccounts(true);
      };
      const more = document.createElement('details'); accountMoreNode = more; more.className = 'account-more';
      const moreTitle = document.createElement('summary'); moreTitle.textContent = '更多操作'; more.appendChild(moreTitle);
      accountRecentNode = document.createElement('small'); accountRecentNode.className = 'account-recent'; more.appendChild(accountRecentNode);
      const moreActions = document.createElement('div'); moreActions.className = 'account-more-actions'; more.appendChild(moreActions);
      accountReauthorize = document.createElement('button'); accountReauthorize.className = 'minor'; accountReauthorize.textContent = '重新授权';
      accountReauthorize.onclick = () => { const id = selectedProfileId; if (accounts.get(id)) return begin(null, Number(addLoginMethod.value), true, id); }; moreActions.appendChild(accountReauthorize);
      moreActions.appendChild(accountInspect);
      accountClear = document.createElement('button'); accountClear.className = 'minor'; accountClear.textContent = '清除登录凭据';
      accountClear.onclick = () => { if (active || !accounts.get(selectedProfileId)) return; clearSession(selectedProfileId); renderAccounts(true); status('所选账号的已保存登录凭据已清除；账号记录和当前游戏保留。'); }; moreActions.appendChild(accountClear);
      moreActions.appendChild(accountRemove);
      accountDetails = document.createElement('div'); accountDetails.hidden = true;
      accountDetailsText = document.createElement('textarea'); accountDetailsText.readOnly = true;
      accountDetailsText.setAttribute('aria-label', '账号信息（不含登录凭据）');
      accountDetailsText.style.cssText = 'height:155px;resize:vertical;font-size:11px;line-height:1.8;margin-top:8px;';
      accountDetails.appendChild(accountDetailsText);
      const identityHint = document.createElement('small'); identityHint.className = 'account-info';
      identityHint.textContent = '这些是官方登录流程返回的账号标识；不等于绑定手机号，也不代表可使用官网密码登录。'; accountDetails.appendChild(identityHint);
      const copyIdentity = document.createElement('button'); copyIdentity.className = 'minor'; copyIdentity.textContent = '复制账号信息';
      copyIdentity.onclick = async () => {
        if (!accounts.get(selectedProfileId) || accountDetails.hidden) return;
        try { await navigator.clipboard.writeText(accountDetailsText.value); status('账号信息已复制，不含登录凭据。'); }
        catch (_) { accountDetailsText.focus(); accountDetailsText.select(); status('已选中账号信息，请按 Ctrl+C 复制。'); }
      }; accountDetails.appendChild(copyIdentity); more.appendChild(accountDetails);
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
      selectedAccountSection.appendChild(accountEditor); selectedAccountSection.appendChild(more); content.appendChild(manager);
      cancelButton = document.createElement('button'); cancelButton.textContent = '取消'; cancelButton.className = 'minor cancel-login'; cancelButton.hidden = true;
      cancelButton.onclick = () => { if (active) { active.controller.abort(); try { active.popup.close(); } catch (_) {} } }; content.appendChild(cancelButton);
      importArea = document.createElement('details'); importArea.className = 'manual-entry'; importArea.hidden = true;
      const summary = document.createElement('summary'); summary.textContent = '授权后卡在 404／空白页？'; importArea.appendChild(summary);
      const hint = document.createElement('small'); hint.textContent = '复制授权后地址栏的完整地址，粘贴到这里继续。'; importArea.appendChild(hint);
      const input = document.createElement('input'); input.type = 'password'; input.autocomplete = 'off'; input.placeholder = '粘贴小米授权回调地址'; importArea.appendChild(input);
      const submit = document.createElement('button'); submit.className = 'minor'; submit.textContent = '继续登录';
      submit.onclick = () => { const raw = input.value.trim(); input.value = ''; manual(raw); }; importArea.appendChild(submit); content.appendChild(importArea);
      const diagnostics = document.createElement('details'); diagnostics.className = 'section-card'; historyDetails = diagnostics;
      const label = document.createElement('summary'); diagnostics.appendChild(label);
      const recordTitle = document.createElement('span'); recordTitle.textContent = '运行记录'; label.appendChild(recordTitle);
      historyCount = document.createElement('span'); historyCount.className = 'record-count'; label.appendChild(historyCount);
      const recordTools = document.createElement('div'); recordTools.className = 'record-tools'; diagnostics.appendChild(recordTools);
      historyFilterButton = document.createElement('button'); historyFilterButton.className = 'minor';
      historyFilterButton.onclick = () => { errorsOnly = !errorsOnly; renderHistory(); }; recordTools.appendChild(historyFilterButton);
      historyClearButton = document.createElement('button'); historyClearButton.className = 'minor'; historyClearButton.textContent = '清空记录';
      historyClearButton.title = '只清空当前页面的运行记录，不影响账号或登录';
      historyClearButton.onclick = () => { log.length = 0; errorsOnly = false; renderHistory(); }; recordTools.appendChild(historyClearButton);
      logNode = document.createElement('ol'); logNode.className = 'record-list'; logNode.setAttribute('aria-label', '运行记录，最新在前');
      const download = document.createElement('button'); download.className = 'minor'; download.textContent = '导出诊断';
      download.onclick = () => {
        const url = URL.createObjectURL(new Blob([JSON.stringify({version: VERSION, scope: '阶段提示；不包含账号与会话值', events: log}, null, 2)], {type: 'application/json'}));
        const link = document.createElement('a'); link.href = url; link.download = '小米服浏览器诊断.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      }; recordTools.appendChild(download); diagnostics.appendChild(logNode); content.appendChild(diagnostics); renderHistory();
      const footer = document.createElement('div'); footer.className = 'panel-footer'; box.appendChild(footer);
      checkUpdateButton = document.createElement('button'); checkUpdateButton.className = 'minor'; checkUpdateButton.textContent = '检查更新';
      checkUpdateButton.onclick = () => checkUpdates(true);
      const note = document.createElement('small'); note.textContent = 'v' + VERSION; footer.appendChild(note);
      const footerActions = document.createElement('div'); footerActions.className = 'footer-actions'; footer.appendChild(footerActions);
      footerActions.appendChild(switchXiaomi); footerActions.appendChild(checkUpdateButton);
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
  ready(() => { panel(); checkUpdates(); if (autoLoginProfileId) { const id = autoLoginProfileId; autoLoginProfileId = null; loginSaved(id); } });
  setInterval(() => checkUpdates(), UPDATE_INTERVAL);
})();
