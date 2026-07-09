/* =========================================================================
 * Pass2KDBX Engine — 纯转换逻辑（无 DOM 依赖）
 * App 前端（Material Design 3 界面）调用 window.Pass2KDBXEngine.run(opts)
 *
 * 依赖全局库（由 index.html 通过 <script src="vendor/..."> 注入）：
 *   - kdbxweb  (window.kdbxweb)
 *   - hashwasm (window.hashwasm, Argon2)
 *   - JSZip    (window.JSZip)
 * 以及浏览器原生：crypto, File, TextEncoder, Blob, URL
 * ========================================================================= */
(function (global) {
  'use strict';

  const { Kdbx, Credentials, ProtectedValue, Consts, KdbxUuid } = global.kdbxweb;

  const APP_VERSION = '2.2';
  const TYPE_NAMES = { 1: 'Login', 2: 'SecureNote', 3: 'Card', 4: 'Identity', 5: 'SSHKey' };
  const TYPE_NAME_TO_ID = { 'Login': 1, 'SecureNote': 2, 'Card': 3, 'Identity': 4, 'SSHKey': 5 };

  // ----- Argon2 注册（沿用网页版实现）-----
  let argon2Ready = false;
  function initArgon2() {
    if (typeof global.hashwasm === 'undefined' || typeof global.kdbxweb === 'undefined') return;
    try {
      global.hashwasm.argon2d({
        password: 't', salt: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        memorySize: 64, iterations: 1, parallelism: 1, hashLength: 32, outputType: 'binary'
      }).then(function () {
        global.kdbxweb.CryptoEngine.setArgon2Impl(function (password, salt, memory, iterations, hashLength, parallelism, type, version) {
          const opts = { password: new Uint8Array(password), salt: new Uint8Array(salt), memorySize: memory, iterations: iterations, parallelism: parallelism, hashLength: hashLength, outputType: 'binary' };
          if (type === 2) return global.hashwasm.argon2id(opts);
          return global.hashwasm.argon2d(opts);
        });
        argon2Ready = true;
      }).catch(function () { /* 回退 AES-KDF */ });
    } catch (e) { /* ignore */ }
  }
  if (typeof global.hashwasm !== 'undefined') initArgon2();
  else global.addEventListener('load', function () { setTimeout(initArgon2, 100); });

  // ----- File/Blob polyfills -----
  if (typeof File !== 'undefined' && File.prototype && !File.prototype.arrayBuffer) {
    File.prototype.arrayBuffer = function () {
      return new Promise((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => resolve(r.result);
        r.onerror = () => reject(r.error || new Error('FileReader error'));
        r.readAsArrayBuffer(this);
      });
    };
  }
  if (typeof Blob !== 'undefined' && Blob.prototype && !Blob.prototype.arrayBuffer) {
    Blob.prototype.arrayBuffer = function () {
      return new Promise((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => resolve(r.result);
        r.onerror = () => reject(r.error || new Error('FileReader error'));
        r.readAsArrayBuffer(this);
      });
    };
  }

  function generateUUID() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
      const buf = new Uint8Array(16);
      crypto.getRandomValues(buf);
      buf[6] = (buf[6] & 0x0f) | 0x40;
      buf[8] = (buf[8] & 0x3f) | 0x80;
      const hex = [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
      return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }

  // ----- base64 / UUID / PEM 互转（Passkey）-----
  function uuidToBase64(uuid) {
    if (!uuid || uuid.includes('=') || uuid.includes('+') || uuid.includes('/')) return uuid;
    const hex = uuid.replace(/-/g, '');
    if (!/^[0-9a-fA-F]+$/.test(hex)) return uuid;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function formatPrivateKeyPEM(keyValue) {
    if (!keyValue) return '';
    if (keyValue.includes('-----BEGIN')) return keyValue;
    try {
      const urlSafe = keyValue.replace(/-/g, '+').replace(/_/g, '/');
      const padding = keyValue.length % 4;
      const padded = padding ? urlSafe + '='.repeat(4 - padding) : urlSafe;
      const rawBytes = Uint8Array.from(atob(padded), c => c.charCodeAt(0));
      let binary = '';
      for (let i = 0; i < rawBytes.length; i++) binary += String.fromCharCode(rawBytes[i]);
      const stdB64 = btoa(binary);
      const lines = ['-----BEGIN PRIVATE KEY-----'];
      for (let i = 0; i < stdB64.length; i += 64) lines.push(stdB64.substring(i, i + 64));
      lines.push('-----END PRIVATE KEY-----');
      return lines.join('\n');
    } catch (e) {
      const lines = ['-----BEGIN PRIVATE KEY-----'];
      for (let i = 0; i < keyValue.length; i += 64) lines.push(keyValue.substring(i, i + 64));
      lines.push('-----END PRIVATE KEY-----');
      return lines.join('\n');
    }
  }
  function base64ToUUID(b64url) {
    if (!b64url) return '';
    if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(b64url)) return b64url;
    try {
      let std = b64url.replace(/-/g, '+').replace(/_/g, '/');
      const padding = std.length % 4;
      if (padding) std += '='.repeat(4 - padding);
      const binary = atob(std);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      let hex = '';
      for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
      if (hex.length === 32) return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
      return hex;
    } catch (e) { return b64url; }
  }
  function pemToB64Url(pem) {
    if (!pem) return '';
    if (!pem.includes('-----BEGIN')) return pem;
    try {
      const lines = pem.split('\n').filter(l => !l.startsWith('-----'));
      const stdB64 = lines.join('').trim();
      const binary = atob(stdB64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      let rawB64 = '';
      for (let i = 0; i < bytes.length; i++) rawB64 += String.fromCharCode(bytes[i]);
      return btoa(rawB64).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    } catch (e) { return pem; }
  }

  // ----- Passkey 反向 / 正向 -----
  function extractPasskeysFromFields(passkeyFields) {
    const credKeys = Object.keys(passkeyFields)
      .filter(k => k.startsWith('KPEX_PASSKEY_CREDENTIAL_ID'))
      .sort((a, b) => {
        const getIdx = (k) => k === 'KPEX_PASSKEY_CREDENTIAL_ID' ? -1 : parseInt(k.split('_').pop());
        return getIdx(a) - getIdx(b);
      });
    const result = [];
    for (const ck of credKeys) {
      let suffix = '';
      if (ck !== 'KPEX_PASSKEY_CREDENTIAL_ID') suffix = '_' + ck.split('_').pop();
      const credentialIdB64 = passkeyFields[ck] || '';
      const credentialId = base64ToUUID(credentialIdB64);
      const keyPem = passkeyFields[`KPEX_PASSKEY_PRIVATE_KEY_PEM${suffix}`] || '';
      const keyValue = pemToB64Url(keyPem);
      const rpId = passkeyFields[`KPEX_PASSKEY_RELYING_PARTY${suffix}`] || '';
      const userHandle = passkeyFields[`KPEX_PASSKEY_USER_HANDLE${suffix}`] || '';
      const userName = passkeyFields[`KPEX_PASSKEY_USERNAME${suffix}`] || '';
      const rpName = passkeyFields[`KPEX_PASSKEY_RP_NAME${suffix}`] || rpId;
      const userDisplayName = passkeyFields[`KPEX_PASSKEY_USER_DISPLAY_NAME${suffix}`] || userName;
      const creationDate = passkeyFields[`KPEX_PASSKEY_CREATION_DATE${suffix}`] || '';
      result.push({
        credentialId, keyType: 'public-key', keyAlgorithm: 'ECDSA', keyCurve: 'P-256', keyValue,
        rpId, rpName, userHandle, userName, userDisplayName, counter: '0', discoverable: 'true', creationDate
      });
    }
    return result;
  }
  function buildPasskeyFile(fc, item) {
    return {
      relyingParty: fc.rpId || '',
      url: (item.login?.uris && item.login.uris.length > 0) ? (item.login.uris[0].uri || '') : '',
      username: fc.userName || item.login?.username || '',
      credentialId: uuidToBase64(fc.credentialId || ''),
      userHandle: fc.userHandle || '',
      privateKey: formatPrivateKeyPEM(fc.keyValue || '')
    };
  }

  // ----- Notes / CustomFields / Tags builders -----
  function buildNotes(item) {
    const parts = [];
    if (item.notes) parts.push(item.notes);
    if (item.card && (item.card.number || item.card.cardholderName)) {
      const lines = ['\n[卡片信息]'];
      if (item.card.cardholderName) lines.push(`持卡人: ${item.card.cardholderName}`);
      if (item.card.brand) lines.push(`品牌: ${item.card.brand}`);
      if (item.card.number) lines.push(`卡号: ${item.card.number}`);
      if (item.card.expMonth) lines.push(`有效期: ${item.card.expMonth}/${item.card.expYear}`);
      if (item.card.code) lines.push(`安全码: ${item.card.code}`);
      parts.push(lines.join('\n'));
    }
    if (item.passwordHistory?.length) {
      const lines = ['\n[密码历史]'];
      for (const h of item.passwordHistory.slice(0, 10)) {
        const ds = h.lastUsedDate ? ` (${h.lastUsedDate})` : '';
        lines.push(`- ${h.password}${ds}`);
      }
      parts.push(lines.join('\n'));
    }
    return parts.join('\n');
  }
  function buildCustomFields(item) {
    const fields = {};
    if (item.type) fields['BitwardenType'] = TYPE_NAMES[item.type] || `Type${item.type}`;
    if (item.login?.totp) {
      const totpRaw = item.login.totp;
      let otpauthUrl = totpRaw;
      if (!totpRaw.startsWith('otpauth://')) {
        const label = encodeURIComponent(item.name || 'Account');
        const issuer = item.login.username ? encodeURIComponent(item.login.username) : label;
        otpauthUrl = `otpauth://totp/${issuer}:${label}?secret=${totpRaw}&issuer=${issuer}&digits=6&period=30`;
      }
      fields['TOTP Seed'] = totpRaw;
      fields['TOTP Settings'] = '30;6';
      fields['otp'] = otpauthUrl;
    }
    if (item.login?.uris?.length) {
      const isAndroidUri = uri => uri.startsWith('androidapp://') || uri.startsWith('android://');
      const parseAndroidUri = uri => {
        if (uri.startsWith('androidapp://')) return { pkg: uri.slice(13), sig: '' };
        if (uri.startsWith('android://')) {
          const rest = uri.slice(9);
          if (rest.includes('@')) {
            const at = rest.lastIndexOf('@');
            const fpHex = rest.substring(0, at);
            const pkg = rest.substring(at + 1);
            const sig = fpHex.match(/.{2}/g).join(':').toUpperCase();
            return { pkg, sig };
          }
          return { pkg: rest, sig: '' };
        }
        return null;
      };
      let appIdx = 0;
      const seenUris = new Set();
      for (const u of item.login.uris) {
        const uri = u.uri || '';
        if (!uri || seenUris.has(uri)) continue;
        seenUris.add(uri);
        if (isAndroidUri(uri)) {
          const parsed = parseAndroidUri(uri);
          if (parsed && parsed.pkg) {
            const key = appIdx === 0 ? 'AndroidApp' : `AndroidApp${appIdx + 1}`;
            fields[key] = parsed.pkg;
            if (parsed.sig) {
              const sigKey = appIdx === 0 ? 'AndroidApp Signature' : `AndroidApp Signature${appIdx + 1}`;
              fields[sigKey] = parsed.sig;
            }
            appIdx++;
          }
        }
      }
      const mainUri = item.login.uris.find(u => u.uri && (u.uri.startsWith('http://') || u.uri.startsWith('https://')));
      let urlIdx = 0;
      for (const u of item.login.uris) {
        const uri = u.uri || '';
        if (!uri || isAndroidUri(uri) || (mainUri && uri === mainUri.uri)) continue;
        if (uri.startsWith('http://') || uri.startsWith('https://')) {
          urlIdx++;
          const key = urlIdx === 1 ? 'KP2A_URL' : `KP2A_URL_${urlIdx}`;
          fields[key] = uri;
        }
      }
    }
    if (item.card) {
      if (item.card.brand) fields['CardBrand'] = item.card.brand;
      if (item.card.number) fields['CardNumber'] = item.card.number;
      if (item.card.expMonth) fields['CardExpiry'] = `${item.card.expMonth}/${item.card.expYear}`;
    }
    if (item.identity) {
      const idMap = {
        'IdentityTitle': item.identity.title, 'IdentityFirstName': item.identity.firstName,
        'IdentityMiddleName': item.identity.middleName, 'IdentityLastName': item.identity.lastName,
        'IdentityAddress1': item.identity.address1, 'IdentityCity': item.identity.city,
        'IdentityState': item.identity.state, 'IdentityPostalCode': item.identity.postalCode,
        'IdentityCountry': item.identity.country, 'IdentityEmail': item.identity.email,
        'IdentityPhone': item.identity.phone, 'IdentitySSN': item.identity.ssn,
        'IdentityPassport': item.identity.passportNumber, 'IdentityLicense': item.identity.licenseNumber
      };
      for (const [k, v] of Object.entries(idMap)) if (v) fields[k] = v;
    }
    if (item.sshKey?.fingerprint) fields['SSHFingerprint'] = item.sshKey.fingerprint;
    for (const cf of item.customFields) if (!fields[cf.name]) fields[cf.name] = cf.value;
    for (let i = 0; i < item.fido2Credentials.length; i++) {
      const fc = item.fido2Credentials[i];
      const idx = item.fido2Credentials.length > 1 ? `_${i}` : '';
      if (fc.credentialId) fields[`KPEX_PASSKEY_CREDENTIAL_ID${idx}`] = uuidToBase64(fc.credentialId);
      if (fc.keyValue) fields[`KPEX_PASSKEY_PRIVATE_KEY_PEM${idx}`] = formatPrivateKeyPEM(fc.keyValue);
      if (fc.rpId) fields[`KPEX_PASSKEY_RELYING_PARTY${idx}`] = fc.rpId;
      if (fc.userHandle) fields[`KPEX_PASSKEY_USER_HANDLE${idx}`] = fc.userHandle;
      if (fc.userName) fields[`KPEX_PASSKEY_USERNAME${idx}`] = fc.userName;
      if (fc.rpName && fc.rpName !== fc.rpId) fields[`KPEX_PASSKEY_RP_NAME${idx}`] = fc.rpName;
      if (fc.userDisplayName && fc.userDisplayName !== fc.userName) fields[`KPEX_PASSKEY_USER_DISPLAY_NAME${idx}`] = fc.userDisplayName;
      if (fc.creationDate) fields[`KPEX_PASSKEY_CREATION_DATE${idx}`] = fc.creationDate;
    }
    if (item.creationDate) fields['CreationDate'] = item.creationDate;
    if (item.revisionDate) fields['RevisionDate'] = item.revisionDate;
    return fields;
  }
  function buildTags(item) {
    const tags = [];
    const tn = TYPE_NAMES[item.type];
    if (tn) tags.push(tn);
    if (item.favorite) tags.push('Favorite');
    if (item.fido2Credentials?.length) tags.push('Passkey');
    return tags;
  }

  // ----- BW JSON parser -----
  function parseBitwardenJson(json) {
    const folders = [], items = [];
    if (json.folders) for (const f of json.folders) folders.push({ id: f.id, name: f.name });
    if (json.items) {
      for (const item of json.items) {
        if (item.deletedDate) continue;
        const parsed = {
          id: item.id, name: item.name || '', type: item.type || 1,
          notes: item.notes || '', favorite: item.favorite || false,
          folderId: item.folderId || null, collectionIds: item.collectionIds || [],
          deleted: false, creationDate: item.creationDate || '', revisionDate: item.revisionDate || '',
          login: null, card: null, identity: null, secureNote: null, sshKey: null,
          fido2Credentials: [], customFields: [], passwordHistory: []
        };
        if (item.login) {
          parsed.login = {
            username: item.login.username || '', password: item.login.password || '',
            totp: item.login.totp || '',
            uris: (item.login.uris || []).map(u => ({ uri: u.uri || '', match: u.match || null }))
          };
        }
        if (item.card) parsed.card = {
          cardholderName: item.card.cardholderName || '', brand: item.card.brand || '',
          number: item.card.number || '', expMonth: item.card.expMonth || '',
          expYear: item.card.expYear || '', code: item.card.code || ''
        };
        if (item.identity) parsed.identity = { ...item.identity };
        if (item.secureNote) parsed.secureNote = { type: item.secureNote.type || 0 };
        if (item.sshKey) parsed.sshKey = {
          privateKey: item.sshKey.privateKey || '', publicKey: item.sshKey.publicKey || '',
          fingerprint: item.sshKey.fingerprint || ''
        };
        for (const fc of (item.login?.fido2Credentials || [])) {
          parsed.fido2Credentials.push({
            credentialId: fc.credentialId || '', keyType: fc.keyType || '', keyAlgorithm: fc.keyAlgorithm || '',
            keyCurve: fc.keyCurve || '', keyValue: fc.keyValue || '', rpId: fc.rpId || '', rpName: fc.rpName || '',
            userHandle: fc.userHandle || '', userName: fc.userName || '', userDisplayName: fc.userDisplayName || '',
            counter: String(fc.counter || '0'), discoverable: String(fc.discoverable || 'false'), creationDate: fc.creationDate || ''
          });
        }
        for (const cf of (item.fields || [])) parsed.customFields.push({ name: cf.name || '', value: cf.value || '', type: cf.type || 0 });
        for (const ph of (item.passwordHistory || [])) parsed.passwordHistory.push({ password: ph.password || '', lastUsedDate: ph.lastUsedDate || '' });
        items.push(parsed);
      }
    }
    return { folders, items };
  }
  function parse1PUXJSON(json) {
    const items = [], folders = [];
    if (json.items) for (const item of json.items) {
      if (item.trashed === true || item.trashed === 'Y') continue;
      const parsed = convert1PUXItem(item);
      if (parsed) items.push(parsed);
    }
    return { folders, items };
  }
  function convert1PUXItem(item) {
    // 官方平铺结构（item 顶层有 fields/sections/urls 而非 overview/details）
    if (!item.overview && !item.details && (item.fields || item.sections || item.urls)) {
      return convert1PUXFlatItem(item);
    }
    // 旧式 overview/details 结构（对齐前端原有逻辑）
    const overview = item.overview || {};
    const details = item.details || {};
    const parsed = { name: overview.title || overview.ainfo || '未命名', type: 1, notes: '', folderId: null, favorite: overview.favorite || false };
    const category = (overview.category || item.category || '').toUpperCase();
    if (category === 'LOGIN' || category === 'PASSWORD' || !category) {
      parsed.type = 1; parsed.login = { username: '', password: '', uris: [], totp: '' };
      if (overview.url) parsed.login.uris.push({ uri: overview.url });
      if (overview.urls) for (const u of overview.urls) if (u.url && u.url !== overview.url) parsed.login.uris.push({ uri: u.url });
      if (details.fields) for (const field of details.fields) {
        const design = field.designation || ''; const val = field.value || '';
        if (!val) continue;
        if (design === 'username') parsed.login.username = val;
        else if (design === 'password') parsed.login.password = val;
        else if (design === 'URL' && !parsed.login.uris.find(u => u.uri === val)) parsed.login.uris.push({ uri: val });
      }
      if (details.notesPlain) parsed.notes = details.notesPlain;
      if (details.sections) for (const section of details.sections) if (section.fields) for (const field of section.fields) {
        if (field.k === 'TOTP' || field.t === 'OTP' || field.n === 'TOTP' || field.n === 'one-time password') if (field.v) parsed.login.totp = field.v;
      }
      if (details.passwordHistory) parsed.passwordHistory = details.passwordHistory.map(ph => ({ password: ph.value || '', lastUsedDate: ph.time ? new Date(ph.time * 1000).toISOString() : '' }));
    } else if (category === 'SECURE_NOTE' || category === 'NOTE') {
      parsed.type = 2; parsed.login = null; if (details.notesPlain) parsed.notes = details.notesPlain;
    } else if (category === 'CREDIT_CARD' || category === 'BANK_ACCOUNT') {
      parsed.type = 3; parsed.login = null; parsed.card = {};
      if (details.sections) for (const section of details.sections) if (section.fields) for (const field of section.fields) {
        const n = (field.n || field.t || '').toLowerCase();
        if (n.includes('cardholder') || n.includes('name')) parsed.card.cardholderName = field.v || '';
        if (n.includes('number') || n.includes('ccnum')) parsed.card.number = field.v || '';
        if (n.includes('expir') || n.includes('exp')) { const exp = (field.v || '').split('/'); parsed.card.expMonth = exp[0] || ''; parsed.card.expYear = exp[1] || ''; }
        if (n.includes('cvv') || n.includes('cvc') || n.includes('security')) parsed.card.code = field.v || '';
        if (n.includes('type') || n.includes('brand')) parsed.card.brand = field.v || '';
      }
      if (details.notesPlain) parsed.notes = details.notesPlain;
    } else if (category === 'IDENTITY') {
      parsed.type = 4; parsed.login = null; parsed.identity = {};
      if (details.sections) for (const section of details.sections) if (section.fields) for (const field of section.fields) {
        const n = (field.n || field.t || '').toLowerCase(); const v = field.v || '';
        if (n.includes('first')) parsed.identity.firstName = (parsed.identity.firstName || '') + ' ' + v;
        if (n.includes('last')) parsed.identity.lastName = v;
        if (n.includes('email')) parsed.identity.email = v;
        if (n.includes('phone')) parsed.identity.phone = v;
        if (n.includes('address')) parsed.identity.address1 = v;
        if (n.includes('city')) parsed.identity.city = v;
        if (n.includes('state')) parsed.identity.state = v;
        if (n.includes('zip') || n.includes('postal')) parsed.identity.postalCode = v;
        if (n.includes('country')) parsed.identity.country = v;
      }
    } else {
      parsed.type = 1; parsed.login = { username: '', password: '', uris: [], totp: '' };
      if (details.notesPlain) parsed.notes = details.notesPlain;
    }
    parsed.customFields = [];
    if (details.sections) for (const section of details.sections) if (section.fields) for (const field of section.fields) {
      const n = field.n || field.t || field.k || ''; const v = field.v || field.t || '';
      if (n && v && n !== 'notesPlain' && n !== 'password' && n !== 'username') parsed.customFields.push({ name: n, value: String(v), type: 0 });
    }
    if (overview.tags && overview.tags.length) parsed.customFields.push({ name: '_TAGS', value: overview.tags.join(', '), type: 0 });
    if (item.created_at || overview.created) parsed.creationDate = item.created_at || overview.created || '';
    if (item.updated_at || overview.updated) parsed.revisionDate = item.updated_at || overview.updated || '';
    return parsed;
  }

  // 官方平铺结构解析器（item 顶层 fields/sections/urls，1Password 6+ 标准导出格式）
  function convert1PUXFlatItem(item) {
    const category = (item.category || '').toUpperCase();
    const parsed = { name: item.name || item.title || '未命名', type: 1, notes: '', folderId: item.folderUuid || null, favorite: item.favorite || false };
    const fields = item.fields || [];
    const sections = item.sections || [];
    const uris = []; if (item.urls) for (const u of item.urls) if (u.url) uris.push({ uri: u.url });

    if (category === 'LOGIN' || category === 'PASSWORD' || !category) {
      parsed.type = 1; parsed.login = { username: '', password: '', uris: uris, totp: '' };
      for (const f of fields) {
        if (f.designation === 'username' && f.value) parsed.login.username = f.value;
        else if (f.designation === 'password' && f.value) parsed.login.password = f.value;
      }
      for (const s of sections) if (s.fields) for (const f of s.fields) {
        if (f.k === 'TOTP' && f.v) parsed.login.totp = f.v;
      }
    } else if (category === 'SECURE_NOTE' || category === 'NOTE') {
      parsed.type = 2; parsed.login = null;
    } else if (category === 'CREDIT_CARD' || category === 'BANK_ACCOUNT') {
      parsed.type = 3; parsed.login = null; parsed.card = {};
      for (const s of sections) if (s.fields) for (const f of s.fields) {
        const n = ((f.name || f.n || f.t || '').toLowerCase()); const v = f.value || f.v || '';
        if (n.includes('cardholder') || n.includes('name')) parsed.card.cardholderName = v;
        if (n.includes('number') || n.includes('ccnum')) parsed.card.number = v;
        if (n.includes('expir') || n.includes('exp')) { const exp = v.split('/'); parsed.card.expMonth = exp[0] || ''; parsed.card.expYear = exp[1] || ''; }
        if (n.includes('cvv') || n.includes('cvc') || n.includes('security')) parsed.card.code = v;
        if (n.includes('type') || n.includes('brand')) parsed.card.brand = v;
      }
    } else if (category === 'IDENTITY') {
      parsed.type = 4; parsed.login = null; parsed.identity = {};
      for (const s of sections) if (s.fields) for (const f of s.fields) {
        const n = ((f.name || f.n || f.t || '').toLowerCase()); const v = f.value || f.v || '';
        if (n.includes('first')) parsed.identity.firstName = (parsed.identity.firstName || '') + ' ' + v;
        if (n.includes('last')) parsed.identity.lastName = v;
        if (n.includes('email')) parsed.identity.email = v;
        if (n.includes('phone')) parsed.identity.phone = v;
        if (n.includes('address')) parsed.identity.address1 = v;
        if (n.includes('city')) parsed.identity.city = v;
        if (n.includes('state')) parsed.identity.state = v;
        if (n.includes('zip') || n.includes('postal')) parsed.identity.postalCode = v;
        if (n.includes('country')) parsed.identity.country = v;
      }
    } else {
      parsed.type = 1; parsed.login = { username: '', password: '', uris: uris, totp: '' };
    }
    // 备注
    for (const s of sections) if (s.fields) for (const f of s.fields) {
      if (!f.value && !f.v) continue;
      const n = ((f.name || f.n || '').toLowerCase());
      if (n === 'notesplain') parsed.notes = f.value || f.v || '';
    }
    // 自定义字段
    parsed.customFields = [];
    for (const s of sections) if (s.fields) for (const f of s.fields) {
      const n = f.name || f.n || f.t || f.k || ''; const v = f.value || f.v || '';
      if (n && v && n !== 'notesPlain' && n !== 'password' && n !== 'username') parsed.customFields.push({ name: n, value: String(v), type: 0 });
    }
    if (item.tags && item.tags.length) parsed.customFields.push({ name: '_TAGS', value: item.tags.join(', '), type: 0 });
    if (item.createdAt) parsed.creationDate = item.createdAt;
    if (item.updatedAt) parsed.revisionDate = item.updatedAt;
    return parsed;
  }

  // ----- CSV parser -----
  function parseCSV(text, fileName) {
    const items = [], folders = [];
    const firstLine = text.split('\n')[0] || '';
    const delimiter = firstLine.includes('\t') ? '\t' : (firstLine.split(',').length > firstLine.split(';').length ? ',' : ';');
    const rows = parseCSVText(text, delimiter);
    if (rows.length < 2) return { folders, items };
    const headers = rows[0];
    const headerMap = {};
    headers.forEach((h, i) => { headerMap[h.trim().toLowerCase()] = i; });
    const format = detectCSVFormat(headerMap, fileName);
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (row.length === 0 || (row.length === 1 && !row[0])) continue;
      const item = format.parseRow(row, headerMap, i);
      if (item && item.name) items.push(item);
    }
    return { folders, items };
  }
  function parseCSVText(text, delimiter) {
    const rows = [];
    let row = [], field = '', inQuotes = false, i = 0;
    while (i < text.length) {
      const ch = text[i];
      if (inQuotes) {
        if (ch === '"') { if (i + 1 < text.length && text[i + 1] === '"') { field += '"'; i += 2; continue; } inQuotes = false; i++; continue; }
        field += ch; i++; continue;
      }
      if (ch === '"') { inQuotes = true; i++; continue; }
      if (ch === delimiter) { row.push(field.trim()); field = ''; i++; continue; }
      if (ch === '\r') { i++; continue; }
      if (ch === '\n') { row.push(field.trim()); field = ''; if (row.length > 1 || (row.length === 1 && row[0])) rows.push(row); row = []; i++; continue; }
      field += ch; i++;
    }
    if (field || row.length) { row.push(field.trim()); if (row.length > 1 || (row.length === 1 && row[0])) rows.push(row); }
    return rows;
  }
  function detectCSVFormat(headerMap, fileName) {
    if (headerMap['name'] !== undefined && headerMap['url'] !== undefined && headerMap['password'] !== undefined) {
      return { name: 'Chrome', parseRow: (row, hm) => ({
        name: row[hm['name']] || row[hm['title']] || '', type: 1,
        login: { username: row[hm['username']] || row[hm['user']] || row[hm['login']] || '', password: row[hm['password']] || '', uris: [{ uri: row[hm['url']] || row[hm['website']] || '' }], totp: '' },
        notes: row[hm['note']] || row[hm['notes']] || '', folderId: row[hm['folder']] || row[hm['category']] || null
      }) };
    }
    if (headerMap['title'] !== undefined && (headerMap['url'] !== undefined || headerMap['website'] !== undefined)) {
      return { name: '1Password', parseRow: (row, hm) => ({
        name: row[hm['title']] || '', type: 1,
        login: { username: row[hm['username']] || row[hm['user']] || '', password: row[hm['password']] || '', uris: [{ uri: row[hm['url']] || row[hm['website']] || row[hm['login url']] || '' }], totp: row[hm['otpauth']] || row[hm['totp']] || '' },
        notes: row[hm['notes']] || row[hm['note']] || '', folderId: null
      }) };
    }
    if (headerMap['url'] !== undefined && headerMap['username'] !== undefined && headerMap['extra'] !== undefined) {
      return { name: 'LastPass', parseRow: (row, hm) => ({
        name: row[hm['name']] || row[hm['title']] || row[hm['url']] || '', type: 1,
        login: { username: row[hm['username']] || '', password: row[hm['password']] || '', uris: [{ uri: row[hm['url']] || '' }], totp: row[hm['totp']] || '' },
        notes: row[hm['extra']] || row[hm['notes']] || '', folderId: row[hm['grouping']] || row[hm['group']] || row[hm['folder']] || null
      }) };
    }
    if (headerMap['hostname'] !== undefined || headerMap['httprealm'] !== undefined) {
      return { name: 'Firefox', parseRow: (row, hm) => {
        const host = row[hm['hostname']] || row[hm['url']] || '';
        const realm = row[hm['httprealm']] || row[hm['realm']] || '';
        return { name: realm ? `${host} (${realm})` : host || '未命名', type: 1,
          login: { username: row[hm['username']] || row[hm['user']] || '', password: row[hm['password']] || '', uris: [{ uri: host.startsWith('http') ? host : 'https://' + host }], totp: '' },
          notes: '', folderId: null };
      } };
    }
    if (headerMap['login_username'] !== undefined && headerMap['login_password'] !== undefined) {
      return { name: 'Bitwarden', parseRow: (row, hm) => ({
        name: row[hm['name']] || row[hm['title']] || '', type: (row[hm['type']] || '').toLowerCase() === 'note' ? 2 : 1,
        login: { username: row[hm['login_username']] || '', password: row[hm['login_password']] || '', uris: [{ uri: row[hm['login_uri']] || row[hm['login_url']] || '' }], totp: row[hm['login_totp']] || '' },
        notes: row[hm['notes']] || row[hm['note']] || '', folderId: row[hm['folder']] || null,
        favorite: (row[hm['favorite']] || row[hm['fav']] || '') === '1' || (row[hm['favorite']] || '').toLowerCase() === 'true'
      }) };
    }
    if (headerMap['account'] !== undefined || headerMap['title'] !== undefined || headerMap['website'] !== undefined) {
      return { name: 'Generic', parseRow: (row, hm) => ({
        name: row[hm['account']] || row[hm['title']] || row[hm['name']] || '未命名', type: 1,
        login: { username: row[hm['login name']] || row[hm['username']] || row[hm['login']] || row[hm['user']] || '', password: row[hm['password']] || '', uris: [{ uri: row[hm['web site']] || row[hm['website']] || row[hm['url']] || '' }], totp: '' },
        notes: row[hm['comments']] || row[hm['notes']] || row[hm['note']] || '', folderId: null
      }) };
    }
    return { name: 'Auto-Detect', parseRow: (row, hm) => {
      const keys = Object.keys(hm);
      const pwCol = keys.find(k => /password|passwd|pwd/i.test(k));
      const userCol = keys.find(k => /user|username|login|email/i.test(k));
      const urlCol = keys.find(k => /url|website|site|link/i.test(k));
      const nameCol = keys.find(k => /name|title|account|site/i.test(k));
      const notesCol = keys.find(k => /notes|note|comment|desc/i.test(k));
      return {
        name: nameCol ? row[hm[nameCol]] : (urlCol ? row[hm[urlCol]] : '未命名'), type: 1,
        login: { username: userCol ? row[hm[userCol]] : '', password: pwCol ? row[hm[pwCol]] : '', uris: [{ uri: urlCol ? row[hm[urlCol]] : '' }], totp: '' },
        notes: notesCol ? row[hm[notesCol]] : '', folderId: null
      };
    } };
  }

  // ----- 1PUX / ZIP readers -----
  async function parse1PUX(file) {
    const JSZip = global.JSZip || await import('vendor/jszip.min.js');
    const zip = await (JSZip.default || JSZip).loadAsync(file);
    const items = [], folders = [];
    const dataFiles = Object.keys(zip.files).filter(name => name.match(/\/data\/[^/]+\.(json|1pif)$/) && !name.includes('__MACOSX'));
    for (const dataFile of dataFiles) {
      try {
        const content = await zip.files[dataFile].async('string');
        const data = JSON.parse(content);
        if (data.items) for (const item of data.items) {
          if (item.trashed === true || item.trashed === 'Y') continue;
          const parsed = convert1PUXItem(item);
          if (parsed) items.push(parsed);
        }
      } catch (e) { console.warn('Failed to parse 1PUX file:', dataFile, e); }
    }
    return { folders, items };
  }
  async function readZipFile(file) {
    const JSZip = global.JSZip || await import('vendor/jszip.min.js');
    const zip = await (JSZip.default || JSZip).loadAsync(file);
    const jsonFile = Object.keys(zip.files).find(name => name.endsWith('.json'));
    if (!jsonFile) throw new Error('ZIP 文件中未找到 JSON 数据');
    const content = await zip.files[jsonFile].async('string');
    return JSON.parse(content);
  }
  async function readZipJsonData(file) {
    const JSZip = global.JSZip || await import('vendor/jszip.min.js');
    const zip = await (JSZip.default || JSZip).loadAsync(file);
    const jsonFile = Object.keys(zip.files).find(n => n.endsWith('data.json') || n.endsWith('.json'));
    if (!jsonFile) return null;
    return await zip.file(jsonFile).async('string');
  }

  // ----- Bitwarden 加密 JSON 解密 -----
  const APP_BUILD = '20260706f';
  async function decryptBitwardenEncryptedJson(jsonData, password) {
    if (!jsonData.encrypted || !jsonData.passwordProtected || !jsonData.salt || !jsonData.data) {
      throw new Error('不是有效的 Bitwarden 加密导出格式');
    }
    let dataEncType = '?';
    try { dataEncType = parseCipherString(jsonData.data).encType; } catch (_) {}
    const enc = new TextEncoder();
    const kdfType = jsonData.kdfType || 0;
    const kdfIterations = jsonData.kdfIterations || 100000;
    const kdfMemory = jsonData.kdfMemory || 64;
    const kdfParallelism = jsonData.kdfParallelism || 4;
    const saltCandidates = [base64ToArrayBuffer(jsonData.salt), enc.encode(jsonData.salt)];
    const argonMemoryCandidates = [kdfMemory * 1024, kdfMemory];
    let lastErr = null, fatalErr = null;
    for (const saltBytes of saltCandidates) {
      try {
        let masterKey;
        if (kdfType === 1) {
          if (typeof global.hashwasm === 'undefined') throw new Error('当前环境未加载 hash-wasm，无法解密 Argon2 加密导出，请检查网络后重试');
          let derived = null, derr = null, derrMsg = '';
          for (const mem of argonMemoryCandidates) {
            try { derived = await global.hashwasm.argon2id({ password, salt: new Uint8Array(saltBytes), parallelism: kdfParallelism, iterations: kdfIterations, memorySize: mem, hashLength: 32, outputType: 'binary' }); derr = null; break; }
            catch (e) { derr = e; derrMsg = e && e.message ? e.message : String(e); }
          }
          if (derr && !derived) throw new Error('Argon2 派生失败：' + derrMsg);
          masterKey = derived;
        } else if (kdfType === 0) {
          const passwordKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
          masterKey = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: kdfIterations, hash: 'SHA-256' }, passwordKey, 256);
        } else {
          throw new Error('不支持的 KDF 类型: ' + kdfType + '（当前仅支持 PBKDF2 与 Argon2id）');
        }
        const masterKeyBytes = new Uint8Array(masterKey);
        const encKey = await hkdfExpand(masterKeyBytes, 32, 'enc');
        const macKey = await hkdfExpand(masterKeyBytes, 32, 'mac');
        if (jsonData.encKeyValidation_DO_NOT_EDIT) await decryptCipherString(jsonData.encKeyValidation_DO_NOT_EDIT, encKey, macKey);
        else await decryptCipherString(jsonData.data, encKey, macKey);
        const dataBuffer = await decryptCipherString(jsonData.data, encKey, macKey);
        return JSON.parse(new TextDecoder().decode(dataBuffer));
      } catch (e) {
        if (e && e.message && (e.message.indexOf('不支持') === 0 || e.message.indexOf('未加载') === 0)) { lastErr = e; fatalErr = e; break; }
        lastErr = e;
      }
    }
    if (fatalErr) throw fatalErr;
    const diag = ['build=' + APP_BUILD, 'kdf=' + kdfType, 'iter=' + kdfIterations, 'mem=' + kdfMemory, 'encType=' + dataEncType, 'hw=' + (typeof global.hashwasm !== 'undefined' ? 'Y' : 'N'), 'err=' + (lastErr ? lastErr.message : '?')].join(' ');
    throw new Error('密码错误或数据已损坏（MAC 验证失败）\n[诊断] ' + diag);
  }
  async function hkdfExpand(prk, length, info) {
    const hashLen = 32;
    const n = Math.ceil(length / hashLen);
    const result = new Uint8Array(n * hashLen);
    let t = new Uint8Array(0);
    const infoBytes = info ? new TextEncoder().encode(info) : new Uint8Array(0);
    for (let i = 1; i <= n; i++) {
      const input = new Uint8Array(t.length + infoBytes.length + 1);
      input.set(t, 0);
      if (infoBytes.length) input.set(infoBytes, t.length);
      input[input.length - 1] = i;
      const key = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const sig = await crypto.subtle.sign('HMAC', key, input);
      t = new Uint8Array(sig);
      result.set(t, (i - 1) * hashLen);
    }
    return result.slice(0, length);
  }
  function parseCipherString(cipherStr) {
    const dotIdx = cipherStr.indexOf('.');
    if (dotIdx === -1) throw new Error('无效的密文格式');
    const encType = parseInt(cipherStr.substring(0, dotIdx), 10);
    const parts = cipherStr.substring(dotIdx + 1).split('|');
    if (parts.length !== 3 && parts.length !== 2) throw new Error('无效的密文格式');
    return { encType, iv: base64ToArrayBuffer(parts[0]), ct: base64ToArrayBuffer(parts[1]), ivB64: parts[0], ctB64: parts[1], mac: parts.length === 3 ? parts[2] : '' };
  }
  function base64ToArrayBuffer(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  async function decryptCipherString(cipherStr, encKey, macKey) {
    const { encType, iv, ct, mac } = parseCipherString(cipherStr);
    let keyLen, needMac;
    if (encType === 2) { keyLen = 32; needMac = true; }
    else if (encType === 1) { keyLen = 16; needMac = true; }
    else if (encType === 0) { keyLen = 32; needMac = false; }
    else throw new Error('不支持的加密类型: ' + encType);
    if (needMac) {
      const macData = new Uint8Array(iv.byteLength + ct.byteLength);
      macData.set(new Uint8Array(iv), 0);
      macData.set(new Uint8Array(ct), iv.byteLength);
      const hmacKey = await crypto.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const computedSig = await crypto.subtle.sign('HMAC', hmacKey, macData);
      const computedMac = arrayBufferToBase64(computedSig);
      if (!constantTimeEqual(computedMac, mac)) throw new Error('密码错误或数据已损坏（MAC 验证失败）');
    }
    const aesKeyBytes = encKey.slice(0, keyLen);
    const aesKey = await crypto.subtle.importKey('raw', aesKeyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
    return await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, aesKey, ct);
  }
  function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return result === 0;
  }
  function isBitwardenEncryptedJson(json) {
    return !!(json && json.encrypted && json.passwordProtected && json.salt && json.data);
  }
  async function deriveMasterKeyWeb(password, saltBytes, kdfType, iterations, memory, parallelism) {
    if (kdfType === 1) {
      if (typeof global.hashwasm === 'undefined') throw new Error('当前环境未加载 hash-wasm，无法使用 Argon2 加密，请检查网络后重试');
      const derived = await global.hashwasm.argon2id({ password, salt: new Uint8Array(saltBytes), parallelism, iterations, memorySize: memory * 1024, hashLength: 32, outputType: 'binary' });
      return new Uint8Array(derived);
    }
    const pwKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' }, pwKey, 256);
    return new Uint8Array(bits);
  }
  async function encryptCipherString(plaintextBytes, encKey, macKey, encType) {
    encType = (encType === undefined) ? 2 : encType;
    let keyLen, needMac;
    if (encType === 2) { keyLen = 32; needMac = true; }
    else if (encType === 1) { keyLen = 16; needMac = true; }
    else if (encType === 0) { keyLen = 32; needMac = false; }
    else throw new Error('不支持的加密类型: ' + encType);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await crypto.subtle.importKey('raw', encKey.slice(0, keyLen), { name: 'AES-CBC' }, false, ['encrypt']);
    const ct = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, aesKey, plaintextBytes);
    let macB64 = '';
    if (needMac) {
      const macData = new Uint8Array(iv.byteLength + ct.byteLength);
      macData.set(new Uint8Array(iv), 0);
      macData.set(new Uint8Array(ct), iv.byteLength);
      const hk = await crypto.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const sig = await crypto.subtle.sign('HMAC', hk, macData);
      macB64 = arrayBufferToBase64(sig);
    }
    return encType + '.' + arrayBufferToBase64(iv) + '|' + arrayBufferToBase64(ct) + (needMac ? '|' + macB64 : '');
  }
  async function encryptBitwardenExport(plaintextObj, password, opts) {
    opts = opts || {};
    const kdfType = opts.kdfType || 0;
    const kdfIterations = opts.kdfIterations || 600000;
    const kdfMemory = opts.kdfMemory || 64;
    const kdfParallelism = opts.kdfParallelism || 4;
    const saltMode = opts.saltMode || 'utf8';
    const validationPlaintext = opts.validationPlaintext || 'Bitwarden';
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const saltField = arrayBufferToBase64(saltBytes);
    const kdfSalt = (saltMode === 'utf8') ? new TextEncoder().encode(saltField) : base64ToArrayBuffer(saltField);
    const master = await deriveMasterKeyWeb(password, kdfSalt, kdfType, kdfIterations, kdfMemory, kdfParallelism);
    const encKey = await hkdfExpand(master, 32, 'enc');
    const macKey = await hkdfExpand(master, 32, 'mac');
    const dataPlain = new TextEncoder().encode(JSON.stringify(plaintextObj));
    const dataCs = await encryptCipherString(dataPlain, encKey, macKey, 2);
    const valCs = await encryptCipherString(new TextEncoder().encode(validationPlaintext), encKey, macKey, 2);
    const envelope = { encrypted: true, passwordProtected: true, salt: saltField, kdfType, kdfIterations, encKeyValidation_DO_NOT_EDIT: valCs, data: dataCs };
    if (kdfType === 1) { envelope.kdfMemory = kdfMemory; envelope.kdfParallelism = kdfParallelism; }
    else { envelope.kdfMemory = null; envelope.kdfParallelism = null; }
    return envelope;
  }

  function sanitizePath(path) { return path.replace(/[\/\\]/g, '_'); }

  // ===================== 统一入口 run() =====================
  // opts: {
  //   file: File,                         // 用户选择的文件
  //   direction: 'to-kdbx' | 'to-bitwarden',
  //   dbPassword: string,                 // KDBX 密码 / KDBX 解密密码
  //   dbName: string,                     // 数据库名称（to-kdbx）
  //   separatePasskey: boolean,           // 分离 Passkey 文件（to-kdbx）
  //   fetchFavicon: boolean,              // 获取网站图标（to-kdbx）
  //   encryptExport: boolean,             // 加密导出（to-bitwarden）
  //   exportPassword: string,             // 加密导出密码
  //   saltMode: 'utf8' | 'base64',
  //   onProgress: (text) => void,         // 进度文本回调（UI 驱动可视化）
  //   onRequestPassword: () => Promise<string>  // 加密 JSON 需要密码时回调（返回用户密码，取消则 reject）
  // }
  // 返回结果对象：
  // {
  //   downloads: [{ name, mime, data: Blob }],
  //   summary: { title, details, stats: [{num,label}], typeCounts: {} },
  //   toKdbx: boolean, fileName: string, kdbxInfo: string
  // }

  async function promptAndDecrypt(jsonData, onRequestPassword) {
    let retries = 0;
    const maxRetries = 3;
    while (retries < maxRetries) {
      const password = await onRequestPassword();
      try {
        return await decryptBitwardenEncryptedJson(jsonData, password);
      } catch (err) {
        if (err.message === '用户取消') throw err;
        retries++;
        if (retries >= maxRetries) throw new Error('密码错误次数过多（' + maxRetries + ' 次），请确认密码后重新导入\n' + err.message);
        throw err; // 让 UI 显示错误并可重试
      }
    }
  }

  async function convertToKdbx(opts, E) {
    const { file, dbPassword, dbName, separatePasskey, fetchFavicon, onProgress } = opts;
    const report = (t) => onProgress && onProgress(t);
    report('正在读取文件...');
    const ext = file.name.split('.').pop().toLowerCase();
    let vault;
    if (ext === 'csv') {
      const text = await file.text();
      vault = parseCSV(text, file.name);
      report(`检测到 CSV 格式 · 找到 ${vault.items.length} 个条目`);
    } else if (ext === '1pux') {
      vault = await parse1PUX(file);
      report(`检测到 1Password 1PUX · 找到 ${vault.items.length} 个条目`);
    } else if (ext === 'zip') {
      const jsonData = await readZipFile(file);
      vault = parseBitwardenJson(jsonData);
      report(`检测到 Bitwarden ZIP · 找到 ${vault.items.length} 个条目`);
    } else {
      const text = await file.text();
      const jsonData = JSON.parse(text);
      if (isBitwardenEncryptedJson(jsonData)) {
        const encResult = await promptAndDecrypt(jsonData, opts.onRequestPassword);
        vault = parseBitwardenJson(encResult);
        report(`检测到 Bitwarden 加密 JSON · 找到 ${vault.items.length} 个条目`);
      } else if (jsonData.accounts && Array.isArray(jsonData.accounts)) {
        vault = parse1PUXJSON(jsonData);
        report(`检测到 1Password 1PUX JSON · 找到 ${vault.items.length} 个条目`);
      } else {
        vault = parseBitwardenJson(jsonData);
        report(`检测到 Bitwarden JSON · 找到 ${vault.items.length} 个条目`);
      }
    }

    report(`找到 ${vault.items.length} 个条目，正在生成 KDBX...`);

    const credentials = new Credentials(ProtectedValue.fromString(dbPassword));
    const db = Kdbx.create(credentials, dbName.trim() || 'My Vault');
    db.upgrade();
    db.setKdf(argon2Ready ? Consts.KdfId.Argon2d : Consts.KdfId.Aes);

    const folderGroupMap = new Map();
    folderGroupMap.set(null, db.getDefaultGroup());
    for (const folder of vault.folders) {
      const group = db.createGroup(db.getDefaultGroup(), sanitizePath(folder.name));
      folderGroupMap.set(folder.id, group);
    }
    const csvFolderNames = new Set();
    for (const item of vault.items) {
      if (item.folderId && typeof item.folderId === 'string' && !folderGroupMap.has(item.folderId)) csvFolderNames.add(item.folderId);
    }
    for (const fname of csvFolderNames) {
      const group = db.createGroup(db.getDefaultGroup(), sanitizePath(fname));
      folderGroupMap.set(fname, group);
      vault.folders.push({ id: fname, name: fname });
    }

    let entryCount = 0;
    const passkeys = [];
    const entryUrlMap = [];
    for (const item of vault.items) {
      if (item.deleted) continue;
      const parentGroup = folderGroupMap.get(item.folderId) || db.getDefaultGroup();
      const entry = db.createEntry(parentGroup);
      entry.fields.set('Title', item.name || '(无标题)');
      if (item.login?.username) entry.fields.set('UserName', item.login.username);
      if (item.login?.password) entry.fields.set('Password', ProtectedValue.fromString(item.login.password));
      if (item.login?.uris?.length) {
        const isAndroidUri = uri => uri && (uri.startsWith('androidapp://') || uri.startsWith('android://'));
        const webUri = item.login.uris.find(u => u.uri && (u.uri.startsWith('http://') || u.uri.startsWith('https://')))
          || item.login.uris.find(u => u.uri && !isAndroidUri(u.uri));
        if (webUri) {
          entry.fields.set('URL', webUri.uri);
          if (webUri.uri.startsWith('http://') || webUri.uri.startsWith('https://')) entryUrlMap.push({ entry, url: webUri.uri });
        }
      }
      const notes = buildNotes(item);
      if (notes) entry.fields.set('Notes', notes);
      const customFields = buildCustomFields(item);
      for (const [key, value] of Object.entries(customFields)) {
        if (key === 'Password') entry.fields.set(key, ProtectedValue.fromString(String(value)));
        else entry.fields.set(key, String(value));
      }
      const tags = buildTags(item);
      if (tags.length) entry.fields.set('_TAGS', tags.join(' '));
      if (item.fido2Credentials?.length) for (const fc of item.fido2Credentials) passkeys.push({ item, fc });
      entryCount++;
      if (entryCount % 25 === 0) report(`已处理 ${entryCount}/${vault.items.length} 个条目...`);
    }

    let faviconCount = 0;
    if (fetchFavicon && entryUrlMap.length > 0) {
      report('正在获取网站图标...');
      faviconCount = await fetchAndSetFavicons(db, entryUrlMap, (done, total) => report(`获取图标中 ${done}/${total}...`));
    }

    report('正在加密并生成 KDBX 文件...');
    const generatedData = await db.save();
    const _dv = new DataView(generatedData);
    const _ver = _dv.getUint32(8, true);
    const _kdbxMajor = (_ver >> 16) & 0xFFFF;
    const _kdbxMinor = _ver & 0xFFFF;
    const _kdfName = argon2Ready ? 'Argon2d' : 'AES-KDF';
    const kdbxInfo = `KDBX ${_kdbxMajor}.${_kdbxMinor} · ${_kdfName} · AES-256`;

    const downloads = [{ name: file.name.replace(/\.(json|zip|csv|1pux)$/i, '') + '.kdbx', mime: 'application/octet-stream', data: new Blob([generatedData], { type: 'application/octet-stream' }) }];

    let passkeyInfo = '';
    if (passkeys.length > 0 && separatePasskey) {
      const passkeyFiles = [];
      for (const pk of passkeys) {
        const passkeyJson = buildPasskeyFile(pk.fc, pk.item);
        const safeName = (pk.item.name || 'passkey').replace(/[<>:"/\\|?*]/g, '_').substring(0, 60);
        const fileName = passkeys.length > 1 ? `${safeName}_${passkeyFiles.length + 1}.passkey` : `${safeName}.passkey`;
        passkeyFiles.push({ name: fileName, json: passkeyJson });
      }
      if (passkeyFiles.length === 1) {
        downloads.push({ name: passkeyFiles[0].name, mime: 'application/json', data: new Blob([JSON.stringify(passkeyFiles[0].json, null, 2)], { type: 'application/json' }) });
      } else {
        downloads.push({ name: file.name.replace(/\.(json|zip|csv|1pux)$/i, '') + '_passkeys.zip', mime: 'application/zip', data: makePasskeyZip(passkeyFiles, file.name) });
      }
      passkeyInfo = ` · 包含 ${passkeys.length} 个 Passkey`;
    }

    const faviconInfo = faviconCount > 0 ? ` · ${faviconCount} 个网站图标` : '';
    const typeCount = {};
    for (const item of vault.items) { const tn = TYPE_NAMES[item.type] || '其他'; typeCount[tn] = (typeCount[tn] || 0) + 1; }
    return {
      toKdbx: true,
      fileName: downloads[0].name,
      kdbxInfo,
      downloads,
      summary: {
        title: '转换完成',
        details: `成功转换 ${entryCount} 个条目到 ${vault.folders.length} 个文件夹${passkeyInfo}${faviconInfo}\n📦 ${kdbxInfo}`,
        stats: [
          { num: entryCount, label: '条目' },
          { num: vault.folders.length, label: '文件夹' },
          { num: (passkeys.length + faviconCount) || 0, label: faviconCount ? '图标' : (passkeys.length ? 'Passkey' : '—') }
        ],
        typeCounts: typeCount
      }
    };
  }

  async function convertToBitwarden(opts, E) {
    const { file, dbPassword, encryptExport, exportPassword, saltMode, onProgress } = opts;
    const report = (t) => onProgress && onProgress(t);
    const ext = file.name.split('.').pop().toLowerCase();
    if (ext === 'kdbx') {
      return await convertKdbxToBitwarden(opts, E);
    }
    report('正在读取文件...');
    let vault;
    if (ext === 'csv') {
      const text = await file.text();
      vault = parseCSV(text, file.name);
      report(`检测到 CSV 格式 · 找到 ${vault.items.length} 个条目`);
    } else if (ext === '1pux') {
      vault = await parse1PUX(file);
      report(`检测到 1Password 1PUX · 找到 ${vault.items.length} 个条目`);
    } else if (ext === 'zip') {
      const jsonData = await readZipFile(file);
      vault = parseBitwardenJson(jsonData);
      report(`检测到 Bitwarden ZIP · 找到 ${vault.items.length} 个条目`);
    } else {
      const text = await file.text();
      const jsonData = JSON.parse(text);
      if (isBitwardenEncryptedJson(jsonData)) {
        const encResult = await promptAndDecrypt(jsonData, opts.onRequestPassword);
        vault = parseBitwardenJson(encResult);
        report(`检测到 Bitwarden 加密 JSON · 找到 ${vault.items.length} 个条目`);
      } else if (jsonData.accounts && Array.isArray(jsonData.accounts)) {
        vault = parse1PUXJSON(jsonData);
        report(`检测到 1Password 1PUX JSON · 找到 ${vault.items.length} 个条目`);
      } else {
        vault = parseBitwardenJson(jsonData);
        report(`检测到 Bitwarden JSON · 找到 ${vault.items.length} 个条目`);
      }
    }
    return await convertVaultToBitwarden(vault, opts, E);
  }

  async function convertVaultToBitwarden(vault, opts, E) {
    const { onProgress } = opts;
    const report = (t) => onProgress && onProgress(t);
    report(`找到 ${vault.items.length} 个条目，正在生成 Bitwarden JSON...`);
    const bwFolders = (vault.folders || []).map(f => ({ id: f.id, name: f.name }));
    const bwItems = [];
    for (const item of vault.items) {
      if (item.deleted) continue;
      const bwItem = convertVaultItemToBW(item);
      if (bwItem) bwItems.push(bwItem);
    }
    const bwExport = { encrypted: false, folders: bwFolders, items: bwItems };
    const out = await maybeEncryptBW(bwExport, opts);
    const downloads = [{ name: opts.file.name.replace(/\.(json|zip|csv|1pux)$/i, '') + '.json', mime: 'application/json', data: new Blob([out.data], { type: 'application/json' }) }];
    const passkeyCount = bwItems.reduce((n, it) => n + (it.fido2Credentials && it.fido2Credentials.length ? it.fido2Credentials.length : 0), 0);
    const csvData = buildCSVFromBwItems(bwItems, bwFolders);
    downloads.push({ name: opts.file.name.replace(/\.(json|zip|csv|1pux)$/i, '') + '.csv', mime: 'text/csv', data: new Blob(['﻿' + csvData], { type: 'text/csv;charset=utf-8' }), csvNote: passkeyCount > 0 ? `${passkeyCount} 个 Passkey 无法保留在 CSV 中` : null });
    // 1Password 1PUX 导出
    const _1pData = generate1PUXExport(vault.items, vault.folders);
    const _1pBlob = await build1PUXZip(_1pData);
    downloads.push({ name: opts.file.name.replace(/\.(json|zip|csv|1pux)$/i, '') + '.1pux', mime: 'application/zip', data: _1pBlob, _1puxNote: '1Password 官方 .1pux 格式' });
    const typeCount = {};
    for (const item of bwItems) { const tn = TYPE_NAMES[item.type] || '其他'; typeCount[tn] = (typeCount[tn] || 0) + 1; }
    return {
      toKdbx: false,
      fileName: downloads[0].name,
      downloads,
      summary: {
        title: '转换完成',
        details: `成功转换 ${bwItems.length} 个条目到 ${bwFolders.length} 个文件夹` + (out.encrypted ? '（已加密）' : ''),
        stats: [
          { num: bwItems.length, label: '条目' },
          { num: bwFolders.length, label: '文件夹' },
          { num: Object.keys(typeCount).length, label: '类型' }
        ],
        typeCounts: typeCount
      }
    };
  }

  function convertVaultItemToBW(item) {
    if (!item.name && !item.login) return null;
    return {
      id: generateUUID(), organizationId: null, folderId: item.folderId || null, type: item.type || 1,
      reprompt: 0, name: item.name || '(无标题)', notes: item.notes || null, favorite: item.favorite || false,
      login: item.login ? { username: item.login.username || null, password: item.login.password || null, totp: item.login.totp || null, uris: (item.login.uris || []).map(u => ({ uri: u.uri || u, match: null })) } : null,
      card: item.card || null, identity: item.identity || null, secureNote: item.type === 2 ? { type: 0 } : null,
      collectionIds: [],
      fields: (item.customFields || []).map(f => ({ name: f.name, value: String(f.value || ''), type: f.type || 0 })),
      passwordHistory: (item.passwordHistory || []).map(ph => ({ password: ph.password || '', lastUsedDate: ph.lastUsedDate || '' })),
      fido2Credentials: (item.fido2Credentials || item.login?.fido2Credentials || []).map(fc => ({
        credentialId: fc.credentialId || '', keyType: fc.keyType || '', keyAlgorithm: fc.keyAlgorithm || '', keyCurve: fc.keyCurve || '',
        keyValue: fc.keyValue || '', rpId: fc.rpId || '', rpName: fc.rpName || '', userHandle: fc.userHandle || '', userName: fc.userName || '',
        userDisplayName: fc.userDisplayName || '', counter: fc.counter || '', discoverable: fc.discoverable || '', creationDate: fc.creationDate || ''
      }))
    };
  }

  async function convertKdbxToBitwarden(opts, E) {
    const { file, dbPassword, onProgress } = opts;
    const report = (t) => onProgress && onProgress(t);
    report('正在加载 KDBX 数据库...');
    const buf = await file.arrayBuffer();
    const credentials = new Credentials(ProtectedValue.fromString(dbPassword));
    const db = await Kdbx.load(buf, credentials);
    report('正在读取分组和条目...');
    const rootGroup = db.getDefaultGroup();
    const allEntries = rootGroup.allEntries();
    const allGroups = rootGroup.allGroups();
    const folderMap = new Map();
    const folders = [];
    let folderIdx = 0;
    function getGroupName(group) {
      if (!group) return '';
      if (typeof group.name === 'string') return group.name;
      if (group.name && typeof group.name.getText === 'function') return group.name.getText();
      return String(group.name || '');
    }
    function buildGroupPath(group, parentPath) {
      if (!group || group === rootGroup) return '';
      const name = getGroupName(group);
      if (!name || name === 'Recycle Bin' || name === '回收站') return '';
      const path = parentPath ? parentPath + '/' + name : name;
      if (!folderMap.has(group.uuid)) { folderMap.set(group.uuid, { id: 'folder_' + (++folderIdx), name: path }); folders.push({ id: 'folder_' + folderIdx, name: path }); }
      return path;
    }
    for (const group of allGroups) {
      if (group === rootGroup) continue;
      const name = getGroupName(group);
      if (!name || name === 'Recycle Bin' || name === '回收站') continue;
      let path = name;
      let parent = group.parentGroup;
      while (parent && parent !== rootGroup) {
        const pn = getGroupName(parent);
        if (pn && pn !== 'Recycle Bin' && pn !== '回收站') path = pn + '/' + path;
        parent = parent.parentGroup;
      }
      if (!folderMap.has(group.uuid)) { folderMap.set(group.uuid, { id: 'folder_' + (++folderIdx), name: path }); folders.push({ id: 'folder_' + folderIdx, name: path }); }
    }
    report(`找到 ${allEntries.length} 个条目，正在生成 Bitwarden JSON...`);
    const bwItems = [];
    let idx = 0;
    for (const entry of allEntries) {
      const item = convertKdbxEntryToBW(entry, folderMap);
      if (item) bwItems.push(item);
      idx++;
      if (idx % 50 === 0) report(`已处理 ${idx}/${allEntries.length} 个条目...`);
    }
    const bwExport = { encrypted: false, folders, items: bwItems };
    const out = await maybeEncryptBW(bwExport, opts);
    const downloads = [{ name: file.name.replace(/\.kdbx$/i, '') + '.json', mime: 'application/json', data: new Blob([out.data], { type: 'application/json' }) }];
    const passkeyCount = bwItems.reduce((n, it) => n + (it.fido2Credentials && it.fido2Credentials.length ? it.fido2Credentials.length : 0), 0);
    const csvData = buildCSVFromBwItems(bwItems, folders);
    downloads.push({ name: file.name.replace(/\.kdbx$/i, '') + '.csv', mime: 'text/csv', data: new Blob(['﻿' + csvData], { type: 'text/csv;charset=utf-8' }), csvNote: passkeyCount > 0 ? `${passkeyCount} 个 Passkey 无法保留在 CSV 中` : null });
    // 1Password 1PUX 导出
    const _1pData2 = generate1PUXExport(bwItems, folders);
    const _1pBlob2 = await build1PUXZip(_1pData2);
    downloads.push({ name: file.name.replace(/\.kdbx$/i, '') + '.1pux', mime: 'application/zip', data: _1pBlob2, _1puxNote: '1Password 官方 .1pux 格式' });
    const typeCount = {};
    for (const item of bwItems) { const tn = TYPE_NAMES[item.type] || '其他'; typeCount[tn] = (typeCount[tn] || 0) + 1; }
    return {
      toKdbx: false, fileName: downloads[0].name, downloads,
      summary: {
        title: '转换完成',
        details: `成功转换 ${bwItems.length} 个条目到 ${folders.length} 个文件夹` + (passkeyCount > 0 ? ` · ${passkeyCount} 个 Passkey 已保留` : '') + (out.encrypted ? '（已加密）' : ''),
        stats: [
          { num: bwItems.length, label: '条目' },
          { num: folders.length, label: '文件夹' },
          { num: Object.keys(typeCount).length, label: '类型' }
        ],
        typeCounts: typeCount
      }
    };
  }

  function convertKdbxEntryToBW(entry, folderMap) {
    const fields = entry.fields;
    const getText = (key) => {
      const v = fields.get(key);
      if (!v) return '';
      if (typeof v === 'string') return v;
      if (typeof v.getText === 'function') return v.getText();
      return String(v);
    };
    const title = getText('Title'), username = getText('UserName'), password = getText('Password'), url = getText('URL'), notes = getText('Notes');
    if (!title && !username && !password && !url && !notes) return null;
    const item = {
      id: generateUUID(), organizationId: null, folderId: null, type: 1, reprompt: 0,
      name: title || '(无标题)', notes: notes || null, favorite: false,
      login: { username: username || null, password: password || null, totp: null, uris: url ? [{ uri: url, match: null }] : [] },
      collectionIds: [], fields: [], passwordHistory: [], fido2Credentials: []
    };
    const group = entry.parentGroup || entry.group;
    if (group && folderMap.has(group.uuid)) item.folderId = folderMap.get(group.uuid).id;
    const bwTypeField = getText('BitwardenType');
    if (bwTypeField && TYPE_NAME_TO_ID[bwTypeField]) item.type = TYPE_NAME_TO_ID[bwTypeField];
    const totp = getText('TOTP Seed') || getText('TOTP') || getText('otp') || getText('otpauth');
    if (totp && item.login) item.login.totp = totp;
    if (item.login) {
      for (let i = 2; i <= 10; i++) { const extraUri = getText(`URI_${i}`); if (extraUri) item.login.uris.push({ uri: extraUri, match: null }); }
      const seenUris = new Set(item.login.uris.map(u => u.uri));
      for (let i = 0; i <= 20; i++) {
        const key = i === 0 ? 'KP2A_URL' : `KP2A_URL_${i + 1}`;
        const val = getText(key);
        if (val && !seenUris.has(val)) { item.login.uris.push({ uri: val, match: null }); seenUris.add(val); }
      }
      for (let i = 0; i <= 10; i++) {
        const key = i === 0 ? 'AndroidApp' : `AndroidApp${i + 1}`;
        const pkg = getText(key);
        if (pkg) {
          const sigKey = i === 0 ? 'AndroidApp Signature' : `AndroidApp Signature${i + 1}`;
          const sig = getText(sigKey);
          if (sig) { const fpHex = sig.replace(/:/g, ''); item.login.uris.push({ uri: `android://${fpHex}@${pkg}`, match: null }); }
          else item.login.uris.push({ uri: `androidapp://${pkg}`, match: null });
        }
      }
    }
    const cardBrand = getText('CardBrand'), cardNumber = getText('CardNumber'), cardExpiry = getText('CardExpiry');
    if (cardBrand || cardNumber || cardExpiry) {
      item.type = 3;
      item.card = { cardholderName: '', brand: cardBrand || '', number: cardNumber || '', expMonth: '', expYear: '', code: '' };
      if (cardExpiry && cardExpiry.includes('/')) { const parts = cardExpiry.split('/'); item.card.expMonth = parts[0] || ''; item.card.expYear = parts[1] || ''; }
      item.login = null;
    }
    const passkeyFields = {};
    for (const [key, value] of fields) if (key.startsWith('KPEX_PASSKEY_')) passkeyFields[key] = typeof value === 'string' ? value : (typeof value.getText === 'function' ? value.getText() : String(value));
    if (Object.keys(passkeyFields).length > 0) {
      const fidoCreds = extractPasskeysFromFields(passkeyFields);
      if (fidoCreds.length > 0) item.fido2Credentials = fidoCreds;
    }
    const skipFields = new Set(['Title', 'UserName', 'Password', 'URL', 'Notes', 'BitwardenType', 'TOTP Seed', 'TOTP', 'otp', 'AndroidApp', 'AndroidApp Signature', 'CardBrand', 'CardNumber', 'CardExpiry', 'CreationDate', 'RevisionDate', 'SSHFingerprint', 'SSHPublicKey', 'SSHPrivateKey', 'IdentityTitle', 'IdentityFirstName', 'IdentityMiddleName', 'IdentityLastName', 'IdentityAddress1', 'IdentityCity', 'IdentityState', 'IdentityPostalCode', 'IdentityCountry', 'IdentityEmail', 'IdentityPhone', 'IdentitySSN', 'IdentityPassport', 'IdentityLicense', '_TAGS']);
    const uriFields = new Set();
    for (let i = 2; i <= 10; i++) uriFields.add(`URI_${i}`);
    for (const [key, value] of fields) {
      if (skipFields.has(key) || uriFields.has(key) || key.startsWith('KPEX_PASSKEY_') || key.startsWith('KP2A_URL')) continue;
      const text = typeof value === 'string' ? value : (typeof value.getText === 'function' ? value.getText() : String(value));
      if (text && key !== '_TAGS') item.fields.push({ name: key, value: text, type: 0 });
    }
    const tags = getText('_TAGS');
    if (tags) item.fields.push({ name: 'Tags', value: tags, type: 0 });
    if (getText('IdentityTitle') || getText('IdentityFirstName') || getText('IdentityLastName') || getText('IdentityEmail')) {
      if (item.type === 1) item.type = 4;
      item.identity = { title: getText('IdentityTitle') || '', firstName: getText('IdentityFirstName') || '', middleName: getText('IdentityMiddleName') || '', lastName: getText('IdentityLastName') || '', address1: getText('IdentityAddress1') || '', address2: '', address3: '', city: getText('IdentityCity') || '', state: getText('IdentityState') || '', postalCode: getText('IdentityPostalCode') || '', country: getText('IdentityCountry') || '', company: '', email: getText('IdentityEmail') || '', phone: getText('IdentityPhone') || '', ssn: getText('IdentitySSN') || '', passportNumber: getText('IdentityPassport') || '', licenseNumber: getText('IdentityLicense') || '' };
      item.login = null;
    }
    if (item.type === 1 && getText('SSHFingerprint')) {
      item.type = 5;
      item.sshKey = { privateKey: getText('SSHPrivateKey') || '', publicKey: getText('SSHPublicKey') || '', fingerprint: getText('SSHFingerprint') || '' };
    }
    if (bwTypeField === 'SecureNote' || (item.type !== 3 && item.type !== 4 && item.type !== 5 && !item.login?.username && !item.login?.password && !item.login?.uris?.length && notes)) {
      item.type = 2; item.secureNote = { type: 0 };
    }
    const creationDate = getText('CreationDate'), revisionDate = getText('RevisionDate');
    if (creationDate) item.creationDate = creationDate;
    if (revisionDate) item.revisionDate = revisionDate;
    return item;
  }

  async function maybeEncryptBW(bwExport, opts) {
    if (opts.encryptExport) {
      const env = await encryptBitwardenExport(bwExport, opts.exportPassword, { saltMode: opts.saltMode || 'utf8' });
      return { data: JSON.stringify(env, null, 2), encrypted: true };
    }
    return { data: JSON.stringify(bwExport, null, 2), encrypted: false };
  }

  function buildCSVFromBwItems(bwItems, folders) {
    const folderMap = {};
    for (const f of folders) folderMap[f.id] = f.name;
    const rows = [];
    const columns = ['Title', 'UserName', 'Password', 'URL', 'Notes', 'TOTP', 'Group', 'Type', 'HasPasskey'];
    for (const item of bwItems) {
      rows.push({
        Title: item.name || '', UserName: item.login?.username || '', Password: item.login?.password || '',
        URL: (item.login?.uris && item.login.uris.length > 0) ? item.login.uris[0].uri : '',
        Notes: item.notes || '', TOTP: item.login?.totp || '',
        Group: folderMap[item.folderId] || '', Type: TYPE_NAMES[item.type] || 'Login',
        HasPasskey: (item.fido2Credentials && item.fido2Credentials.length > 0) ? 'YES' : 'NO'
      });
    }
    const escapeCsv = (val) => { const s = String(val || ''); return (s.includes(',') || s.includes('"') || s.includes('\n')) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const header = columns.map(escapeCsv).join(',');
    const dataLines = rows.map(r => columns.map(c => escapeCsv(r[c])).join(','));
    return header + '\n' + dataLines.join('\n');
  }

  async function fetchAndSetFavicons(db, entryUrlMap, onProgress) {
    const domainMap = new Map();
    for (const { entry, url } of entryUrlMap) {
      try {
        const hostname = new URL(url).hostname;
        if (!hostname) continue;
        if (!domainMap.has(hostname)) domainMap.set(hostname, { entries: [], iconData: null, uuid: null });
        domainMap.get(hostname).entries.push(entry);
      } catch (_) {}
    }
    const domains = Array.from(domainMap.keys());
    if (domains.length === 0) return 0;
    const CONCURRENCY = 8;
    let done = 0, iconCount = 0;
    async function fetchOne(domain) {
      const record = domainMap.get(domain);
      const googleUrls = [`https://www.google.com/s2/favicons?domain=${domain}&sz=64`, `https://www.google.com/s2/favicons?domain=${domain}&sz=32`];
      for (const u of googleUrls) if (await tryFetchIcon(record, u)) break;
      if (!record.iconData) { if (await tryFetchIcon(record, `https://icons.duckduckgo.com/ip3/${domain}.ico`)) { /* ok */ } }
      if (!record.iconData) {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 5000);
          const resp = await fetch(`https://${domain}`, { signal: controller.signal, mode: 'cors', credentials: 'omit' });
          clearTimeout(timeout);
          if (resp.ok) {
            const html = await resp.text();
            for (const iconUrl of extractFaviconLinks(html, domain)) if (await tryFetchIcon(record, iconUrl)) break;
          }
        } catch (_) {}
        if (!record.iconData) {
          const commonUrls = [`https://${domain}/favicon.ico`, `https://${domain}/apple-touch-icon.png`, `https://${domain}/favicon-32x32.png`, `https://${domain}/favicon-16x16.png`];
          for (const u of commonUrls) if (await tryFetchIcon(record, u)) break;
        }
      }
      done++;
      if (onProgress) onProgress(done, domains.length);
    }
    async function tryFetchIcon(record, faviconUrl) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const resp = await fetch(faviconUrl, { signal: controller.signal, mode: 'cors', credentials: 'omit' });
        clearTimeout(timeout);
        if (!resp.ok) return false;
        const blob = await resp.blob();
        if (blob.size === 0 || blob.size > 1024 * 1024) return false;
        record.iconData = await blob.arrayBuffer();
        return true;
      } catch (_) { return false; }
    }
    function extractFaviconLinks(html, domain) {
      const urls = [];
      const linkRegex = /<link\s[^>]*rel=["'](?:shortcut )?(?:icon|apple-touch-icon|mask-icon)["'][^>]*>/gi;
      const matches = html.match(linkRegex) || [];
      for (const tag of matches) {
        const hrefMatch = tag.match(/href=["']([^"']+)["']/i);
        if (hrefMatch) {
          let href = hrefMatch[1];
          if (href.startsWith('//')) href = 'https:' + href;
          else if (href.startsWith('/')) href = 'https://' + domain + href;
          else if (!href.startsWith('http')) continue;
          if (href.endsWith('.svg')) continue;
          urls.push(href);
        }
      }
      return urls;
    }
    for (let i = 0; i < domains.length; i += CONCURRENCY) await Promise.all(domains.slice(i, i + CONCURRENCY).map(fetchOne));
    for (const [, record] of domainMap) {
      if (!record.iconData) continue;
      try {
        const uuid = KdbxUuid.random();
        record.uuid = uuid;
        db.meta.customIcons.set(uuid.id, { data: record.iconData, name: domain, lastModified: new Date() });
        for (const entry of record.entries) entry.customIcon = uuid;
        iconCount++;
      } catch (_) {}
    }
    return iconCount;
  }

  // 多 Passkey 打包为 ZIP（无压缩存储）
  function makePasskeyZip(passkeyFiles, baseName) {
    const encoder = new TextEncoder();
    const fileEntries = [];
    let centralDirOffset = 0;
    for (const pf of passkeyFiles) {
      const content = JSON.stringify(pf.json, null, 2);
      const data = encoder.encode(content);
      const nameBytes = encoder.encode(pf.name);
      const localHeader = new Uint8Array(30 + nameBytes.length);
      const lhView = new DataView(localHeader.buffer);
      lhView.setUint32(0, 0x04034b50, true); lhView.setUint16(4, 20, true); lhView.setUint16(6, 0, true);
      lhView.setUint16(8, 0, true); lhView.setUint16(10, 0, true); lhView.setUint16(12, 0, true);
      lhView.setUint32(14, crc32(data), true); lhView.setUint32(18, data.length, true); lhView.setUint32(22, data.length, true);
      lhView.setUint16(26, nameBytes.length, true); lhView.setUint16(28, 0, true);
      localHeader.set(nameBytes, 30);
      fileEntries.push({ localHeader, data, nameBytes, crc: crc32(data), offset: centralDirOffset });
      centralDirOffset += localHeader.length + data.length;
    }
    const cdParts = [];
    let cdOffset = centralDirOffset;
    for (const fe of fileEntries) {
      const cd = new Uint8Array(46 + fe.nameBytes.length);
      const cdView = new DataView(cd.buffer);
      cdView.setUint32(0, 0x02014b50, true); cdView.setUint16(4, 20, true); cdView.setUint16(6, 20, true);
      cdView.setUint16(8, 0, true); cdView.setUint16(10, 0, true); cdView.setUint16(12, 0, true);
      cdView.setUint32(16, fe.crc, true); cdView.setUint32(20, fe.data.length, true); cdView.setUint32(24, fe.data.length, true);
      cdView.setUint16(28, fe.nameBytes.length, true); cdView.setUint16(30, 0, true); cdView.setUint16(32, 0, true);
      cdView.setUint16(34, 0, true); cdView.setUint16(36, 0, true); cdView.setUint32(38, fe.offset, true);
      cd.set(fe.nameBytes, 46); cdParts.push(cd); cdOffset += cd.length;
    }
    const eocd = new Uint8Array(22);
    const eocdView = new DataView(eocd.buffer);
    eocdView.setUint32(0, 0x06054b50, true); eocdView.setUint16(4, 0, true); eocdView.setUint16(6, 0, true);
    eocdView.setUint16(8, fileEntries.length, true); eocdView.setUint16(10, fileEntries.length, true);
    eocdView.setUint32(12, cdParts.reduce((s, c) => s + c.length, 0), true); eocdView.setUint32(16, centralDirOffset, true); eocdView.setUint16(20, 0, true);
    const parts = [];
    for (const fe of fileEntries) { parts.push(fe.localHeader); parts.push(fe.data); }
    for (const cd of cdParts) parts.push(cd);
    parts.push(eocd);
    const totalLen = parts.reduce((s, p) => s + p.length, 0);
    const zipData = new Uint8Array(totalLen);
    let offset = 0;
    for (const p of parts) { zipData.set(p, offset); offset += p.length; }
    return new Blob([zipData], { type: 'application/zip' });
  }
  function crc32(data) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < data.length; i++) { crc ^= data[i]; for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0); }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  // ========== 1PUX 导出（KDBX / 其他格式 → 1Password 1PUX）==========
  function generate1PUXExport(items, folders) {
    const fuuid = () => generateUUID();
    const now = new Date().toISOString();
    const accountUuid = fuuid();
    const folderMap = new Map();
    const f1p = [];
    for (const f of (folders || [])) { const u = fuuid(); folderMap.set(f.id, u); f1p.push({ uuid: u, name: f.name }); }

    const i1p = [];
    for (const item of items) {
      if (item.deleted) continue;
      const cat = ['', 'LOGIN', 'SECURE_NOTE', 'CREDIT_CARD', 'IDENTITY'][item.type] || 'LOGIN';
      const ituuid = fuuid();
      const urls = [];
      const fields = [];
      const sections = [];

      if (item.type === 1 && item.login) {
        if (item.login.username) fields.push({ id: fuuid(), type: 'T', name: 'username', value: item.login.username, designation: 'username' });
        if (item.login.password) fields.push({ id: fuuid(), type: 'P', name: 'password', value: item.login.password, designation: 'password' });
        if (item.login.uris) for (const u of item.login.uris) if (u.uri) urls.push({ url: u.uri });
        if (item.login.totp) sections.push({ id: fuuid(), name: '', fields: [{ id: fuuid(), type: 'OTP', name: 'TOTP', value: item.login.totp, k: 'TOTP' }] });
      } else if (item.type === 3 && item.card) {
        const cf = [];
        if (item.card.cardholderName) cf.push({ id: fuuid(), type: 'T', name: 'cardholder name', value: item.card.cardholderName });
        if (item.card.number) cf.push({ id: fuuid(), type: 'T', name: 'ccnum', value: item.card.number });
        if (item.card.expMonth || item.card.expYear) cf.push({ id: fuuid(), type: 'T', name: 'expiry', value: (item.card.expMonth || '') + '/' + (item.card.expYear || '') });
        if (item.card.code) cf.push({ id: fuuid(), type: 'T', name: 'cvv', value: item.card.code });
        if (item.card.brand) cf.push({ id: fuuid(), type: 'T', name: 'type', value: item.card.brand });
        if (cf.length) sections.push({ id: fuuid(), name: 'Credit Card', fields: cf });
      } else if (item.type === 4 && item.identity) {
        const idf = [];
        if (item.identity.firstName) idf.push({ id: fuuid(), type: 'T', name: 'first name', value: item.identity.firstName });
        if (item.identity.lastName) idf.push({ id: fuuid(), type: 'T', name: 'last name', value: item.identity.lastName });
        if (item.identity.email) idf.push({ id: fuuid(), type: 'T', name: 'email', value: item.identity.email });
        if (item.identity.phone) idf.push({ id: fuuid(), type: 'T', name: 'phone', value: item.identity.phone });
        if (item.identity.address1) idf.push({ id: fuuid(), type: 'T', name: 'address', value: item.identity.address1 });
        if (item.identity.city) idf.push({ id: fuuid(), type: 'T', name: 'city', value: item.identity.city });
        if (item.identity.state) idf.push({ id: fuuid(), type: 'T', name: 'state', value: item.identity.state });
        if (item.identity.postalCode) idf.push({ id: fuuid(), type: 'T', name: 'zip', value: item.identity.postalCode });
        if (item.identity.country) idf.push({ id: fuuid(), type: 'T', name: 'country', value: item.identity.country });
        if (idf.length) sections.push({ id: fuuid(), name: 'Identification', fields: idf });
      }
      // 备注
      if (item.notes) {
        let ns = sections.find(s => s.name === '');
        if (!ns) { ns = { id: fuuid(), name: '', fields: [] }; sections.push(ns); }
        ns.fields.push({ id: fuuid(), type: 'note', name: 'notesPlain', value: item.notes });
      }
      // 自定义字段（跳过内部标签）
      if (item.customFields && item.customFields.length) {
        let ns = sections.find(s => s.name === '');
        if (!ns) { ns = { id: fuuid(), name: '', fields: [] }; sections.push(ns); }
        for (const cf of item.customFields) {
          if (cf.name === '_TAGS') continue;
          ns.fields.push({ id: fuuid(), type: 'T', name: cf.name, value: String(cf.value || '') });
        }
      }
      // Passkey 以备注形式保留
      if (item.fido2Credentials && item.fido2Credentials.length) {
        let ns = sections.find(s => s.name === '');
        if (!ns) { ns = { id: fuuid(), name: '', fields: [] }; sections.push(ns); }
        for (const fc of item.fido2Credentials) {
          ns.fields.push({ id: fuuid(), type: 'note', name: 'Passkey', value: 'rpId=' + (fc.rpId || '') + ' credentialId=' + (fc.credentialId || '') + ' userName=' + (fc.userName || '') });
        }
      }
      const fUuid = item.folderId && folderMap.has(item.folderId) ? folderMap.get(item.folderId) : null;
      const i = { uuid: ituuid, category: cat, name: item.name || '未命名', favorite: item.favorite || false, trashed: 'N', createdAt: item.creationDate || now, updatedAt: item.revisionDate || now, urls: urls, fields: fields, sections: sections };
      if (fUuid) i.folderUuid = fUuid;
      i1p.push(i);
    }
    return { accounts: [{ uuid: accountUuid, name: 'Exported Vault' }], folders: f1p, items: i1p };
  }

  async function build1PUXZip(data) {
    const JSZip = global.JSZip || await import('vendor/jszip.min.js');
    const zip = new ((JSZip.default || JSZip)());
    zip.file('data/1password.1pif', JSON.stringify(data));
    return await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
  }

  async function run(opts) {
    const E = global.Pass2KDBXEngine;
    if (opts.direction === 'to-kdbx') return await convertToKdbx(opts, E);
    return await convertToBitwarden(opts, E);
  }

  global.Pass2KDBXEngine = {
    APP_VERSION, TYPE_NAMES, TYPE_NAME_TO_ID,
    generateUUID, parseBitwardenJson, parse1PUXJSON, parse1PUX, parseCSV, readZipFile, readZipJsonData,
    isBitwardenEncryptedJson, decryptBitwardenEncryptedJson, encryptBitwardenExport,
    buildNotes, buildCustomFields, buildTags, buildPasskeyFile, extractPasskeysFromFields,
    run, maybeEncryptBW, convertVaultItemToBW, generate1PUXExport, build1PUXZip,
    get argon2Ready() { return argon2Ready; },
    Kdbx, Credentials, ProtectedValue, Consts, KdbxUuid
  };
})(window);
