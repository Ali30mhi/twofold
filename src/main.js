import './style.css';
import jsQR from 'jsqr';
import { parseOtpauth, buildOtpauth, base32Decode, base32Encode, hotp } from './otp.js';
import { createVault, seal, open } from './vault.js';
import { parseMigration } from './migration.js';

const STORAGE_KEY = 'twofold.vault';
const AUTO_LOCK_MS = 5 * 60 * 1000;
const CIRCUMFERENCE = 2 * Math.PI * 15;

let session = null; // { key, kdf } while unlocked; the key itself is non-extractable
let accounts = [];
let lastActivity = Date.now();
let pendingImport = null;
let scanStream = null;
let scanFrame = 0;

const $ = (sel) => document.querySelector(sel);
const list = $('#list');

// ---------- small ui helpers ----------
function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text; // textContent only: labels come from untrusted codes
  return node;
}

function setError(target, msg) {
  const node = typeof target === 'string' ? $(target) : target.querySelector('.error');
  node.textContent = msg;
  node.hidden = !msg;
}

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2200);
}

async function busy(form, label, task) {
  const btn = form.querySelector('button:not([type="button"])');
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = label;
  try {
    await task();
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

function show(screen) {
  for (const id of ['setup', 'unlock', 'app']) $(`#${id}`).hidden = id !== screen;
  $('#app-actions').hidden = screen !== 'app';
  const focus = { setup: '#setup-pass', unlock: '#unlock-pass', app: null }[screen];
  if (focus) $(focus).focus();
}

function group(code) {
  if (code.length >= 6 && code.length % 2 === 0) {
    const half = code.length / 2;
    return `${code.slice(0, half)} ${code.slice(half)}`;
  }
  return code;
}

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

// ---------- vault ----------
const dedupeKey = (a) => `${a.type}|${a.secret}|${a.issuer}|${a.account}`;

// everything from storage, files and QR codes is re-validated through the otpauth parser
function hydrate(raw) {
  if (!raw || typeof raw.secret !== 'string' || typeof raw.type !== 'string') return null;
  try {
    const a = parseOtpauth(buildOtpauth({ ...raw, issuer: String(raw.issuer ?? ''), account: String(raw.account ?? '') }));
    return { ...a, id: typeof raw.id === 'string' ? raw.id : crypto.randomUUID(), key: base32Decode(a.secret) };
  } catch {
    return null;
  }
}

const dehydrate = ({ id, type, issuer, account, secret, algorithm, digits, period, counter }) =>
  ({ id, type, issuer, account, secret, algorithm, digits, period, counter });

async function persist() {
  const blob = await seal(session, accounts.map(dehydrate));
  localStorage.setItem(STORAGE_KEY, JSON.stringify(blob));
}

function save() {
  persist().catch(() => toast('Could not save your changes'));
}

function readStored() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('The saved vault is damaged');
  }
}

function lock() {
  stopScan();
  session = null;
  accounts = [];
  list.replaceChildren();
  if ($('#import-dialog').open) $('#import-dialog').close();
  show('unlock');
}

function enterApp() {
  lastActivity = Date.now();
  render();
  show('app');
}

// ---------- adding accounts ----------
function addMany(rawList) {
  const seen = new Set(accounts.map(dedupeKey));
  let added = 0;
  let skipped = 0;
  let failed = 0;
  for (const raw of rawList) {
    const a = hydrate(raw);
    if (!a) {
      failed++;
      continue;
    }
    if (seen.has(dedupeKey(a))) {
      skipped++;
      continue;
    }
    seen.add(dedupeKey(a));
    accounts.push({ ...a, id: crypto.randomUUID() });
    added++;
  }
  if (added) {
    render();
    save();
  }
  setError('#error', '');
  return { added, skipped, failed };
}

function addAccount(raw) {
  const r = addMany([raw]);
  if (r.skipped) throw new Error('This account is already in your vault');
  if (r.failed) throw new Error('That account could not be added');
  toast('Account added');
}

// accepts otpauth:// links and Google Authenticator transfer links
function handleText(text) {
  const t = String(text).trim();
  if (/^otpauth-migration:/i.test(t)) {
    const { accounts: found, failed } = parseMigration(t);
    const r = addMany(found);
    const unsupported = failed + r.failed;
    const parts = [`Added ${plural(r.added, 'account')}`];
    if (r.skipped) parts.push(`${r.skipped} already here`);
    if (unsupported) parts.push(`${unsupported} not supported`);
    toast(parts.join(', '));
  } else if (/^otpauth:/i.test(t)) {
    addAccount(parseOtpauth(t));
  } else {
    throw new Error('This is not a two-factor setup code');
  }
}

function tryHandle(text) {
  try {
    handleText(text);
  } catch (err) {
    setError('#error', err.message);
  }
}

// ---------- QR codes ----------
function decodeFrom(source, width, height, maxSide) {
  const scale = Math.min(1, maxSide / Math.max(width, height));
  const canvas = document.createElement('canvas');
  canvas.width = Math.round(width * scale);
  canvas.height = Math.round(height * scale);
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
  return jsQR(img.data, img.width, img.height)?.data ?? null;
}

async function scanImage(file) {
  let bitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    return setError('#error', 'Could not read that image');
  }
  const text = decodeFrom(bitmap, bitmap.width, bitmap.height, 1600);
  bitmap.close();
  if (!text) return setError('#error', 'No QR code found in that image');
  tryHandle(text);
}

function cameraError(err) {
  switch (err?.name) {
    case 'NotAllowedError':
    case 'SecurityError':
      return 'Camera permission was denied. Allow it from the camera icon next to the address bar, or upload a QR image instead.';
    case 'NotFoundError':
    case 'OverconstrainedError':
      return 'No camera was found on this device. Upload or paste a QR image instead.';
    case 'NotReadableError':
    case 'AbortError':
      return 'The camera is busy in another app. Close it and try again.';
    default:
      return 'The camera could not be started. Upload or paste a QR image instead.';
  }
}

async function startScan() {
  if (!navigator.mediaDevices?.getUserMedia) {
    return setError('#error', 'This browser cannot use the camera here. Try uploading an image instead.');
  }
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
  } catch (err) {
    return setError('#error', cameraError(err));
  }
  const video = $('#scan-video');
  video.srcObject = scanStream;
  $('#scan-dialog').showModal();
  await video.play().catch(() => {});

  const loop = () => {
    if (!scanStream) return;
    if (video.readyState >= 2 && video.videoWidth) {
      const text = decodeFrom(video, video.videoWidth, video.videoHeight, 800);
      if (text) {
        stopScan();
        tryHandle(text);
        return;
      }
    }
    scanFrame = requestAnimationFrame(loop);
  };
  loop();
}

function stopScan() {
  cancelAnimationFrame(scanFrame);
  if (scanStream) for (const track of scanStream.getTracks()) track.stop(); // turn the camera off right away
  scanStream = null;
  $('#scan-video').srcObject = null;
  if ($('#scan-dialog').open) $('#scan-dialog').close();
}

// ---------- account list ----------
function ring() {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 36 36');
  svg.setAttribute('class', 'ring');
  svg.setAttribute('aria-hidden', 'true');
  for (const cls of ['bg', 'fg']) {
    const c = document.createElementNS(ns, 'circle');
    c.setAttribute('cx', '18');
    c.setAttribute('cy', '18');
    c.setAttribute('r', '15');
    c.setAttribute('class', cls);
    svg.append(c);
  }
  return svg;
}

async function refresh(a) {
  const counter = a.type === 'totp' ? Math.floor(Date.now() / 1000 / a.period) : a.counter;
  a.shown = counter;
  const code = await hotp(a.key, counter, a);
  if (a.shown !== counter || !a.codeEl) return;
  a.current = code;
  a.codeEl.textContent = group(code);
}

async function copy(a) {
  if (!a.current) return;
  try {
    await navigator.clipboard.writeText(a.current);
    toast('Copied');
  } catch {
    toast('Could not copy');
  }
}

function render() {
  list.replaceChildren();
  $('#empty').hidden = accounts.length > 0;
  for (const a of accounts) {
    const name = a.issuer || a.account;
    const li = el('li', 'card');

    const info = el('div', 'info');
    info.append(el('div', 'issuer', name));
    if (a.issuer && a.account) info.append(el('div', 'account', a.account));

    const code = el('button', 'code', '··· ···');
    code.type = 'button';
    code.setAttribute('aria-label', `Copy code for ${name}`);
    code.addEventListener('click', () => copy(a));

    const side = el('div', 'side');
    if (a.type === 'totp') {
      const r = ring();
      a.ringEl = r.querySelector('.fg');
      side.append(r);
    } else {
      const next = el('button', 'next', 'Next');
      next.type = 'button';
      next.addEventListener('click', () => {
        a.counter += 1;
        refresh(a);
        save();
      });
      side.append(next);
    }

    const del = el('button', 'delete', '✕');
    del.type = 'button';
    del.setAttribute('aria-label', `Remove ${name}`);
    del.addEventListener('click', () => {
      if (!confirm(`Remove ${name}? You will lose access to its codes.`)) return;
      accounts.splice(accounts.indexOf(a), 1);
      render();
      save();
    });
    side.append(del);

    li.append(info, code, side);
    list.append(li);
    a.codeEl = code;
    a.shown = null;
    refresh(a);
  }
  tick();
}

function tick() {
  if (session && Date.now() - lastActivity > AUTO_LOCK_MS) {
    lock();
    toast('Locked after 5 minutes of inactivity');
    return;
  }
  const t = Date.now() / 1000;
  for (const a of accounts) {
    if (a.type !== 'totp' || !a.ringEl) continue;
    const left = a.period - (t % a.period);
    a.ringEl.style.strokeDashoffset = String(CIRCUMFERENCE * (1 - left / a.period));
    a.codeEl.classList.toggle('expiring', left <= 5);
    if (Math.floor(t / a.period) !== a.shown) refresh(a);
  }
}

// ---------- events ----------
for (const evt of ['pointerdown', 'keydown']) {
  addEventListener(evt, () => { lastActivity = Date.now(); }, { passive: true });
}

$('#setup-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const form = e.target;
  const pass = $('#setup-pass').value;
  if (pass !== $('#setup-pass2').value) return setError(form, 'The passphrases do not match');
  setError(form, '');
  busy(form, 'Creating…', async () => {
    try {
      session = await createVault(pass);
      accounts = [];
      await persist();
      form.reset();
      enterApp();
    } catch (err) {
      setError(form, err.message);
    }
  });
});

$('#unlock-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const form = e.target;
  setError(form, '');
  busy(form, 'Unlocking…', async () => {
    try {
      const result = await open(readStored(), $('#unlock-pass').value);
      session = result.session;
      accounts = result.accounts.map(hydrate).filter(Boolean);
      form.reset();
      enterApp();
    } catch (err) {
      setError(form, err.message);
      $('#unlock-pass').select();
    }
  });
});

$('#reset').addEventListener('click', () => {
  const ok = confirm('A forgotten passphrase cannot be recovered.\n\nDelete the saved vault and every account in it, and start over?');
  if (!ok) return;
  localStorage.removeItem(STORAGE_KEY);
  show('setup');
});

$('#lock').addEventListener('click', lock);

$('#export').addEventListener('click', async () => {
  await persist();
  const blob = new Blob([localStorage.getItem(STORAGE_KEY)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `twofold-backup-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  toast('Encrypted backup downloaded');
});

$('#import').addEventListener('click', () => $('#import-file').click());

$('#import-file').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  if (file.size > 5_000_000) return toast('That file is too large to be a backup');
  try {
    pendingImport = JSON.parse(await file.text());
  } catch {
    return toast('That file is not a Twofold backup');
  }
  setError($('#import-form'), '');
  $('#import-dialog').showModal();
});

$('#import-cancel').addEventListener('click', () => $('#import-dialog').close());
$('#import-dialog').addEventListener('close', () => {
  pendingImport = null;
  $('#import-form').reset();
});

$('#import-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const form = e.target;
  setError(form, '');
  busy(form, 'Importing…', async () => {
    try {
      const result = await open(pendingImport, $('#import-pass').value);
      const r = addMany(result.accounts);
      await persist();
      $('#import-dialog').close();
      const parts = [`Imported ${plural(r.added, 'account')}`];
      if (r.skipped) parts.push(`${r.skipped} already here`);
      if (r.failed) parts.push(`${r.failed} invalid`);
      toast(parts.join(', '));
    } catch (err) {
      setError(form, err.message);
    }
  });
});

$('#scan').addEventListener('click', startScan);
$('#scan-cancel').addEventListener('click', stopScan);
$('#scan-dialog').addEventListener('close', stopScan);

$('#upload').addEventListener('click', () => $('#qr-file').click());
$('#qr-file').addEventListener('change', (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (file) scanImage(file);
});

// paste a screenshot of a QR code anywhere while unlocked
document.addEventListener('paste', (e) => {
  if (!session) return;
  const item = [...(e.clipboardData?.items ?? [])].find((i) => i.type.startsWith('image/'));
  if (!item) return;
  e.preventDefault();
  scanImage(item.getAsFile());
});

$('#uri-form').addEventListener('submit', (e) => {
  e.preventDefault();
  try {
    handleText($('#uri').value);
    $('#uri').value = '';
  } catch (err) {
    setError('#error', err.message);
  }
});

$('#manual-form').addEventListener('submit', (e) => {
  e.preventDefault();
  try {
    const account = $('#m-account').value.trim();
    if (!account) throw new Error('Account name is required');
    const key = base32Decode($('#m-secret').value);
    if (key.length === 0) throw new Error('Secret key is empty');
    addAccount({
      type: $('#m-type').value,
      issuer: $('#m-issuer').value.trim(),
      account,
      secret: base32Encode(key, false),
      algorithm: $('#m-alg').value,
      digits: Number($('#m-digits').value),
      period: Number($('#m-period').value),
      counter: 0,
    });
    e.target.reset();
  } catch (err) {
    setError('#error', err.message);
  }
});

$('#demo').addEventListener('click', () => {
  tryHandle('otpauth://totp/Demo:you@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Demo');
});

setInterval(tick, 250);
show(localStorage.getItem(STORAGE_KEY) ? 'unlock' : 'setup');

// Warn when the keyboard types non-Latin characters into a passphrase field:
// a vault created with one layout cannot be opened by pressing the same keys in another.
for (const id of ['setup-pass', 'setup-pass2', 'unlock-pass', 'import-pass']) {
  const input = document.getElementById(id);
  const warn = el('p', 'kbd-warn', 'Your keyboard is typing non-Latin characters. Make sure this is the same layout you used when the vault was created.');
  warn.hidden = true;
  input.closest('label').after(warn);
  input.addEventListener('input', () => { warn.hidden = !/[^\x00-\x7F]/.test(input.value); });
  input.form.addEventListener('reset', () => { warn.hidden = true; });
}
