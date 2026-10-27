import './style.css';
import { parseOtpauth, base32Decode, base32Encode, hotp } from './otp.js';

// Preview build: accounts live in memory only. Encrypted storage comes next.
const accounts = [];
const CIRCUMFERENCE = 2 * Math.PI * 15;
const $ = (sel) => document.querySelector(sel);
const list = $('#list');

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text; // textContent only: labels come from untrusted links
  return node;
}

function showError(msg) {
  $('#error').textContent = msg;
  $('#error').hidden = !msg;
}

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1400);
}

function group(code) {
  if (code.length >= 6 && code.length % 2 === 0) {
    const half = code.length / 2;
    return `${code.slice(0, half)} ${code.slice(half)}`;
  }
  return code;
}

function addAccount(acc) {
  accounts.push({ ...acc, id: crypto.randomUUID(), key: base32Decode(acc.secret) });
  render();
  showError('');
}

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
  const t = Date.now() / 1000;
  for (const a of accounts) {
    if (a.type !== 'totp' || !a.ringEl) continue;
    const left = a.period - (t % a.period);
    a.ringEl.style.strokeDashoffset = String(CIRCUMFERENCE * (1 - left / a.period));
    a.codeEl.classList.toggle('expiring', left <= 5);
    if (Math.floor(t / a.period) !== a.shown) refresh(a);
  }
}
setInterval(tick, 250);

$('#uri-form').addEventListener('submit', (e) => {
  e.preventDefault();
  try {
    addAccount(parseOtpauth($('#uri').value));
    $('#uri').value = '';
  } catch (err) {
    showError(err.message);
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
    showError(err.message);
  }
});

$('#demo').addEventListener('click', () => {
  addAccount(parseOtpauth('otpauth://totp/Demo:you@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Demo'));
});

render();
