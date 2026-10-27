// HOTP (RFC 4226), TOTP (RFC 6238), base32 (RFC 4648) and otpauth:// key URIs.
// Uses Web Crypto only, so the same code runs in the browser and in Node for tests.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HASHES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

export function base32Encode(bytes, pad = true) {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 31];
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  if (pad) while (out.length % 8 !== 0) out += '=';
  return out;
}

export function base32Decode(text) {
  const clean = String(text).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    // never echo the offending character: it is part of a secret
    if (idx === -1) throw new Error('Secret key contains characters that are not valid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
      value &= (1 << bits) - 1;
    }
  }
  return new Uint8Array(out);
}

function normalizeAlgorithm(name) {
  const key = String(name).toUpperCase().replace(/-/g, '');
  if (!Object.hasOwn(HASHES, key)) throw new Error(`Unsupported algorithm "${name}"`);
  return key;
}

export async function hotp(key, counter, { digits = 6, algorithm = 'SHA1' } = {}) {
  const hash = HASHES[normalizeAlgorithm(algorithm)];
  if (!Number.isInteger(digits) || digits < 1 || digits > 10) throw new Error('Digits must be between 1 and 10');
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error('Counter must be a non-negative integer');
  if (!key || key.length === 0) throw new Error('Secret key is empty');

  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign']);
  const msg = new ArrayBuffer(8);
  new DataView(msg).setBigUint64(0, BigInt(counter));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, msg));

  // dynamic truncation, RFC 4226 section 5.3
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function totp(key, { time = Date.now() / 1000, period = 30, ...options } = {}) {
  if (!Number.isInteger(period) || period < 1) throw new Error('Period must be a positive integer');
  return hotp(key, Math.floor(time / period), options);
}

function intParam(value, name, min, max) {
  if (!/^\d+$/.test(value)) throw new Error(`Invalid ${name} "${value}"`);
  const n = Number(value);
  if (n < min || n > max) throw new Error(`${name} must be between ${min} and ${max}`);
  return n;
}

export function parseOtpauth(input) {
  let url;
  try {
    url = new URL(String(input).trim());
  } catch {
    throw new Error('This is not a valid otpauth:// link');
  }
  if (url.protocol !== 'otpauth:') throw new Error('The link must start with otpauth://');

  const type = url.hostname.toLowerCase();
  if (type !== 'totp' && type !== 'hotp') throw new Error(`Unsupported code type "${type}"`);

  let label;
  try {
    label = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
  } catch {
    throw new Error('The account label is not encoded correctly');
  }
  let issuer = '';
  let account = label.trim();
  const colon = label.indexOf(':');
  if (colon !== -1) {
    issuer = label.slice(0, colon).trim();
    account = label.slice(colon + 1).trim();
  }

  const params = new Map();
  for (const [k, v] of url.searchParams) {
    const name = k.toLowerCase();
    if (params.has(name)) throw new Error(`Parameter "${name}" appears more than once`);
    params.set(name, v);
  }

  if (!params.get('secret')) throw new Error('The link has no secret key');
  const key = base32Decode(params.get('secret'));
  if (key.length === 0) throw new Error('Secret key is empty');
  if (params.get('issuer')) issuer = params.get('issuer').trim();
  if (!account && !issuer) throw new Error('The link has no account name');

  const algorithm = normalizeAlgorithm(params.get('algorithm') ?? 'SHA1');
  const digits = params.has('digits') ? intParam(params.get('digits'), 'digits', 1, 10) : 6;
  const period = params.has('period') ? intParam(params.get('period'), 'period', 1, 3600) : 30;
  let counter = 0;
  if (type === 'hotp') {
    if (!params.has('counter')) throw new Error('Counter-based links need a counter parameter');
    counter = intParam(params.get('counter'), 'counter', 0, Number.MAX_SAFE_INTEGER);
  }

  return { type, issuer, account, secret: base32Encode(key, false), algorithm, digits, period, counter };
}

export function buildOtpauth(a) {
  const label = encodeURIComponent(a.issuer ? `${a.issuer}:${a.account}` : a.account);
  const params = new URLSearchParams({ secret: a.secret });
  if (a.issuer) params.set('issuer', a.issuer);
  if (a.algorithm !== 'SHA1') params.set('algorithm', a.algorithm);
  if (a.digits !== 6) params.set('digits', String(a.digits));
  if (a.type === 'totp' && a.period !== 30) params.set('period', String(a.period));
  if (a.type === 'hotp') params.set('counter', String(a.counter));
  return `otpauth://${a.type}/${label}?${params}`;
}
