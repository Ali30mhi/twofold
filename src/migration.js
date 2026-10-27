// Google Authenticator "Transfer accounts" export:
// otpauth-migration://offline?data=<base64 protobuf MigrationPayload>
import { base32Encode } from './otp.js';
import { fromBase64 } from './vault.js';

const ALGORITHMS = { 0: 'SHA1', 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' }; // 4 is MD5, not supported
const DIGITS = { 0: 6, 1: 6, 2: 8 };
const decoder = new TextDecoder();

// minimal protobuf reader: just what MigrationPayload needs, strict about bounds
class Reader {
  constructor(bytes) {
    this.b = bytes;
    this.i = 0;
  }
  done() {
    return this.i >= this.b.length;
  }
  varint() {
    let result = 0n;
    let shift = 0n;
    for (;;) {
      if (this.i >= this.b.length) throw new Error('truncated');
      const byte = this.b[this.i++];
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7n;
      if (shift > 63n) throw new Error('varint too long');
    }
  }
  advance(n) {
    if (this.i + n > this.b.length) throw new Error('truncated');
    this.i += n;
  }
  bytes() {
    const len = Number(this.varint());
    if (this.i + len > this.b.length) throw new Error('truncated');
    const out = this.b.subarray(this.i, this.i + len);
    this.i += len;
    return out;
  }
  skip(wire) {
    if (wire === 0) this.varint();
    else if (wire === 1) this.advance(8);
    else if (wire === 2) this.bytes();
    else if (wire === 5) this.advance(4);
    else throw new Error('unsupported wire type');
  }
}

function readFields(bytes, handlers) {
  const r = new Reader(bytes);
  while (!r.done()) {
    const tag = Number(r.varint());
    const handler = handlers[tag >>> 3];
    if (handler && handler.wire === (tag & 7)) handler.read(r);
    else r.skip(tag & 7);
  }
}

function parseOtpParameters(bytes) {
  const o = { secret: null, name: '', issuer: '', algorithm: 0, digits: 0, type: 0, counter: 0n };
  readFields(bytes, {
    1: { wire: 2, read: (r) => { o.secret = r.bytes(); } },
    2: { wire: 2, read: (r) => { o.name = decoder.decode(r.bytes()); } },
    3: { wire: 2, read: (r) => { o.issuer = decoder.decode(r.bytes()); } },
    4: { wire: 0, read: (r) => { o.algorithm = Number(r.varint()); } },
    5: { wire: 0, read: (r) => { o.digits = Number(r.varint()); } },
    6: { wire: 0, read: (r) => { o.type = Number(r.varint()); } },
    7: { wire: 0, read: (r) => { o.counter = r.varint(); } },
  });

  if (!o.secret || o.secret.length === 0) throw new Error('missing secret');
  const algorithm = ALGORITHMS[o.algorithm];
  const digits = DIGITS[o.digits];
  if (!algorithm || !digits || o.type > 2) throw new Error('unsupported settings');
  if (o.counter > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('counter too large');
  const type = o.type === 1 ? 'hotp' : 'totp';

  // names often look like "Issuer:account"; keep the issuer field as the source of truth
  let issuer = o.issuer.trim();
  let account = o.name.trim();
  const colon = account.indexOf(':');
  if (colon !== -1) {
    const prefix = account.slice(0, colon).trim();
    if (!issuer || prefix === issuer) {
      issuer = issuer || prefix;
      account = account.slice(colon + 1).trim();
    }
  }
  if (!account && !issuer) throw new Error('missing name');

  return {
    type, issuer, account,
    secret: base32Encode(o.secret, false),
    algorithm, digits, period: 30,
    counter: type === 'hotp' ? Number(o.counter) : 0,
  };
}

export function parseMigration(input) {
  let url;
  try {
    url = new URL(String(input).trim());
  } catch {
    throw new Error('This is not a valid transfer link');
  }
  if (url.protocol !== 'otpauth-migration:') throw new Error('This is not a Google Authenticator transfer link');
  const data = url.searchParams.get('data');
  if (!data) throw new Error('The transfer link has no data');

  const accounts = [];
  let failed = 0;
  try {
    // a raw "+" in the query string arrives as a space
    const bytes = fromBase64(data.replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/'));
    readFields(bytes, {
      1: {
        wire: 2,
        read: (r) => {
          const raw = r.bytes();
          try {
            accounts.push(parseOtpParameters(raw));
          } catch {
            failed++; // one bad entry never sinks the whole transfer
          }
        },
      },
    });
  } catch {
    throw new Error('The transfer link is damaged');
  }
  if (accounts.length === 0 && failed === 0) throw new Error('The transfer link contains no accounts');
  return { accounts, failed };
}
