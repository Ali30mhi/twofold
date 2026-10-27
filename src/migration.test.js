import { describe, it, expect } from 'vitest';
import { parseMigration } from './migration.js';

// a tiny independent protobuf writer, used only to build test payloads
function varint(value) {
  let n = BigInt(value);
  const out = [];
  do {
    let byte = Number(n & 0x7fn);
    n >>= 7n;
    if (n) byte |= 0x80;
    out.push(byte);
  } while (n);
  return out;
}
const field = (num, wire, payload) => [...varint((num << 3) | wire), ...payload];
const bytesField = (num, bytes) => field(num, 2, [...varint(bytes.length), ...bytes]);
const strField = (num, s) => bytesField(num, [...new TextEncoder().encode(s)]);
const intField = (num, v) => field(num, 0, varint(v));

function otp({ secret, name, issuer, algorithm = 1, digits = 1, type = 2, counter }) {
  const parts = [...bytesField(1, secret), ...strField(2, name)];
  if (issuer) parts.push(...strField(3, issuer));
  parts.push(...intField(4, algorithm), ...intField(5, digits), ...intField(6, type));
  if (counter !== undefined) parts.push(...intField(7, counter));
  return parts;
}

function link(otps, extra = []) {
  const payload = [
    ...otps.flatMap((o) => bytesField(1, otp(o))),
    ...intField(2, 1), ...intField(3, 1), ...intField(4, 0),
    ...extra,
  ];
  return `otpauth-migration://offline?data=${encodeURIComponent(btoa(String.fromCharCode(...payload)))}`;
}

// "Hello!" + DE AD BE EF is the secret behind the well-known JBSWY3DPEHPK3PXP
const HELLO = [...new TextEncoder().encode('Hello!'), 0xde, 0xad, 0xbe, 0xef];

describe('Google Authenticator transfer links', () => {
  it('reads a TOTP account', () => {
    const { accounts, failed } = parseMigration(link([{ secret: HELLO, name: 'alice@example.com', issuer: 'Example' }]));
    expect(failed).toBe(0);
    expect(accounts).toEqual([{
      type: 'totp', issuer: 'Example', account: 'alice@example.com', secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1', digits: 6, period: 30, counter: 0,
    }]);
  });

  it('removes a repeated issuer prefix from the name', () => {
    const { accounts } = parseMigration(link([{ secret: HELLO, name: 'Example:alice', issuer: 'Example' }]));
    expect(accounts[0]).toMatchObject({ issuer: 'Example', account: 'alice' });
  });

  it('takes the issuer from the name when the issuer field is empty', () => {
    const { accounts } = parseMigration(link([{ secret: HELLO, name: 'GitHub:bob' }]));
    expect(accounts[0]).toMatchObject({ issuer: 'GitHub', account: 'bob' });
  });

  it('reads HOTP accounts with their counter, algorithm and digits', () => {
    const { accounts } = parseMigration(link([{ secret: HELLO, name: 'vpn', type: 1, counter: 7, algorithm: 2, digits: 2 }]));
    expect(accounts[0]).toMatchObject({ type: 'hotp', counter: 7, algorithm: 'SHA256', digits: 8 });
  });

  it('reads several accounts from one code', () => {
    const { accounts } = parseMigration(link([
      { secret: HELLO, name: 'one', issuer: 'A' },
      { secret: HELLO, name: 'two', issuer: 'B' },
      { secret: HELLO, name: 'three', issuer: 'C' },
    ]));
    expect(accounts.map((a) => a.issuer)).toEqual(['A', 'B', 'C']);
  });

  it('skips an unsupported account but keeps the rest', () => {
    const { accounts, failed } = parseMigration(link([
      { secret: HELLO, name: 'old', issuer: 'Legacy', algorithm: 4 },
      { secret: HELLO, name: 'fine', issuer: 'Good' },
    ]));
    expect(failed).toBe(1);
    expect(accounts.map((a) => a.issuer)).toEqual(['Good']);
  });

  it('ignores fields it does not know about', () => {
    const { accounts } = parseMigration(link([{ secret: HELLO, name: 'x', issuer: 'Y' }], intField(9, 12345)));
    expect(accounts).toHaveLength(1);
  });

  it('rejects truncated data', () => {
    const data = btoa(String.fromCharCode(0x0a, 0x10));
    expect(() => parseMigration(`otpauth-migration://offline?data=${encodeURIComponent(data)}`)).toThrow(/damaged/);
  });

  it('rejects links that are not transfer links', () => {
    expect(() => parseMigration('otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP')).toThrow(/not a Google Authenticator/);
  });
});
