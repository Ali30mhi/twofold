import { describe, it, expect } from 'vitest';
import { base32Decode, base32Encode, hotp, totp, parseOtpauth, buildOtpauth } from './otp.js';

const ascii = (s) => new TextEncoder().encode(s);

describe('base32 (RFC 4648 section 10)', () => {
  const vectors = [
    ['', ''],
    ['f', 'MY======'],
    ['fo', 'MZXQ===='],
    ['foo', 'MZXW6==='],
    ['foob', 'MZXW6YQ='],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI======'],
  ];
  for (const [plain, encoded] of vectors) {
    it(`encodes "${plain}"`, () => expect(base32Encode(ascii(plain))).toBe(encoded));
    it(`decodes "${encoded}"`, () => expect(new TextDecoder().decode(base32Decode(encoded))).toBe(plain));
  }
  it('ignores case, spaces and dashes', () => expect(base32Decode('mzxw 6ytb-oi')).toEqual(ascii('foobar')));
  it('rejects characters outside the alphabet', () => expect(() => base32Decode('MZ1W')).toThrow());
});

describe('HOTP (RFC 4226 appendix D)', () => {
  const codes = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  codes.forEach((code, counter) => {
    it(`counter ${counter}`, async () => expect(await hotp(ascii('12345678901234567890'), counter)).toBe(code));
  });
});

describe('TOTP (RFC 6238 appendix B)', () => {
  const seeds = {
    SHA1: ascii('12345678901234567890'),
    SHA256: ascii('12345678901234567890123456789012'),
    SHA512: ascii('1234567890123456789012345678901234567890123456789012345678901234'),
  };
  const table = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  for (const [time, sha1, sha256, sha512] of table) {
    for (const [algorithm, expected] of [['SHA1', sha1], ['SHA256', sha256], ['SHA512', sha512]]) {
      it(`${algorithm} at T=${time}`, async () => {
        expect(await totp(seeds[algorithm], { time, digits: 8, algorithm })).toBe(expected);
      });
    }
  }
});

describe('otpauth:// links', () => {
  it('parses a typical TOTP link', () => {
    const a = parseOtpauth('otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example');
    expect(a).toMatchObject({
      type: 'totp', issuer: 'Example', account: 'alice@google.com',
      secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30,
    });
  });

  it('reads percent-encoded labels and non-default parameters', () => {
    const a = parseOtpauth(
      'otpauth://totp/ACME%20Co%3Ajohn.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA256&digits=8&period=60',
    );
    expect(a).toMatchObject({ issuer: 'ACME Co', account: 'john.doe@email.com', algorithm: 'SHA256', digits: 8, period: 60 });
  });

  it('parses a HOTP link with its counter', () => {
    const a = parseOtpauth('otpauth://hotp/Service:bob?secret=JBSWY3DPEHPK3PXP&counter=5');
    expect(a).toMatchObject({ type: 'hotp', issuer: 'Service', account: 'bob', counter: 5 });
  });

  it('rejects a link without a secret', () => {
    expect(() => parseOtpauth('otpauth://totp/A:b?issuer=A')).toThrow(/no secret/);
  });

  it('rejects repeated parameters instead of guessing', () => {
    expect(() => parseOtpauth('otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP')).toThrow(/more than once/);
  });

  it('rejects a HOTP link without a counter', () => {
    expect(() => parseOtpauth('otpauth://hotp/A:b?secret=JBSWY3DPEHPK3PXP')).toThrow(/counter/);
  });

  it('rejects links that are not otpauth', () => {
    expect(() => parseOtpauth('https://example.com/?secret=JBSWY3DPEHPK3PXP')).toThrow();
  });

  it('never puts the secret in an error message', () => {
    const secret = 'ABCD1EFGHIJK';
    try {
      parseOtpauth(`otpauth://totp/A:b?secret=${secret}`);
      throw new Error('expected a failure');
    } catch (e) {
      expect(e.message).not.toContain(secret);
      expect(e.message).toMatch(/base32/);
    }
  });

  it('round-trips through build and parse', () => {
    const accounts = [
      { type: 'totp', issuer: 'GitHub', account: 'me@example.com', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, counter: 0 },
      { type: 'totp', issuer: 'Bank & Co', account: 'a b:c', secret: 'HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ', algorithm: 'SHA512', digits: 8, period: 60, counter: 0 },
      { type: 'hotp', issuer: '', account: 'server-1', secret: 'GEZDGNBVGY3TQOJQ', algorithm: 'SHA256', digits: 6, period: 30, counter: 42 },
    ];
    for (const a of accounts) expect(parseOtpauth(buildOtpauth(a))).toEqual(a);
  });
});
