import { describe, it, expect } from 'vitest';
import { createVault, seal, open, toBase64, fromBase64 } from './vault.js';

// 100k is the lowest the vault accepts; it keeps the tests quick
const FAST = { iterations: 100_000 };
const PASS = 'correct horse battery';
const accounts = [
  { id: '1', type: 'totp', issuer: 'GitHub', account: 'me@example.com', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, counter: 0 },
];

describe('encrypted vault', () => {
  it('round-trips with the right passphrase', async () => {
    const blob = await seal(await createVault(PASS, FAST), accounts);
    const result = await open(JSON.parse(JSON.stringify(blob)), PASS);
    expect(result.accounts).toEqual(accounts);
  });

  it('rejects a wrong passphrase', async () => {
    const blob = await seal(await createVault(PASS, FAST), accounts);
    await expect(open(blob, 'not the passphrase')).rejects.toThrow(/Wrong passphrase/);
  });

  it('detects a modified ciphertext', async () => {
    const blob = await seal(await createVault(PASS, FAST), accounts);
    const bytes = fromBase64(blob.data);
    bytes[0] ^= 1;
    blob.data = toBase64(bytes);
    await expect(open(blob, PASS)).rejects.toThrow(/modified/);
  });

  it('refuses weak key settings instead of trying them', async () => {
    const blob = await seal(await createVault(PASS, FAST), accounts);
    blob.kdf = { ...blob.kdf, iterations: 1000 };
    await expect(open(blob, PASS)).rejects.toThrow(/safe range/);
  });

  it('uses a fresh IV for every save', async () => {
    const session = await createVault(PASS, FAST);
    const a = await seal(session, accounts);
    const b = await seal(session, accounts);
    expect(a.iv).not.toBe(b.iv);
    expect(a.data).not.toBe(b.data);
  });

  it('never stores secrets or labels in readable form', async () => {
    const text = JSON.stringify(await seal(await createVault(PASS, FAST), accounts));
    for (const s of ['JBSWY3DPEHPK3PXP', 'GitHub', 'me@example.com']) expect(text).not.toContain(s);
  });

  it('requires a passphrase of at least 8 characters', async () => {
    await expect(createVault('short', FAST)).rejects.toThrow(/at least 8/);
  });

  it('rejects files that are not vaults', async () => {
    await expect(open({ hello: 'world' }, PASS)).rejects.toThrow(/not a Twofold vault/);
  });
});
