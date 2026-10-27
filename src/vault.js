// Encrypted vault: AES-256-GCM under a key derived from the passphrase with PBKDF2-SHA256.
// The derived key is non-extractable, and only ciphertext is ever written anywhere.

export const FORMAT = 'twofold-vault';
export const VERSION = 1;
export const DEFAULT_ITERATIONS = 600_000; // OWASP recommendation for PBKDF2-HMAC-SHA256
export const MIN_PASSPHRASE = 8;
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 10_000_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function toBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(text) {
  if (typeof text !== 'string') throw new Error('Vault file is damaged');
  let bin;
  try {
    bin = atob(text);
  } catch {
    throw new Error('Vault file is damaged');
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(passphrase, salt, iterations) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// The header is authenticated (not encrypted), so any edit to it makes decryption fail.
function header(kdf) {
  return encoder.encode(JSON.stringify({ format: FORMAT, version: VERSION, kdf }));
}

export async function createVault(passphrase, { iterations = DEFAULT_ITERATIONS } = {}) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE) {
    throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE} characters`);
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kdf = { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: toBase64(salt) };
  return { key: await deriveKey(passphrase, salt, iterations), kdf };
}

export async function seal(session, accounts) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = encoder.encode(JSON.stringify({ accounts }));
  const data = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: header(session.kdf) }, session.key, plain),
  );
  return { format: FORMAT, version: VERSION, kdf: session.kdf, iv: toBase64(iv), data: toBase64(data) };
}

export async function open(blob, passphrase) {
  if (!blob || typeof blob !== 'object' || blob.format !== FORMAT) throw new Error('This is not a Twofold vault');
  if (blob.version !== VERSION) throw new Error('This vault was made by an unsupported version');

  const k = blob.kdf ?? {};
  if (k.name !== 'PBKDF2' || k.hash !== 'SHA-256') throw new Error('Unsupported key derivation settings');
  // reject out-of-range settings instead of trying them: too low is weak, too high is a denial of service
  if (!Number.isInteger(k.iterations) || k.iterations < MIN_ITERATIONS || k.iterations > MAX_ITERATIONS) {
    throw new Error('The vault key settings are outside the safe range');
  }
  const salt = fromBase64(k.salt);
  const iv = fromBase64(blob.iv);
  const data = fromBase64(blob.data);
  if (salt.length < 16 || iv.length !== 12) throw new Error('Vault file is damaged');

  const kdf = { name: 'PBKDF2', hash: 'SHA-256', iterations: k.iterations, salt: k.salt };
  const key = await deriveKey(String(passphrase), salt, k.iterations);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: header(kdf) }, key, data);
  } catch {
    throw new Error('Wrong passphrase, or the vault was modified');
  }
  let parsed;
  try {
    parsed = JSON.parse(decoder.decode(plain));
  } catch {
    throw new Error('Vault file is damaged');
  }
  if (!parsed || !Array.isArray(parsed.accounts)) throw new Error('Vault file is damaged');
  return { session: { key, kdf }, accounts: parsed.accounts };
}
