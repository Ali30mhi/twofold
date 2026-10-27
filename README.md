# Twofold

A two-factor authenticator that runs in your browser and keeps your secrets on your device.

**Live:** https://ali30mhi.github.io/twofold/

Twofold generates the same codes as Google Authenticator or Authy, but your accounts live in an encrypted vault on your own device. There is no server, no sign-up and no account to lose.

## Features

- TOTP and HOTP codes (RFC 6238 and RFC 4226) with SHA-1, SHA-256 and SHA-512, 6 to 8 digits, 30 or 60 second periods
- Add accounts by scanning a QR code with the camera, uploading an image, pasting a screenshot with Ctrl+V, pasting an `otpauth://` link, or typing the key by hand
- Move everything over from Google Authenticator in one go through its "Transfer accounts" QR code
- Encrypted vault that locks itself after 5 minutes of inactivity
- Encrypted backups you can export and import on another device
- Light and dark themes

## How your data is protected

- The vault is encrypted with AES-256-GCM. The key is derived from your passphrase with PBKDF2-SHA256 at 600,000 iterations, the current OWASP recommendation, and is created as non-extractable, so not even the app's own code can read the raw key.
- Every save uses a fresh random IV. Vault files with weak or out-of-range key settings are rejected instead of being tried.
- QR codes are decoded locally, and the camera is switched off as soon as a code has been read.
- Production builds ship with a strict Content Security Policy.

A forgotten passphrase cannot be recovered. Export a backup and keep the passphrase somewhere safe.

## Status

Twofold is a young project and has not had an independent security audit. Until it has one, use it alongside an established authenticator for important accounts.

## Development

```bash
npm install
npm run dev      # local dev server
npm test         # test suite, including the official RFC test vectors
npm run build    # production build in dist/
npm run deploy   # publish to GitHub Pages
```

The OTP engine is checked against the published test vectors from RFC 4226, RFC 6238 and RFC 4648. Further tests cover the vault (wrong passphrase, tampering, weak settings, no readable secrets in storage) and the Google Authenticator import (several accounts per code, unsupported entries, damaged data).

## License

MIT
