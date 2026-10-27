import { defineConfig } from 'vite';

// Strict Content Security Policy for production builds only.
// The dev server injects inline styles for hot reload, which this policy would block.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data: blob:",
  "media-src 'self' blob: mediastream:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

export default defineConfig({
  base: './',
  plugins: [
    {
      name: 'csp',
      apply: 'build',
      transformIndexHtml: (html) =>
        html.replace('<head>', `<head>\n<meta http-equiv="Content-Security-Policy" content="${CSP}" />`),
    },
  ],
});
