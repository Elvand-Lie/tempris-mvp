// Preview builds: mock API (VITE_DEMO_MOCK=1 via .env.preview), single self-contained HTML.
// PREVIEW_CDN=1 loads React from cdnjs instead of bundling it (used for the published artifact).
import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { fileURLToPath } from 'node:url';

const cdn = process.env.PREVIEW_CDN === '1';
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const umd: Plugin = {
  name: 'react-umd-tags',
  transformIndexHtml: (html) => html.replace('</title>', '</title>\n    <script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.3.1/umd/react.production.min.js"></script>\n    <script src="https://cdnjs.cloudflare.com/ajax/libs/react-dom/18.3.1/umd/react-dom.production.min.js"></script>'),
};

const fonts: Plugin = {
  name: 'preview-fonts',
  transformIndexHtml: (html) => html.replace('</title>', '</title>\n    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&display=swap" />'),
};

export default defineConfig({
  mode: 'preview',
  plugins: [react(), viteSingleFile(), fonts, ...(cdn ? [umd] : [])],
  resolve: {
    alias: [
      { find: /^\.\/preview\/previewApi$/, replacement: here('./src/preview/mockApi.ts') },
      { find: /^\.\/review$/, replacement: here('./src/preview/review.ts') },
    ].concat(cdn ? [
      { find: /^react$/, replacement: here('./src/preview/react-global.ts') },
      { find: /^react\/jsx-runtime$/, replacement: here('./src/preview/jsx-global.ts') },
      { find: /^react-dom\/client$/, replacement: here('./src/preview/react-dom-global.ts') },
    ] : []),
  },
  build: { outDir: cdn ? 'dist-preview-cdn' : 'dist-preview', target: 'es2020', emptyOutDir: true },
});
