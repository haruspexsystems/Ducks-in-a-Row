/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Unit tests for the pure helpers: the readers in src/types that mirror C#
  // code the dashboard has to agree with, the rules in src/lib, and the client
  // setup snippet builders. Node environment rather than a DOM one on purpose:
  // nothing here touches the document, and pulling in jsdom for string
  // functions would be a dependency the suite does not use. Add a DOM
  // environment alongside this when the first component test arrives.
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/acme': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: '../Certus.Web/wwwroot',
    emptyOutDir: true,
    // Never inline font files, whatever their size. Vite's default 4 kB threshold
    // is below the small @fontsource subsets (cyrillic-ext, vietnamese), so those
    // faces were emitted as `data:` URIs inside the CSS and then refused at runtime
    // by the `font-src 'self'` directive in SecurityHeadersMiddleware. Emitting every
    // font as a same origin file under /assets satisfies that directive as it stands,
    // instead of widening it to accept `data:`. Returning undefined for everything
    // else keeps the default limit for small images, which `img-src data:` allows.
    assetsInlineLimit: (filePath) =>
      /\.(woff2?|ttf|otf|eot)$/i.test(filePath) ? false : undefined,
  },
})
