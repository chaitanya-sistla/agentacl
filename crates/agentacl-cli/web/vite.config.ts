import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'node:path'

// Output is embedded into the agentacl binary (see src/ui/mod.rs): fixed
// file names, a single JS bundle, no CDN, nothing loaded from the network.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, 'src') } },
  build: {
    outDir: '../src/ui/dist',
    emptyOutDir: true,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        entryFileNames: 'assets/app.js',
        chunkFileNames: 'assets/app-[name].js',
        assetFileNames: (i) => (i.names?.[0]?.endsWith('.css') ? 'assets/app.css' : 'assets/[name][extname]'),
        codeSplitting: false,
      },
    },
  },
})
