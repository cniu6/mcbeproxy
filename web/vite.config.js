import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { compression } from 'vite-plugin-compression2'

export default defineConfig({
  plugins: [
    vue(),
    // 同时生成 .gz 与 .br，Go 端按 Accept-Encoding 直接吐出预压缩文件，
    // 把 ~1.9MB 的 JS 在线传输体积降到 ~500KB / ~400KB
    compression({
      include: [/\.(js|mjs|css|html|svg|json)$/],
      threshold: 1024,
      algorithm: 'gzip',
      deleteOriginalAssets: false
    }),
    compression({
      include: [/\.(js|mjs|css|html|svg|json)$/],
      threshold: 1024,
      algorithm: 'brotliCompress',
      deleteOriginalAssets: false
    })
  ],
  base: './',
  build: {
    outDir: '../internal/api/dist',
    emptyOutDir: true,
    // 提高警告阈值，避免大块 vendor 触发警告（chunks 已拆分）
    chunkSizeWarningLimit: 1024,
    rollupOptions: {
      output: {
        // 保持文件名一致性
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
        // 手动分块：把第三方库拆成独立 chunk，减小入口文件体积，
        // 同时让浏览器可以并行下载并长期缓存（vendor hash 相对稳定）
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          // naive-ui 体积最大，单独成块
          if (id.includes('node_modules/naive-ui') || id.includes('node_modules/vooks') ||
              id.includes('node_modules/vueuc') || id.includes('node_modules/css-render') ||
              id.includes('node_modules/@css-render') || id.includes('node_modules/seemly') ||
              id.includes('node_modules/treemate') || id.includes('node_modules/evtd') ||
              id.includes('node_modules/async-validator') || id.includes('node_modules/date-fns') ||
              id.includes('node_modules/date-fns-tz') || id.includes('node_modules/lodash-es')) {
            return 'naive-ui'
          }
          // 图标单独成块
          if (id.includes('node_modules/@vicons')) {
            return 'vicons'
          }
          // Vue 运行时
          if (id.includes('node_modules/vue') || id.includes('node_modules/@vue')) {
            return 'vue'
          }
          // 其余第三方库
          return 'vendor'
        }
      }
    }
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8081'
    }
  }
})
