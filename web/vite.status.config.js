import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import fs from 'node:fs'
import path from 'node:path'

const outDir = path.resolve(import.meta.dirname, '../internal/api/status-dist')

// 以 JS 为入口构建，再生成唯一一个 index.html 并内联 JS/CSS。
// 避免 HTML 入口把整页标记一并打进 bundle，造成自引用资源串。
function emitSingleHTML() {
  return {
    name: 'emit-single-html',
    apply: 'build',
    closeBundle() {
      const assetsDir = path.join(outDir, 'assets')
      let script = ''
      let style = ''
      if (fs.existsSync(assetsDir)) {
        for (const file of fs.readdirSync(assetsDir)) {
          const full = path.join(assetsDir, file)
          const content = fs.readFileSync(full, 'utf8')
          if (file.endsWith('.js')) script += content
          else if (file.endsWith('.css')) style += content
        }
        fs.rmSync(assetsDir, { recursive: true, force: true })
      }
      if (!script) throw new Error('status build produced no script')
      script = script.replace(/<\/script>/gi, '<\\/script>')
      style = style.replace(/<\/style>/gi, '<\\/style>')
      const html = `<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>服务器状态</title>
    ${style ? `<style>${style}</style>` : ''}
  </head>
  <body>
    <div id="app"></div>
    <script type="module">${script}</script>
  </body>
</html>
`
      for (const file of fs.readdirSync(outDir)) {
        if (file !== 'index.html') fs.rmSync(path.join(outDir, file), { recursive: true, force: true })
      }
      fs.writeFileSync(path.join(outDir, 'index.html'), html)
    }
  }
}

export default defineConfig({
  plugins: [vue(), emitSingleHTML()],
  publicDir: false,
  base: './',
  build: {
    outDir,
    emptyOutDir: true,
    target: 'es2020',
    cssCodeSplit: false,
    rollupOptions: {
      input: path.resolve(import.meta.dirname, 'src/status/main.js'),
      output: {
        format: 'es',
        entryFileNames: 'assets/status.js',
        chunkFileNames: 'assets/status-[hash].js',
        assetFileNames: 'assets/status.[ext]'
      }
    }
  }
})
