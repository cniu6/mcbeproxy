import { createApp } from 'vue'
import App from './App.vue'

// naive-ui components are imported on demand by unplugin-vue-components
// (see vite.config.js) instead of registering the whole library globally.
createApp(App).mount('#app')
