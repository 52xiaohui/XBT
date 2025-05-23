import './assets/main.css'

import { createApp } from 'vue'
import App from './App.vue'
import router from './router'

import Varlet from '@varlet/ui'
import '@varlet/ui/es/style'
import '@varlet/touch-emulator'
import { createPinia } from 'pinia'
import piniaPluginPersistedstate from 'pinia-plugin-persistedstate'


const app = createApp(App)

const pinia = createPinia()
pinia.use(piniaPluginPersistedstate)
app.use(pinia)

app.use(router)

app.use(Varlet)

app.mount('#app')
