import LobbyView from '@/views/LobbyView.vue'
import SignConfigView from '@/views/sign/SignConfigView.vue'
import SignDetailView from '@/views/sign/SignDetailView.vue'
import SignLobbyView from '@/views/sign/SignLobbyView.vue'
import SignProgressView from '@/views/sign/SignProgressView.vue'
import UserLobbyView from '@/views/user/UserLobbyView.vue'
import UserLoginView from '@/views/user/UserLoginView.vue'
import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'root',
    },
    {
      // 带有底部导航栏界面
      path: '/lobby',
      name: 'lobby',
      component: LobbyView,
      children: [
        {
          name: 'sign-lobby',
          path: 'sign',
          component: SignLobbyView,
        },
        {
          name: 'user-lobby',
          path: 'user',
          component: UserLobbyView,
        }
      ]
    },
    {
      path: '/sign/config',
      name: 'sign-config',
      component: SignConfigView,
    },
    {
      path: '/sign/detail',
      name: 'sign-detail',
      component: SignDetailView,
    },
    {
      path: '/sign/progress',
      name: 'sign-progress',
      component: SignProgressView,
    },
    {
      path: '/user/login',
      name: 'user-login',
      component: UserLoginView,
    }
  ],
})

router.beforeEach((to, from) => {
  if (to.path === '/') {
    return { name: 'lobby' }
  }
  if (to.path === '/lobby') {
    return { name: 'sign-lobby' }
  }
})

export default router
